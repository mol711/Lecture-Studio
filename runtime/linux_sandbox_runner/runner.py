"""Standalone Linux-side runner invoked inside WSL2 / Linux VM using pure stdlib."""

from __future__ import annotations

import argparse
import base64
import contextlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import time
import uuid


def run_bwrap(spec: dict[str, object]) -> dict[str, object]:
    linux_work = pathlib.Path(f"/tmp/ls_wsl_job_{uuid.uuid4().hex[:10]}")
    in_dir = linux_work / "in"
    st_dir = linux_work / "staging"
    in_dir.mkdir(parents=True, exist_ok=True)
    st_dir.mkdir(parents=True, exist_ok=True)

    host_in = pathlib.Path(str(spec["input_dir_wsl"]))
    host_st = pathlib.Path(str(spec["staging_dir_wsl"]))
    host_worker = pathlib.Path(str(spec["worker_script_wsl"]))
    limits: dict[str, object] = spec["limits"]  # type: ignore[assignment]
    bpf_bytes = base64.b64decode(str(spec["seccomp_bpf_b64"]))

    with tempfile.NamedTemporaryFile(prefix="ls_bpf_", suffix=".bpf", delete=False) as tmp_bpf:
        tmp_bpf.write(bpf_bytes)
        tmp_bpf.flush()
        bpf_path = pathlib.Path(tmp_bpf.name)

    try:
        for item in host_in.iterdir():
            dst = in_dir / item.name
            if item.is_symlink():
                os.symlink(os.readlink(item), dst)
            elif item.is_file():
                shutil.copy2(item, dst)

        local_worker = linux_work / host_worker.name
        shutil.copy2(host_worker, local_worker)

        resolved_args = [
            str(a).replace("{INPUT_DIR}", "/work/in").replace("{STAGING_DIR}", "/work/staging")
            for a in spec["worker_args"]  # type: ignore[attr-defined]
        ]

        unit_name = f"ls-wsl-{uuid.uuid4().hex[:10]}.scope"
        bwrap_cmd = [
            "bwrap",
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
            "--setenv",
            "PATH",
            "/usr/bin:/bin",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "usr/lib",
            "/lib",
            "--symlink",
            "usr/lib64",
            "/lib64",
            "--symlink",
            "usr/bin",
            "/bin",
        ]
        if pathlib.Path("/etc/alternatives").exists():
            bwrap_cmd.extend(["--ro-bind", "/etc/alternatives", "/etc/alternatives"])
        if pathlib.Path("/etc/ld.so.cache").exists():
            bwrap_cmd.extend(["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"])

        bwrap_cmd.extend([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            str(in_dir),
            "/work/in",
            "--bind",
            str(st_dir),
            "/work/staging",
            "--ro-bind",
            str(local_worker),
            "/work/worker.py",
            "--chdir",
            "/work/staging",
        ])

        with bpf_path.open("rb") as bpf_fh:
            bwrap_cmd.extend(["--seccomp", str(bpf_fh.fileno())])
            bwrap_cmd.extend(["/usr/bin/python3", "-I", "-X", "utf8", "/work/worker.py", *resolved_args])

            mem_bytes = max(int(limits["max_memory_bytes"]), 1024 * 1024)  # type: ignore[arg-type]
            tasks_max = int(limits["max_processes"])  # type: ignore[arg-type]
            cpu_quota = int(limits["cpu_quota_percent"])  # type: ignore[arg-type]
            timeout_s = float(limits["timeout_ms"]) / 1000.0  # type: ignore[arg-type]
            max_out_bytes = int(limits["max_output_bytes"])  # type: ignore[arg-type]

            cmd = [
                "systemd-run",
                "--user",
                "--scope",
                f"--unit={unit_name}",
                "-p",
                f"MemoryMax={mem_bytes}",
                "-p",
                "MemorySwapMax=0",
                "-p",
                f"TasksMax={tasks_max}",
                "-p",
                f"CPUQuota={cpu_quota}%",
                "--",
                *bwrap_cmd,
            ]

            t0 = time.monotonic()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                pass_fds=(bpf_fh.fileno(),),
            )
            timed_out = False
            try:
                stdout, stderr = proc.communicate(timeout=timeout_s)
                rc = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                subprocess.run(["systemctl", "--user", "kill", unit_name], capture_output=True)
                subprocess.run(["systemctl", "--user", "stop", unit_name], capture_output=True)
                proc.kill()
                stdout, stderr = proc.communicate()
                rc = proc.returncode if proc.returncode is not None else -15
            dt_ms = round((time.monotonic() - t0) * 1000.0, 2)

        violations: list[str] = []
        host_st.mkdir(parents=True, exist_ok=True)
        for item in st_dir.iterdir():
            st = os.lstat(item)
            if stat.S_ISLNK(st.st_mode):
                violations.append(f"SYMLINK_IN_STAGING:{item.name}")
                continue
            if not stat.S_ISREG(st.st_mode):
                violations.append(f"NON_REGULAR_IN_STAGING:{item.name}")
                continue
            if st.st_size > max_out_bytes:
                violations.append(f"OVERSIZED_IN_STAGING:{item.name}")
                continue
            shutil.copy2(item, host_st / item.name)

        return {
            "exit_code": int(rc),
            "timed_out": timed_out,
            "stdout": (stdout or "").strip(),
            "stderr": (stderr or "").strip(),
            "duration_ms": dt_ms,
            "staging_violations": violations,
        }
    finally:
        with contextlib.suppress(OSError):
            os.unlink(bpf_path)
        shutil.rmtree(linux_work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-b64", required=True)
    args = parser.parse_args()
    spec = json.loads(base64.b64decode(args.spec_b64).decode("utf-8"))
    print(json.dumps(run_bwrap(spec), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
