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
import sys
import tempfile
import threading
import time
import uuid

MAX_STAGING_FILES = 32


def _ceil_page(n: int) -> int:
    return max(4096, ((int(n) + 4095) // 4096) * 4096)


def _scan_staging_contents(st_dir: pathlib.Path) -> tuple[int, int, list[str], list[pathlib.Path]]:
    files = 0
    total_bytes = 0
    violations: list[str] = []
    regular_files: list[pathlib.Path] = []
    for dirpath, dirnames, filenames in os.walk(st_dir, followlinks=False):
        dp = pathlib.Path(dirpath)
        kept_dirs: list[str] = []
        for dname in dirnames:
            dp_sub = dp / dname
            st = os.lstat(dp_sub)
            rel = dp_sub.relative_to(st_dir).as_posix()
            if stat.S_ISLNK(st.st_mode):
                violations.append(f"SYMLINK_DIR_IN_STAGING:{rel}")
            else:
                kept_dirs.append(dname)
        dirnames[:] = kept_dirs
        for fname in filenames:
            p = dp / fname
            st = os.lstat(p)
            rel = p.relative_to(st_dir).as_posix()
            if stat.S_ISLNK(st.st_mode):
                violations.append(f"SYMLINK_IN_STAGING:{rel}")
            elif not stat.S_ISREG(st.st_mode):
                violations.append(f"NON_REGULAR_IN_STAGING:{rel}")
            else:
                files += 1
                total_bytes += st.st_size
                regular_files.append(p)
    return files, total_bytes, violations, regular_files


def _drain_stream_bounded(
    stream: object,
    max_bytes: int,
    overflow_event: threading.Event,
    out_box: list[str],
) -> None:
    if stream is None:
        out_box.append("")
        return
    collected = bytearray()
    while True:
        chunk = stream.read(4096)  # type: ignore[attr-defined]
        if not chunk:
            break
        remaining = max(0, max_bytes - len(collected))
        if remaining > 0:
            collected.extend(chunk[:remaining])
        if len(chunk) > remaining:
            overflow_event.set()
            break
    out_box.append(bytes(collected).decode("utf-8", errors="replace").strip())


def _build_bwrap_cmd(
    in_dir: pathlib.Path,
    st_dir: pathlib.Path,
    local_worker: pathlib.Path,
    bpf_fd: int,
    max_tmp_bytes: int,
    max_out_bytes: int,
    resolved_args: list[str],
) -> list[str]:
    cmd = [
        "prlimit",
        f"--fsize={max_out_bytes}",
        "--",
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
        cmd.extend(["--ro-bind", "/etc/alternatives", "/etc/alternatives"])
    if pathlib.Path("/etc/ld.so.cache").exists():
        cmd.extend(["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"])

    cmd.extend([
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        str(max_tmp_bytes),
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
        "--seccomp",
        str(bpf_fd),
        "/usr/bin/python3",
        "-I",
        "-X",
        "utf8",
        "/work/worker.py",
        *resolved_args,
    ])
    return cmd


def _run_inner_exec(inner_spec_path: pathlib.Path, bpf_fd: int) -> int:
    inner = json.loads(inner_spec_path.read_text(encoding="utf-8"))
    st_dir = pathlib.Path(str(inner["st_dir"]))
    host_st = pathlib.Path(str(inner["host_st"]))
    in_dir = pathlib.Path(str(inner["in_dir"]))
    local_worker = pathlib.Path(str(inner["local_worker"]))
    resolved_args = [str(a) for a in inner["worker_args"]]
    max_out_bytes = int(inner["max_out_bytes"])
    max_tmp_bytes = int(inner["tmp_cap_bytes"])
    staging_cap_bytes = int(inner["staging_cap_bytes"])
    staging_nr_inodes = int(inner["staging_nr_inodes"])
    result_file = pathlib.Path(str(inner["result_file"]))

    subprocess.run(
        [
            "mount",
            "-t",
            "tmpfs",
            "-o",
            f"size={staging_cap_bytes},nr_inodes={staging_nr_inodes},mode=0700",
            "tmpfs",
            str(st_dir),
        ],
        check=True,
    )

    bwrap_cmd = _build_bwrap_cmd(
        in_dir=in_dir,
        st_dir=st_dir,
        local_worker=local_worker,
        bpf_fd=bpf_fd,
        max_tmp_bytes=max_tmp_bytes,
        max_out_bytes=max_out_bytes,
        resolved_args=resolved_args,
    )
    proc = subprocess.run(bwrap_cmd, pass_fds=(bpf_fd,))
    bwrap_rc = int(proc.returncode)

    sv = os.statvfs(st_dir)
    files_n, total_b, violations, regular_files = _scan_staging_contents(st_dir)
    fsize_killed = bwrap_rc in (-25, 153)
    space_exhausted = (
        (bwrap_rc != 0 and (sv.f_bavail == 0 or sv.f_favail == 0))
        or (sv.f_blocks > 1 and sv.f_bavail == 0)
        or sv.f_favail == 0
    )
    disk_limit_exceeded = (
        files_n > MAX_STAGING_FILES
        or total_b > max_out_bytes
        or fsize_killed
        or space_exhausted
    )

    host_st.mkdir(parents=True, exist_ok=True)
    if not disk_limit_exceeded and not violations and bwrap_rc == 0:
        for src in regular_files:
            rel = src.relative_to(st_dir)
            dst = host_st / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    payload = {
        "exit_code": bwrap_rc,
        "disk_limit_exceeded": disk_limit_exceeded,
        "staging_violations": violations,
        "staging_files": files_n,
        "staging_bytes": total_b,
        "f_bavail": sv.f_bavail,
        "f_favail": sv.f_favail,
        "staging_cap_bytes": staging_cap_bytes,
        "staging_nr_inodes": staging_nr_inodes,
    }
    tmp_res = result_file.with_suffix(".tmp")
    tmp_res.write_text(json.dumps(payload), encoding="utf-8")
    os.replace(tmp_res, result_file)
    return 0


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

        mem_bytes = max(int(limits["max_memory_bytes"]), 1024 * 1024)  # type: ignore[arg-type]
        tasks_max = int(limits["max_processes"])  # type: ignore[arg-type]
        cpu_quota = int(limits["cpu_quota_percent"])  # type: ignore[arg-type]
        timeout_s = float(limits["timeout_ms"]) / 1000.0  # type: ignore[arg-type]
        max_out_bytes = int(limits["max_output_bytes"])  # type: ignore[arg-type]
        max_stdio_bytes = int(limits.get("max_stdio_bytes", 256 * 1024))  # type: ignore[arg-type]
        max_tmp_bytes = max(max_out_bytes, 65536)
        staging_cap_bytes = _ceil_page(max_out_bytes)
        staging_nr_inodes = MAX_STAGING_FILES + 1  # 1 root directory inode + 32 file inodes

        inner_result_path = linux_work / "inner_result.json"
        inner_spec_path = linux_work / "inner_spec.json"
        inner_spec_path.write_text(
            json.dumps({
                "st_dir": str(st_dir),
                "host_st": str(host_st),
                "in_dir": str(in_dir),
                "local_worker": str(local_worker),
                "worker_args": resolved_args,
                "max_out_bytes": max_out_bytes,
                "tmp_cap_bytes": max_tmp_bytes,
                "staging_cap_bytes": staging_cap_bytes,
                "staging_nr_inodes": staging_nr_inodes,
                "result_file": str(inner_result_path),
            }),
            encoding="utf-8",
        )

        unit_name = f"ls-wsl-{uuid.uuid4().hex[:10]}.scope"

        with bpf_path.open("rb") as bpf_fh:
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
                "unshare",
                "-Ur",
                "-m",
                "--",
                sys.executable,
                "-I",
                str(pathlib.Path(__file__).resolve()),
                "--inner-exec",
                str(inner_spec_path),
                "--bpf-fd",
                str(bpf_fh.fileno()),
            ]

            t0 = time.monotonic()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(bpf_fh.fileno(),),
            )
            overflow_event = threading.Event()
            out_box: list[str] = []
            err_box: list[str] = []
            t_out = threading.Thread(
                target=_drain_stream_bounded,
                args=(proc.stdout, max_stdio_bytes, overflow_event, out_box),
                daemon=True,
            )
            t_err = threading.Thread(
                target=_drain_stream_bounded,
                args=(proc.stderr, max_stdio_bytes, overflow_event, err_box),
                daemon=True,
            )
            t_out.start()
            t_err.start()

            timed_out = False
            stdio_limit_exceeded = False

            def _kill_scope() -> None:
                subprocess.run(["systemctl", "--user", "kill", unit_name], capture_output=True)
                subprocess.run(["systemctl", "--user", "stop", unit_name], capture_output=True)
                with contextlib.suppress(OSError):
                    proc.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=3.0)

            while True:
                rc_poll = proc.poll()
                if rc_poll is not None:
                    break
                if overflow_event.is_set():
                    stdio_limit_exceeded = True
                    _kill_scope()
                    break
                if time.monotonic() - t0 >= timeout_s:
                    timed_out = True
                    _kill_scope()
                    break
                time.sleep(0.02)

            t_out.join(timeout=2.0)
            t_err.join(timeout=2.0)
            outer_rc = proc.returncode if proc.returncode is not None else -15
            if overflow_event.is_set():
                stdio_limit_exceeded = True

            dt_ms = round((time.monotonic() - t0) * 1000.0, 2)

        stdout_s = out_box[0] if out_box else ""
        stderr_s = err_box[0] if err_box else ""

        host_st.mkdir(parents=True, exist_ok=True)
        disk_limit_exceeded = False
        violations: list[str] = []
        if not stdio_limit_exceeded and not timed_out and inner_result_path.exists():
            inner_res = json.loads(inner_result_path.read_text(encoding="utf-8"))
            rc = int(inner_res["exit_code"])
            disk_limit_exceeded = bool(inner_res["disk_limit_exceeded"])
            violations = [str(v) for v in inner_res.get("staging_violations", [])]
        else:
            rc = outer_rc if outer_rc != 0 else -1

        return {
            "exit_code": int(rc),
            "timed_out": timed_out,
            "stdio_limit_exceeded": stdio_limit_exceeded,
            "disk_limit_exceeded": disk_limit_exceeded,
            "stdout": stdout_s,
            "stderr": stderr_s,
            "duration_ms": dt_ms,
            "staging_violations": violations,
        }
    finally:
        with contextlib.suppress(OSError):
            os.unlink(bpf_path)
        shutil.rmtree(linux_work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-b64")
    parser.add_argument("--inner-exec")
    parser.add_argument("--bpf-fd", type=int)
    args = parser.parse_args()
    if args.inner_exec is not None:
        if args.bpf_fd is None:
            parser.error("--bpf-fd is required with --inner-exec")
        return _run_inner_exec(pathlib.Path(args.inner_exec), int(args.bpf_fd))
    if args.spec_b64 is None:
        parser.error("either --spec-b64 or --inner-exec is required")
    spec = json.loads(base64.b64decode(args.spec_b64).decode("utf-8"))
    print(json.dumps(run_bwrap(spec), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
