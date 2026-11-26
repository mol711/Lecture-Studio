"""Isolated dummy worker (pure Python stdlib) for Phase 1 Security Foundation."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import pathlib
import socket
import subprocess
import sys
import time


def mode_benign(input_path: pathlib.Path, output_path: pathlib.Path, job_id: str, expected_rev: int) -> int:
    raw = input_path.read_bytes()
    input_hash = hashlib.sha256(raw).hexdigest()
    payload = json.loads(raw.decode("utf-8"))
    out_doc = {
        "schema_version": "1.0.0",
        "job_id": job_id,
        "input_revision": expected_rev,
        "input_hash": input_hash,
        "worker_pid": os.getpid(),
        "echo_title": str(payload.get("title", "")),
        "status": "ok",
    }
    output_path.write_text(json.dumps(out_doc, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"BENIGN_OK pid={os.getpid()} sha256={input_hash}")
    return 0


def mode_escape_read(target: pathlib.Path) -> int:
    try:
        data = target.read_text(encoding="utf-8", errors="replace")
        print(f"BREACH:READ:{data[:64]}")
        return 0
    except Exception as exc:
        print(f"BLOCKED:{type(exc).__name__}:{exc}")
        return 1


def mode_escape_write(target: pathlib.Path) -> int:
    try:
        with target.open("a", encoding="utf-8") as fh:
            fh.write("\nTAMPERED_BY_WORKER\n")
        print(f"BREACH:WROTE:{target}")
        return 0
    except Exception as exc:
        print(f"BLOCKED:{type(exc).__name__}:{exc}")
        return 1


def mode_net_tcp(host: str, port: int) -> int:
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(2.0)
            sock.connect((host, port))
            sock.sendall(b"CANARY_PROBE\n")
        print(f"BREACH:TCP_CONNECTED:{host}:{port}")
        return 0
    except Exception as exc:
        print(f"BLOCKED:{type(exc).__name__}:{exc}")
        return 1


def mode_net_udp_dns(host: str, port: int) -> int:
    dns_query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x03com\x00\x00\x01\x00\x01"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2.0)
            sent = sock.sendto(dns_query, (host, port))
            try:
                resp, _ = sock.recvfrom(512)
                print(f"BREACH:UDP_RECV:{len(resp)}")
                return 0
            except Exception as recv_exc:
                print(f"PARTIAL_OR_BLOCKED:sendto={sent}:recv={type(recv_exc).__name__}:{recv_exc}")
                return 2
    except Exception as exc:
        print(f"BLOCKED:{type(exc).__name__}:{exc}")
        return 1


def mode_net_child_proc(loopback_port: int) -> int:
    child_code = (
        "import socket, sys\n"
        "results = []\n"
        f"targets = [('1.1.1.1', 443), ('127.0.0.1', {loopback_port})]\n"
        "for h, p in targets:\n"
        "    try:\n"
        "        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:\n"
        "            s.settimeout(2.0)\n"
        "            s.connect((h, p))\n"
        "            s.sendall(b'CHILD_PROBE\\n')\n"
        "        results.append(f'BREACH:{h}:{p}')\n"
        "    except Exception as e:\n"
        "        results.append(f'BLOCKED:{h}:{p}:{type(e).__name__}:{e}')\n"
        "print(';'.join(results))\n"
        "sys.exit(0 if any(r.startswith('BREACH:') for r in results) else 1)\n"
    )
    proc = subprocess.run(
        [sys.executable, "-I", "-X", "utf8", "-c", child_code],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )
    print(f"CHILD_RC={proc.returncode} STDOUT={(proc.stdout or '').strip()} STDERR={(proc.stderr or '').strip()}")
    return 0 if proc.returncode == 0 else 1


def mode_resource_mem(target_mb: int) -> int:
    blocks: list[bytearray] = []
    step_mb = 4
    allocated_mb = 0
    try:
        while allocated_mb < target_mb:
            buf = bytearray(step_mb * 1024 * 1024)
            for off in range(0, len(buf), 4096):
                buf[off] = 0xAA
            blocks.append(buf)
            allocated_mb += step_mb
            print(f"ALLOC_MB={allocated_mb}", flush=True)
        print(f"ALLOC_COMPLETED_MB={allocated_mb}")
        return 0
    except MemoryError as exc:
        print(f"BLOCKED_MEMORY_ERROR:allocated_mb={allocated_mb}:{exc}")
        return 1


def mode_resource_fork(count: int) -> int:
    children: list[subprocess.Popen[bytes]] = []
    errors: list[str] = []
    for idx in range(count):
        try:
            proc = subprocess.Popen(
                [sys.executable, "-I", "-c", "import time; time.sleep(5)"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            children.append(proc)
        except Exception as exc:
            errors.append(f"idx={idx}:{type(exc).__name__}:{exc}")
            break
    spawned = len(children)
    for proc in children:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            with contextlib.suppress(Exception):
                proc.kill()
    print(f"FORK_SPAWNED={spawned}/{count} ERRORS={errors[:3]}")
    return 0 if spawned == count else 1


def mode_resource_timeout_orphan(child_pid_file: pathlib.Path) -> int:
    child_code = (
        "import os, pathlib, time\n"
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
        "time.sleep(30)\n"
    )
    kwargs: dict[str, object] = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
    }
    if os.name == "nt":
        kwargs["creationflags"] = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
            | getattr(subprocess, "DETACHED_PROCESS", 0x008)
        )
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen([sys.executable, "-I", "-c", child_code], **kwargs)  # type: ignore[arg-type]
    for _ in range(40):
        if child_pid_file.exists():
            break
        time.sleep(0.05)
    print(f"ORPHAN_SPAWNED parent={os.getpid()} child={proc.pid}", flush=True)
    time.sleep(30)
    return 0


def mode_tamper_invalid_schema(output_path: pathlib.Path, job_id: str) -> int:
    bad_doc = {
        "schema_version": "999.0.0",
        "job_id": job_id,
        "input_revision": 9999,
        "unexpected_field": "tampered",
    }
    output_path.write_text(json.dumps(bad_doc), encoding="utf-8")
    print("WROTE_INVALID_SCHEMA")
    return 0


def mode_tamper_symlink_output(output_path: pathlib.Path, secret_path: pathlib.Path) -> int:
    try:
        if output_path.exists() or output_path.is_symlink():
            output_path.unlink()
        os.symlink(secret_path, output_path)
        print(f"CREATED_SYMLINK:{output_path}->{secret_path}")
        return 0
    except Exception as exc:
        print(f"BLOCKED_SYMLINK:{type(exc).__name__}:{exc}")
        return 1


def mode_check_seccomp(output_path: pathlib.Path, job_id: str, expected_rev: int, input_hash: str) -> int:
    if os.name != "posix":
        print("NOT_POSIX")
        return 1
    lines = pathlib.Path("/proc/self/status").read_text(encoding="utf-8").splitlines()
    seccomp_info = {k.strip(): v.strip() for ln in lines if ln.startswith("Seccomp") for k, v in [ln.split(":", 1)]}
    out_doc = {
        "schema_version": "1.0.0",
        "job_id": job_id,
        "input_revision": expected_rev,
        "input_hash": input_hash,
        "worker_pid": os.getpid(),
        "echo_title": f"seccomp={seccomp_info.get('Seccomp')} filters={seccomp_info.get('Seccomp_filters')}",
        "status": "ok",
    }
    output_path.write_text(json.dumps(out_doc), encoding="utf-8")
    print(f"SECCOMP_OK Seccomp={seccomp_info.get('Seccomp')} Filters={seccomp_info.get('Seccomp_filters')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Lecture-Studio Phase 1 isolated dummy worker")
    parser.add_argument("--mode", required=True)
    parser.add_argument("--input", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument("--secret", type=pathlib.Path)
    parser.add_argument("--outside", type=pathlib.Path)
    parser.add_argument("--symlink", type=pathlib.Path)
    parser.add_argument("--loopback-port", type=int, default=0)
    parser.add_argument("--child-pid-file", type=pathlib.Path)
    parser.add_argument("--job-id", default="job-p1")
    parser.add_argument("--revision", type=int, default=1)
    parser.add_argument("--input-hash", default="0" * 64)
    parser.add_argument("--mem-mb", type=int, default=256)
    parser.add_argument("--fork-count", type=int, default=24)
    args = parser.parse_args()

    m = args.mode
    if m == "benign":
        return mode_benign(args.input, args.output, args.job_id, args.revision)
    if m == "escape_read_secret":
        return mode_escape_read(args.secret)
    if m == "escape_write_ro_input":
        return mode_escape_write(args.input)
    if m == "escape_write_outside":
        return mode_escape_write(args.outside)
    if m == "escape_symlink":
        return mode_escape_read(args.symlink)
    if m == "net_tcp_external":
        return mode_net_tcp("1.1.1.1", 443)
    if m == "net_udp_dns":
        return mode_net_udp_dns("1.1.1.1", 53)
    if m == "net_ipv6":
        return mode_net_tcp("2606:4700:4700::1111", 443)
    if m == "net_loopback":
        return mode_net_tcp("127.0.0.1", args.loopback_port)
    if m == "net_child_proc":
        return mode_net_child_proc(args.loopback_port)
    if m == "resource_mem":
        return mode_resource_mem(args.mem_mb)
    if m == "resource_fork":
        return mode_resource_fork(args.fork_count)
    if m == "resource_timeout_orphan":
        return mode_resource_timeout_orphan(args.child_pid_file)
    if m == "tamper_invalid_schema":
        return mode_tamper_invalid_schema(args.output, args.job_id)
    if m == "tamper_symlink_output":
        return mode_tamper_symlink_output(args.output, args.secret)
    if m == "check_seccomp":
        return mode_check_seccomp(args.output, args.job_id, args.revision, args.input_hash)

    print(f"UNKNOWN_MODE:{m}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
