"""Validate JSON Schemas against Draft 2020-12 and verify Python worker scripts."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

import jsonschema

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMAS_DIR = REPO_ROOT / "schemas"
WORKER_SCRIPT = REPO_ROOT / "runtime" / "dummy_worker" / "worker.py"
RUNNER_SCRIPT = REPO_ROOT / "runtime" / "linux_sandbox_runner" / "runner.py"


def test_all_json_schemas_valid_draft_2020_12() -> None:
    schema_files = sorted(SCHEMAS_DIR.glob("*.schema.json"))
    assert len(schema_files) == 10
    for sf in schema_files:
        schema = json.loads(sf.read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)


def test_phase2_workspace_history_and_exchange_schemas() -> None:
    ex_schema = json.loads((SCHEMAS_DIR / "exchange_task.schema.json").read_text(encoding="utf-8"))
    hist_schema = json.loads(
        (SCHEMAS_DIR / "history_records.schema.json").read_text(encoding="utf-8")
    )

    valid_ex = {
        "schema_version": "1.0.0",
        "task_id": "task-1",
        "request_id": "req-1",
        "project_id": "proj-1",
        "actor": "external_agent",
        "allowed_operation": "propose_edit",
        "target_rel_path": "latex/main.tex",
        "target_revision": 1,
        "input_hash": "b" * 64,
        "status": "proposed",
        "expires_at_utc": "2026-12-01T00:00:00Z",
        "output_hash": "c" * 64,
        "audit_id": "aud-1",
        "proposal_content": "\\section{Test}",
    }
    jsonschema.validate(instance=valid_ex, schema=ex_schema)

    spoof_ex = json.loads(json.dumps(valid_ex))
    spoof_ex["actor"] = "cli_user"
    try:
        jsonschema.validate(instance=spoof_ex, schema=ex_schema)
        raise AssertionError("non-external_agent actor must fail exchange schema")
    except jsonschema.ValidationError:
        pass

    valid_consent = {
        "schema_version": "1.0.0",
        "consent_id": "c-1",
        "subject_scope": "proj-1",
        "purpose": "history_save",
        "grantor": "teacher",
        "granted_at_utc": "2026-11-26T00:00:00Z",
        "policy_version": "1.0.0",
        "revoked_at_utc": None,
    }
    jsonschema.validate(instance=valid_consent, schema=hist_schema)


def test_job_request_and_ipc_schema_reject_network_or_unknown_method() -> None:
    req_schema = json.loads((SCHEMAS_DIR / "job_request.schema.json").read_text(encoding="utf-8"))
    valid_req = {
        "schema_version": "1.0.0",
        "request_id": "req-1",
        "job_id": "job-1",
        "actor": "cli_user",
        "claimed_actor": "cli_user",
        "project_id": "proj-1",
        "operation": "dummy_echo",
        "purpose": "security_verification",
        "policy_version": "1.0.0",
        "input_revision": 1,
        "input_hash": "a" * 64,
        "classification": "Public",
        "allowed_inputs": ["sample.json"],
        "staging_output_ref": "out.json",
        "resource_limits": {
            "max_memory_bytes": 67108864,
            "max_processes": 8,
            "cpu_quota_percent": 50,
            "timeout_ms": 15000,
            "max_output_bytes": 1048576,
            "max_stdio_bytes": 262144,
            "allow_network": False,
        },
    }
    jsonschema.validate(instance=valid_req, schema=req_schema)

    bad_stdio = json.loads(json.dumps(valid_req))
    bad_stdio["resource_limits"]["max_stdio_bytes"] = 128
    try:
        jsonschema.validate(instance=bad_stdio, schema=req_schema)
        raise AssertionError("max_stdio_bytes < 1024 must fail schema validation")
    except jsonschema.ValidationError:
        pass

    bad_net = json.loads(json.dumps(valid_req))
    bad_net["resource_limits"]["allow_network"] = True
    try:
        jsonschema.validate(instance=bad_net, schema=req_schema)
        raise AssertionError("allow_network=True must fail schema validation")
    except jsonschema.ValidationError:
        pass


def test_dummy_worker_benign_and_runner_help(tmp_path: pathlib.Path) -> None:
    in_file = tmp_path / "in.json"
    out_file = tmp_path / "out.json"
    raw = json.dumps({"title": "Synthetic Unit Test"}).encode("utf-8")
    in_file.write_bytes(raw)
    expected_hash = hashlib.sha256(raw).hexdigest()

    proc = subprocess.run(
        [
            sys.executable,
            str(WORKER_SCRIPT),
            "--mode",
            "benign",
            "--input",
            str(in_file),
            "--output",
            str(out_file),
            "--job-id",
            "job-py-1",
            "--revision",
            "3",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "BENIGN_OK" in proc.stdout
    out_doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert out_doc["job_id"] == "job-py-1"
    assert out_doc["input_revision"] == 3
    assert out_doc["input_hash"] == expected_hash

    # Verify standalone Linux runner compiles & exposes --help cleanly
    runner_help = subprocess.run(
        [sys.executable, str(RUNNER_SCRIPT), "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--spec-b64" in runner_help.stdout
    assert "--inner-exec" in runner_help.stdout

    # Verify zero-sleep burst modes are wired cleanly in worker.py
    inode_dir = tmp_path / "inodes"
    inode_dir.mkdir()
    proc_inodes = subprocess.run(
        [
            sys.executable,
            str(WORKER_SCRIPT),
            "--mode",
            "resource_disk_inodes",
            "--output",
            str(inode_dir),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "DISK_INODES_COMPLETED=64" in proc_inodes.stdout

    worker_src = WORKER_SCRIPT.read_text(encoding="utf-8")
    assert "def mode_resource_disk_spray_fast" in worker_src
