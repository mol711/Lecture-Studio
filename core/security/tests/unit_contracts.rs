use std::fs;
use std::io::Write;

use lecture_studio_security::audit::AuditAppendInput;
use lecture_studio_security::ipc::{
    decode_content_length_frame, decode_ndjson_line, encode_content_length_frame,
    verify_channel_actor, IpcEnvelope, MAX_MESSAGE_BYTES,
};
use lecture_studio_security::sandbox::{
    create_sandbox_backend, list_backend_availability, seccomp_bpf,
};
use lecture_studio_security::staging::{
    atomic_promote, is_staging_tainted, measure_staging_usage, purge_oversized_staging,
    quarantine_staging, validate_relative_staging_ref, StagingInspector,
};
use lecture_studio_security::{
    Actor, AuditDecision, DataClassification, HashChainedAuditLog, JobExecutionContext, JobRequest,
    JobStatus, Operation, PolicyEngine, Purpose, ResourceLimits, SandboxMode, SecurityError,
    SecurityGateway,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn sample_hash() -> String {
    let mut h = Sha256::new();
    h.update(b"synthetic-lecture-input");
    hex::encode(h.finalize())
}

fn base_job_request(actor: Actor, claimed: Actor) -> JobRequest {
    JobRequest {
        schema_version: "1.0.0".to_string(),
        request_id: "req-1".to_string(),
        job_id: "job-1".to_string(),
        actor,
        claimed_actor: claimed,
        project_id: "proj-1".to_string(),
        operation: Operation::DummyEcho,
        purpose: Purpose::SecurityVerification,
        policy_version: "1.0.0".to_string(),
        input_revision: 1,
        input_hash: sample_hash(),
        classification: DataClassification::Public,
        allowed_inputs: vec!["in.json".to_string()],
        staging_output_ref: "out.json".to_string(),
        resource_limits: ResourceLimits::default(),
    }
}

#[test]
fn policy_and_classification_inheritance_enforced() {
    assert_eq!(
        DataClassification::inherit_from(&[
            DataClassification::Public,
            DataClassification::Confidential,
            DataClassification::Internal,
        ]),
        DataClassification::Confidential
    );
    assert_eq!(
        DataClassification::inherit_from(&[
            DataClassification::Public,
            DataClassification::Restricted,
        ]),
        DataClassification::Restricted
    );
    assert_eq!(
        DataClassification::inherit_from(&[]),
        DataClassification::Restricted
    );

    let engine = PolicyEngine::default();
    let ok_req = base_job_request(Actor::CliUser, Actor::CliUser);
    let rule = engine
        .evaluate(&ok_req, Actor::CliUser)
        .expect("cli_user dummy_echo should be allowed");
    assert!(rule.can_commit_official);

    // Spoofed claimed_actor rejected
    let spoof = base_job_request(Actor::ExternalAgent, Actor::CliUser);
    let err = engine.evaluate(&spoof, Actor::ExternalAgent).unwrap_err();
    assert_eq!(err.code(), "ACTOR_SPOOF");
    assert_eq!(err.jsonrpc_code(), -32001);

    // Restricted data rejected for cli_user (max Confidential)
    let mut restricted = base_job_request(Actor::CliUser, Actor::CliUser);
    restricted.classification = DataClassification::Restricted;
    let err2 = engine.evaluate(&restricted, Actor::CliUser).unwrap_err();
    assert_eq!(err2.code(), "CLASSIFICATION_DENIED");

    // allow_network = true rejected
    let mut net_req = base_job_request(Actor::CliUser, Actor::CliUser);
    net_req.resource_limits.allow_network = true;
    let err3 = engine.evaluate(&net_req, Actor::CliUser).unwrap_err();
    assert_eq!(err3.code(), "NETWORK_DENIED");

    // Invalid YAML policy fails closed
    let tmp = TempDir::new().unwrap();
    let bad_yaml = tmp.path().join("bad_policy.yaml");
    fs::write(&bad_yaml, "not: valid: policy: [").unwrap();
    let err4 = PolicyEngine::from_yaml_file(&bad_yaml).unwrap_err();
    assert_eq!(err4.code(), "POLICY_INVALID");
}

#[test]
fn ipc_poc02_framing_limits_depth_methods_and_actor() {
    let mut params = Map::new();
    params.insert("actor".to_string(), Value::String("cli_user".to_string()));
    let env = IpcEnvelope {
        jsonrpc: "2.0".to_string(),
        id: Value::Number(1.into()),
        method: "job.submit".to_string(),
        params,
    };

    let framed = encode_content_length_frame(&env).unwrap();
    let decoded = decode_content_length_frame(&framed).unwrap();
    assert_eq!(decoded.method, "job.submit");
    verify_channel_actor(&decoded, Actor::CliUser).unwrap();

    // Spoofed actor in IPC params
    let err_spoof = verify_channel_actor(&decoded, Actor::ExternalAgent).unwrap_err();
    assert_eq!(err_spoof.code(), "ACTOR_SPOOF");
    assert_eq!(err_spoof.jsonrpc_code(), -32001);

    // Unknown method rejected with -32601
    let bad_method = br#"{"jsonrpc":"2.0","id":2,"method":"shell.exec","params":{}}"#;
    let err_m = decode_ndjson_line(bad_method).unwrap_err();
    assert_eq!(err_m.jsonrpc_code(), -32601);

    // Oversized frame > 4 MiB rejected with -32700
    let huge = format!(
        "Content-Length: {}\r\n\r\n{}",
        MAX_MESSAGE_BYTES + 10,
        "a".repeat(MAX_MESSAGE_BYTES + 10)
    );
    let err_big = decode_content_length_frame(huge.as_bytes()).unwrap_err();
    assert_eq!(err_big.jsonrpc_code(), -32700);

    // Excessive nesting depth > 32 rejected with -32700
    let mut nested = json!({"leaf": 1});
    for _ in 0..36 {
        nested = json!({"n": nested});
    }
    let deep_json = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "job.status",
        "params": nested
    })
    .to_string();
    let err_depth = decode_ndjson_line(deep_json.as_bytes()).unwrap_err();
    assert_eq!(err_depth.jsonrpc_code(), -32700);

    // Invalid UTF-8 rejected with -32700
    let err_utf8 = decode_ndjson_line(b"\xff\xfe\xfd").unwrap_err();
    assert_eq!(err_utf8.jsonrpc_code(), -32700);
}

#[test]
fn audit_hash_chain_tamper_detection_and_tail_recovery() {
    let tmp = TempDir::new().unwrap();
    let log_path = tmp.path().join("audit.jsonl");
    let log = HashChainedAuditLog::new(&log_path, true);
    let h = sample_hash();

    for i in 1..=3 {
        log.append(AuditAppendInput {
            actor: "cli_user",
            operation: "dummy_echo",
            purpose: "security_verification",
            project_id: "proj-1",
            job_id: &format!("job-{i}"),
            policy_version: "1.0.0",
            classification: DataClassification::Public,
            input_hash: &h,
            output_hash: Some(&h),
            decision: AuditDecision::Allow,
            reason_code: "OK",
            error_code: None,
            extra_keys: &[],
        })
        .unwrap();
    }
    let (ok, count, _) = log.verify_chain().unwrap();
    assert!(ok);
    assert_eq!(count, 3);

    // Reject forbidden raw content keys
    let forbidden = log
        .append(AuditAppendInput {
            actor: "cli_user",
            operation: "dummy_echo",
            purpose: "security_verification",
            project_id: "proj-1",
            job_id: "job-bad",
            policy_version: "1.0.0",
            classification: DataClassification::Public,
            input_hash: &h,
            output_hash: None,
            decision: AuditDecision::Deny,
            reason_code: "TEST",
            error_code: None,
            extra_keys: &["prompt"],
        })
        .unwrap_err();
    assert_eq!(forbidden.jsonrpc_code(), -32004);

    // Simulate crash-truncated trailing line
    {
        let mut fh = fs::OpenOptions::new().append(true).open(&log_path).unwrap();
        writeln!(fh, "{{\"audit_id\":\"partial-crash").unwrap();
    }
    let (ok_before, _, _) = log.verify_chain().unwrap();
    assert!(!ok_before);

    let (recovered_count, sidecar) = log.recover_truncated_tail().unwrap();
    assert_eq!(recovered_count, 3);
    assert!(sidecar.is_some());
    assert!(sidecar.unwrap().exists());
    let (ok_after, count_after, _) = log.verify_chain().unwrap();
    assert!(ok_after);
    assert_eq!(count_after, 3);

    // Unwritable audit fails closed (-32004)
    let ro_log = HashChainedAuditLog::new(tmp.path().join("ro.jsonl"), false);
    let err_ro = ro_log
        .append(AuditAppendInput {
            actor: "cli_user",
            operation: "dummy_echo",
            purpose: "security_verification",
            project_id: "proj-1",
            job_id: "job-ro",
            policy_version: "1.0.0",
            classification: DataClassification::Public,
            input_hash: &h,
            output_hash: None,
            decision: AuditDecision::Allow,
            reason_code: "OK",
            error_code: None,
            extra_keys: &[],
        })
        .unwrap_err();
    assert_eq!(err_ro.jsonrpc_code(), -32004);
}

#[test]
fn staging_inspector_quarantine_and_atomic_promote() {
    let tmp = TempDir::new().unwrap();
    let staging = tmp.path().join("staging");
    let quarantine = tmp.path().join("quarantine");
    let official = tmp.path().join("official").join("out.json");
    fs::create_dir_all(&staging).unwrap();

    let h = sample_hash();
    let valid_doc = json!({
        "schema_version": "1.0.0",
        "job_id": "job-1",
        "input_revision": 1,
        "input_hash": h,
        "worker_pid": 42,
        "echo_title": "Synthetic",
        "status": "ok"
    });
    let out_file = staging.join("out.json");
    fs::write(&out_file, valid_doc.to_string()).unwrap();

    let inspector = StagingInspector::default();
    let (raw, oref) = inspector
        .validate_dummy_output(&staging, "out.json", "job-1", 1, &h)
        .unwrap();
    assert_eq!(oref.size_bytes as usize, raw.len());
    atomic_promote(&raw, &official).unwrap();
    assert!(official.exists());

    // Mismatched revision must be rejected and quarantined
    let bad_rev = json!({
        "schema_version": "1.0.0",
        "job_id": "job-1",
        "input_revision": 99,
        "input_hash": h,
        "worker_pid": 42,
        "echo_title": "Bad",
        "status": "ok"
    });
    let bad_file = staging.join("bad.json");
    fs::write(&bad_file, bad_rev.to_string()).unwrap();
    let err = inspector
        .validate_dummy_output(&staging, "bad.json", "job-1", 1, &h)
        .unwrap_err();
    assert_eq!(err.code(), "REVISION_MISMATCH");
    let q_dir = quarantine_staging(&staging, &quarantine, "job-1").unwrap();
    assert!(q_dir.join("bad.json").exists());
}

#[test]
fn staging_containment_rejects_traversal_absolute_drive_ads_and_oversized() {
    let tmp = TempDir::new().unwrap();
    let staging = tmp.path().join("staging");
    let quarantine = tmp.path().join("quarantine");
    let official = tmp.path().join("official").join("out.json");
    fs::create_dir_all(staging.join("sub")).unwrap();

    // Disallowed staging_output_ref patterns
    for bad_ref in [
        "",
        "../outside.json",
        "sub/../../outside.json",
        "/etc/passwd",
        r"\Windows\System32\drivers\etc\hosts",
        r"C:\temp\out.json",
        "out.json:ads_stream",
        "./out.json",
    ] {
        let err = validate_relative_staging_ref(bad_ref).unwrap_err();
        assert_eq!(
            err.code(),
            "PATH_ESCAPE",
            "expected PATH_ESCAPE for {bad_ref}"
        );
        assert_eq!(err.jsonrpc_code(), -32003);
    }

    // Valid nested relative ref is accepted
    assert!(validate_relative_staging_ref("sub/out.json").is_ok());

    let h = sample_hash();
    let valid_doc = json!({
        "schema_version": "1.0.0",
        "job_id": "job-c",
        "input_revision": 1,
        "input_hash": h,
        "worker_pid": 9,
        "echo_title": "Outside",
        "status": "ok"
    });
    // Place valid JSON outside staging root
    let outside_json = tmp.path().join("outside.json");
    fs::write(&outside_json, valid_doc.to_string()).unwrap();

    let inspector = StagingInspector {
        max_files: 32,
        max_total_bytes: 512,
    };
    let err_rel = inspector
        .validate_dummy_output(&staging, "../outside.json", "job-c", 1, &h)
        .unwrap_err();
    assert_eq!(err_rel.code(), "PATH_ESCAPE");

    let abs_ref = outside_json.to_string_lossy().into_owned();
    let err_abs = inspector
        .validate_dummy_output(&staging, &abs_ref, "job-c", 1, &h)
        .unwrap_err();
    assert_eq!(err_abs.code(), "PATH_ESCAPE");

    // Nested valid output inside staging succeeds
    fs::write(staging.join("sub").join("out.json"), valid_doc.to_string()).unwrap();
    let (_, oref) = inspector
        .validate_dummy_output(&staging, "sub/out.json", "job-c", 1, &h)
        .unwrap();
    assert_eq!(oref.path, "sub/out.json");

    // Oversized output file (> 512 bytes) rejected and purged cleanly
    let huge = "X".repeat(1024);
    fs::write(staging.join("huge.json"), &huge).unwrap();
    let err_sz = inspector
        .validate_dummy_output(&staging, "huge.json", "job-c", 1, &h)
        .unwrap_err();
    assert_eq!(err_sz.code(), "SIZE_LIMIT_EXCEEDED");

    let purge_report =
        purge_oversized_staging(&staging, &quarantine, "job-c", "SIZE_LIMIT_EXCEEDED").unwrap();
    assert_eq!(purge_report.purged_files, 2);
    assert!(!purge_report.tainted);
    assert_eq!(purge_report.remaining_files, 0);
    assert_eq!(purge_report.remaining_bytes, 0);
    let (files_after, bytes_after) = measure_staging_usage(&staging).unwrap();
    assert_eq!(files_after, 0);
    assert_eq!(bytes_after, 0);
    assert!(quarantine
        .join("job-c")
        .join("resource_limit_quarantine.json")
        .exists());

    // Gateway rejects traversal staging_output_ref BEFORE spawning sandbox
    let in_dir = tmp.path().join("in");
    fs::create_dir_all(&in_dir).unwrap();
    let unused_worker = tmp.path().join("worker.py");
    fs::write(&unused_worker, "").unwrap();
    let mut gw = SecurityGateway::new(
        PolicyEngine::default(),
        HashChainedAuditLog::new(tmp.path().join("audit.jsonl"), true),
        SandboxMode::Auto,
        "Ubuntu",
        true,
    );
    let mut bad_req = base_job_request(Actor::CliUser, Actor::CliUser);
    bad_req.staging_output_ref = "../outside.json".to_string();
    let resp = gw
        .execute_dummy_job(
            &bad_req,
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &staging,
                official_output_file: &official,
                quarantine_dir: &quarantine,
                worker_script: &unused_worker,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(resp.status, JobStatus::Failed);
    assert_eq!(resp.error_code, Some(-32003));
    assert_eq!(resp.diagnostics[0].code, "PATH_ESCAPE");
    assert!(!official.exists());
}

#[test]
fn backend_switching_never_falls_back_to_unsandboxed_and_idempotency_holds() {
    let avail = list_backend_availability("Ubuntu");
    assert!(avail.contains_key("linux_bwrap"));
    assert!(avail.contains_key("windows_appcontainer"));
    assert!(avail.contains_key("wsl_linux_bwrap"));

    // Requesting Linux-native backend on Windows (or Windows backend on Linux) must fail closed
    #[cfg(windows)]
    {
        let err = match create_sandbox_backend(SandboxMode::LinuxBwrap, "Ubuntu") {
            Ok(_) => panic!("linux_bwrap must not succeed on Windows host"),
            Err(e) => e,
        };
        assert_eq!(err.jsonrpc_code(), -32002);
        assert!(create_sandbox_backend(SandboxMode::WindowsAppcontainer, "Ubuntu").is_ok());
    }
    #[cfg(target_os = "linux")]
    {
        let err = match create_sandbox_backend(SandboxMode::WindowsAppcontainer, "Ubuntu") {
            Ok(_) => panic!("windows_appcontainer must not succeed on Linux host"),
            Err(e) => e,
        };
        assert_eq!(err.jsonrpc_code(), -32002);
    }

    // Seccomp BPF bytecode check (8-byte aligned instructions, ends in ALLOW)
    let bpf = seccomp_bpf::build_x86_64_seccomp_bpf();
    assert_eq!(bpf.len() % 8, 0);
    assert!(bpf.len() >= 11 * 8);

    // Duplicate request_id rejected with DUPLICATE_REQUEST before running worker
    let tmp = TempDir::new().unwrap();
    let in_dir = tmp.path().join("in");
    let st_dir = tmp.path().join("st");
    let q_dir = tmp.path().join("q");
    let official = tmp.path().join("out.json");
    fs::create_dir_all(&in_dir).unwrap();
    fs::create_dir_all(&st_dir).unwrap();
    let worker_dummy = tmp.path().join("unused_worker.py");
    fs::write(&worker_dummy, "").unwrap();

    let audit = HashChainedAuditLog::new(tmp.path().join("audit.jsonl"), true);
    let mut gw = SecurityGateway::new(
        PolicyEngine::default(),
        audit,
        SandboxMode::Auto,
        "Ubuntu",
        true,
    );
    // Force stale revision on first call to record idem_key quickly without spawning sandbox
    let req = base_job_request(Actor::CliUser, Actor::CliUser);
    let r1 = gw
        .execute_dummy_job(
            &req,
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 2,
                input_dir: &in_dir,
                staging_dir: &st_dir,
                official_output_file: &official,
                quarantine_dir: &q_dir,
                worker_script: &worker_dummy,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(r1.status, JobStatus::Failed);
    assert_eq!(r1.diagnostics[0].code, "STALE_REVISION");

    let r2 = gw
        .execute_dummy_job(
            &req,
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st_dir,
                official_output_file: &official,
                quarantine_dir: &q_dir,
                worker_script: &worker_dummy,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(r2.status, JobStatus::Failed);
    assert_eq!(r2.diagnostics[0].code, "DUPLICATE_REQUEST");
    assert!(!official.exists());
    let _: fn(&SecurityError) -> i32 = SecurityError::jsonrpc_code;
}

#[test]
fn staging_purge_failure_records_remaining_bytes_and_blocks_reuse() {
    let tmp = TempDir::new().unwrap();
    let staging = tmp.path().join("staging_tainted");
    let quarantine = tmp.path().join("quarantine");
    let in_dir = tmp.path().join("in");
    let official = tmp.path().join("official").join("out.json");
    fs::create_dir_all(&staging).unwrap();
    fs::create_dir_all(&in_dir).unwrap();
    let unused_worker = tmp.path().join("unused_worker.py");
    fs::write(&unused_worker, "").unwrap();

    let deletable = staging.join("deletable.bin");
    fs::write(&deletable, vec![b'A'; 256]).unwrap();

    #[cfg(windows)]
    let (locked_path, locked_guard) = {
        use std::os::windows::fs::OpenOptionsExt;
        let p = staging.join("locked.bin");
        fs::write(&p, vec![b'B'; 1024]).unwrap();
        // Hold exclusive handle (share_mode=0) so remove_file fails with sharing violation.
        let fh = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&p)
            .unwrap();
        (p, Some(fh))
    };

    #[cfg(unix)]
    let (locked_path, locked_dir) = {
        use std::os::unix::fs::PermissionsExt;
        let sub = staging.join("locked_sub");
        fs::create_dir_all(&sub).unwrap();
        let p = sub.join("locked.bin");
        fs::write(&p, vec![b'B'; 1024]).unwrap();
        fs::set_permissions(&sub, fs::Permissions::from_mode(0o555)).unwrap();
        (p, sub)
    };

    let err = purge_oversized_staging(
        &staging,
        &quarantine,
        "job-purge-fail",
        "DISK_LIMIT_EXCEEDED",
    )
    .unwrap_err();
    assert_eq!(err.code(), "STAGING_PURGE_FAILED");
    assert_eq!(err.jsonrpc_code(), -32003);

    let report_path = quarantine
        .join("job-purge-fail")
        .join("resource_limit_quarantine.json");
    let report: Value = serde_json::from_str(&fs::read_to_string(&report_path).unwrap()).unwrap();
    assert_eq!(report["tainted"], json!(true));
    assert_eq!(report["status"], json!("purge_incomplete_tainted"));
    assert_eq!(report["before_bytes"], json!(1280));
    assert_eq!(report["purged_bytes"], json!(256));
    assert_eq!(report["remaining_bytes"], json!(1024));
    assert_eq!(report["remaining_files"], json!(1));
    let failures = report["failed_entries"].as_array().unwrap();
    assert!(!failures.is_empty());
    assert!(failures
        .iter()
        .any(|f| f["path"].as_str().unwrap_or("").contains("locked")));
    assert!(is_staging_tainted(&staging));
    assert!(!deletable.exists());
    assert!(locked_path.exists());

    // Even a fresh SecurityGateway must refuse reusing the tainted staging directory BEFORE launch.
    let audit_path = tmp.path().join("audit.jsonl");
    let mut fresh_gw = SecurityGateway::new(
        PolicyEngine::default(),
        HashChainedAuditLog::new(&audit_path, true),
        SandboxMode::Auto,
        "Ubuntu",
        true,
    );
    let reuse_req = base_job_request(Actor::CliUser, Actor::CliUser);
    let reuse_resp = fresh_gw
        .execute_dummy_job(
            &reuse_req,
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &staging,
                official_output_file: &official,
                quarantine_dir: &quarantine,
                worker_script: &unused_worker,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(reuse_resp.status, JobStatus::Failed);
    assert_eq!(reuse_resp.error_code, Some(-32003));
    assert_eq!(reuse_resp.diagnostics[0].code, "STAGING_TAINTED");
    assert_eq!(reuse_resp.metrics.exit_code, None);
    assert!(!official.exists());

    // A non-empty untainted staging directory must also be refused before launch (STAGING_DIRTY).
    let dirty_staging = tmp.path().join("staging_dirty");
    fs::create_dir_all(&dirty_staging).unwrap();
    fs::write(dirty_staging.join("leftover.txt"), b"leftover").unwrap();
    let mut dirty_req = base_job_request(Actor::CliUser, Actor::CliUser);
    dirty_req.request_id = "req-dirty".to_string();
    dirty_req.job_id = "job-dirty".to_string();
    let dirty_resp = fresh_gw
        .execute_dummy_job(
            &dirty_req,
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &dirty_staging,
                official_output_file: &official,
                quarantine_dir: &quarantine,
                worker_script: &unused_worker,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(dirty_resp.status, JobStatus::Failed);
    assert_eq!(dirty_resp.error_code, Some(-32003));
    assert_eq!(dirty_resp.diagnostics[0].code, "STAGING_DIRTY");

    #[cfg(windows)]
    drop(locked_guard);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&locked_dir, fs::Permissions::from_mode(0o755));
    }
}
