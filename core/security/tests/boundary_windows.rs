#![cfg(windows)]

use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use lecture_studio_security::sandbox::{create_sandbox_backend, SandboxedProcessSpec};
use lecture_studio_security::staging::measure_staging_usage;
use lecture_studio_security::{
    Actor, DataClassification, HashChainedAuditLog, JobExecutionContext, JobRequest, JobStatus,
    Operation, PolicyEngine, Purpose, ResourceLimits, SandboxMode, SecurityGateway,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

fn dummy_worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("runtime")
        .join("dummy_worker")
        .join("worker.py")
}

struct CanaryServer {
    port: u16,
    hits: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<()>,
}

fn start_canary_server() -> CanaryServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let hits_c = Arc::clone(&hits);
    let stop_c = Arc::clone(&stop);

    let handle = thread::spawn(move || {
        while !stop_c.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, addr)) => {
                    let mut buf = [0u8; 128];
                    let n = stream.read(&mut buf).unwrap_or(0);
                    hits_c
                        .lock()
                        .unwrap()
                        .push(format!("{addr}:{}", String::from_utf8_lossy(&buf[..n])));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break,
            }
        }
    });
    CanaryServer {
        port,
        hits,
        stop,
        handle,
    }
}

fn is_win_pid_alive(pid: u32) -> bool {
    // SAFETY: querying exit code on a limited handle.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code);
        CloseHandle(h);
        ok != 0 && code == STILL_ACTIVE as u32
    }
}

fn make_req(job_id: &str, req_id: &str, input_hash: &str, staging_ref: &str) -> JobRequest {
    JobRequest {
        schema_version: "1.0.0".to_string(),
        request_id: req_id.to_string(),
        job_id: job_id.to_string(),
        actor: Actor::CliUser,
        claimed_actor: Actor::CliUser,
        project_id: "proj-win-boundary".to_string(),
        operation: Operation::DummyEcho,
        purpose: Purpose::SecurityVerification,
        policy_version: "1.0.0".to_string(),
        input_revision: 1,
        input_hash: input_hash.to_string(),
        classification: DataClassification::Public,
        allowed_inputs: vec!["lecture_sample.json".to_string()],
        staging_output_ref: staging_ref.to_string(),
        resource_limits: ResourceLimits::default(),
    }
}

#[test]
fn windows_appcontainer_security_boundaries_sec01_to_sec06() {
    let tmp = TempDir::new().unwrap();
    let in_dir = tmp.path().join("in");
    let secret_dir = tmp.path().join("secret");
    let outside_dir = tmp.path().join("outside");
    let official_dir = tmp.path().join("official");
    let quarantine_dir = tmp.path().join("quarantine");
    let audit_path = tmp.path().join("audit").join("audit.jsonl");
    for d in [
        &in_dir,
        &secret_dir,
        &outside_dir,
        &official_dir,
        &quarantine_dir,
    ] {
        fs::create_dir_all(d).unwrap();
    }

    let in_file = in_dir.join("lecture_sample.json");
    let in_bytes = br#"{"title":"Synthetic Windows Lecture","topic":"AppContainer"}"#;
    fs::write(&in_file, in_bytes).unwrap();
    let in_hash = hex::encode(Sha256::digest(in_bytes));

    let secret_file = secret_dir.join("secret.txt");
    fs::write(&secret_file, "TOP_SECRET_WIN_CANARY").unwrap();
    let outside_file = outside_dir.join("outside.txt");
    fs::write(&outside_file, "ORIGINAL_OUTSIDE").unwrap();

    // Create unprivileged NTFS directory junction pointing to secret_dir
    let junction = in_dir.join("junction_to_secret");
    let mk = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&secret_dir)
        .output()
        .unwrap();
    assert!(mk.status.success(), "mklink /J failed: {:?}", mk);

    let canary = start_canary_server();
    let canary_port = canary.port;
    let canary_hits = canary.hits;
    let stop_canary = canary.stop;
    let canary_thread = canary.handle;
    let worker = dummy_worker_path();
    let mut gw = SecurityGateway::new(
        PolicyEngine::default(),
        HashChainedAuditLog::new(&audit_path, true),
        SandboxMode::WindowsAppcontainer,
        "Ubuntu",
        true,
    );

    // 1. Benign execution -> committed
    let st1 = tmp.path().join("st1");
    let r1 = gw
        .execute_dummy_job(
            &make_req("job-w01", "req-w01", &in_hash, "out.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st1,
                official_output_file: &official_dir.join("w01.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "benign".into(),
                    "--input".into(),
                    "{INPUT_DIR}\\lecture_sample.json".into(),
                    "--output".into(),
                    "{STAGING_DIR}\\out.json".into(),
                    "--job-id".into(),
                    "job-w01".into(),
                    "--revision".into(),
                    "1".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(r1.status, JobStatus::Committed);
    assert_eq!(r1.metrics.backend, "windows_appcontainer");
    assert!(official_dir.join("w01.json").exists());

    // 2. SEC-01: unauthorized read, RO input write, outside write, NTFS junction read
    let backend = create_sandbox_backend(SandboxMode::WindowsAppcontainer, "Ubuntu").unwrap();
    for (idx, args) in [
        vec![
            "--mode".into(),
            "escape_read_secret".into(),
            "--secret".into(),
            secret_file.to_string_lossy().into(),
        ],
        vec![
            "--mode".into(),
            "escape_write_ro_input".into(),
            "--input".into(),
            "{INPUT_DIR}\\lecture_sample.json".into(),
        ],
        vec![
            "--mode".into(),
            "escape_write_outside".into(),
            "--outside".into(),
            outside_file.to_string_lossy().into(),
        ],
        vec![
            "--mode".into(),
            "escape_symlink".into(),
            "--symlink".into(),
            "{INPUT_DIR}\\junction_to_secret\\secret.txt".into(),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let st = tmp.path().join(format!("st_sec01_{idx}"));
        let res = backend
            .run(&SandboxedProcessSpec {
                job_id: format!("sec01-{idx}"),
                worker_script: worker.clone(),
                input_dir: in_dir.clone(),
                staging_dir: st,
                worker_args: args,
                limits: ResourceLimits::default(),
            })
            .unwrap();
        assert_ne!(
            res.exit_code, 0,
            "SEC-01 case {idx} unexpectedly succeeded: {}",
            res.stdout
        );
        assert!(!res.stdout.contains("BREACH:"));
    }
    assert_eq!(fs::read(&in_file).unwrap(), in_bytes);
    assert_eq!(
        fs::read_to_string(&outside_file).unwrap(),
        "ORIGINAL_OUTSIDE"
    );

    // 3. SEC-02: TCP ext, UDP DNS, IPv6, host loopback canary, child proc network
    for (idx, args) in [
        vec!["--mode".into(), "net_tcp_external".into()],
        vec!["--mode".into(), "net_udp_dns".into()],
        vec!["--mode".into(), "net_ipv6".into()],
        vec![
            "--mode".into(),
            "net_loopback".into(),
            "--loopback-port".into(),
            canary_port.to_string(),
        ],
        vec![
            "--mode".into(),
            "net_child_proc".into(),
            "--loopback-port".into(),
            canary_port.to_string(),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let st = tmp.path().join(format!("st_sec02_{idx}"));
        let res = backend
            .run(&SandboxedProcessSpec {
                job_id: format!("sec02-{idx}"),
                worker_script: worker.clone(),
                input_dir: in_dir.clone(),
                staging_dir: st,
                worker_args: args,
                limits: ResourceLimits::default(),
            })
            .unwrap();
        assert_ne!(
            res.exit_code, 0,
            "SEC-02 case {idx} failed to block: {}",
            res.stdout
        );
        assert!(!res.stdout.contains("BREACH:"));
    }
    assert!(
        canary_hits.lock().unwrap().is_empty(),
        "Canary received loopback hit!"
    );

    // 4. SEC-04: Memory limit (64 MiB), ActiveProcessLimit (6), Timeout + detached orphan kill
    let mem_res = backend
        .run(&SandboxedProcessSpec {
            job_id: "sec04-mem".into(),
            worker_script: worker.clone(),
            input_dir: in_dir.clone(),
            staging_dir: tmp.path().join("st_mem"),
            worker_args: vec![
                "--mode".into(),
                "resource_mem".into(),
                "--mem-mb".into(),
                "256".into(),
            ],
            limits: ResourceLimits::default(),
        })
        .unwrap();
    assert_ne!(mem_res.exit_code, 0);
    assert!(!mem_res.stdout.contains("ALLOC_COMPLETED_MB="));

    let fork_res = backend
        .run(&SandboxedProcessSpec {
            job_id: "sec04-fork".into(),
            worker_script: worker.clone(),
            input_dir: in_dir.clone(),
            staging_dir: tmp.path().join("st_fork"),
            worker_args: vec![
                "--mode".into(),
                "resource_fork".into(),
                "--fork-count".into(),
                "24".into(),
            ],
            limits: ResourceLimits {
                max_processes: 6,
                ..ResourceLimits::default()
            },
        })
        .unwrap();
    assert_ne!(fork_res.exit_code, 0);
    assert!(!fork_res.stdout.contains("FORK_SPAWNED=24/24"));

    let st_timeout = tmp.path().join("st_timeout");
    let pid_file = st_timeout.join("orphan.pid");
    let to_res = gw
        .execute_dummy_job(
            &JobRequest {
                resource_limits: ResourceLimits {
                    timeout_ms: 4000,
                    ..ResourceLimits::default()
                },
                ..make_req("job-w-to", "req-w-to", &in_hash, "out.json")
            },
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st_timeout,
                official_output_file: &official_dir.join("should_not_exist_to.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "resource_timeout_orphan".into(),
                    "--child-pid-file".into(),
                    "{STAGING_DIR}\\orphan.pid".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(to_res.status, JobStatus::Cancelled);
    assert_eq!(to_res.error_code, Some(-32005));
    assert!(
        to_res.diagnostics[0].message.contains("ORPHAN_SPAWNED"),
        "Worker did not spawn orphan before timeout: {:?}",
        to_res.diagnostics
    );
    assert!(
        !pid_file.exists(),
        "Timed-out staging output must be quarantined"
    );
    let quarantined_pid_file = quarantine_dir.join("job-w-to").join("orphan.pid");
    let orphan_pid: u32 = fs::read_to_string(&quarantined_pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(
        !is_win_pid_alive(orphan_pid),
        "Orphan process {orphan_pid} survived Job termination!"
    );

    // 5. SEC-03: Invalid schema quarantined, Gateway down fail-closed, audit unwritable fail-closed
    let st_bad = tmp.path().join("st_bad");
    let bad_out = official_dir.join("should_not_exist_bad.json");
    let r_bad = gw
        .execute_dummy_job(
            &make_req("job-w-bad", "req-w-bad", &in_hash, "bad.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st_bad,
                official_output_file: &bad_out,
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "tamper_invalid_schema".into(),
                    "--output".into(),
                    "{STAGING_DIR}\\bad.json".into(),
                    "--job-id".into(),
                    "job-w-bad".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(r_bad.status, JobStatus::Quarantined);
    assert!(!bad_out.exists());

    let mut gw_down = SecurityGateway::new(
        PolicyEngine::default(),
        HashChainedAuditLog::new(&audit_path, true),
        SandboxMode::WindowsAppcontainer,
        "Ubuntu",
        false,
    );
    let r_down = gw_down
        .execute_dummy_job(
            &make_req("job-w-down", "req-w-down", &in_hash, "out.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &tmp.path().join("st_down"),
                official_output_file: &official_dir.join("should_not_exist_down.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(r_down.status, JobStatus::Failed);
    assert_eq!(r_down.diagnostics[0].code, "GATEWAY_DOWN");

    let mut gw_aud_fail = SecurityGateway::new(
        PolicyEngine::default(),
        HashChainedAuditLog::new(tmp.path().join("ro_audit.jsonl"), false),
        SandboxMode::WindowsAppcontainer,
        "Ubuntu",
        true,
    );
    let r_aud = gw_aud_fail
        .execute_dummy_job(
            &make_req("job-w-aud", "req-w-aud", &in_hash, "out.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &tmp.path().join("st_aud"),
                official_output_file: &official_dir.join("should_not_exist_aud.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "benign".into(),
                    "--input".into(),
                    "{INPUT_DIR}\\lecture_sample.json".into(),
                    "--output".into(),
                    "{STAGING_DIR}\\out.json".into(),
                    "--job-id".into(),
                    "job-w-aud".into(),
                    "--revision".into(),
                    "1".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(r_aud.status, JobStatus::Failed);
    assert_eq!(r_aud.error_code, Some(-32004));
    assert!(!official_dir.join("should_not_exist_aud.json").exists());

    // 6. SEC-06: Actor spoof & stale revision
    let r_spoof = gw
        .execute_dummy_job(
            &make_req("job-w-sp", "req-w-sp", &in_hash, "out.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::ExternalAgent,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &tmp.path().join("st_sp"),
                official_output_file: &official_dir.join("should_not_exist_sp.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(r_spoof.status, JobStatus::Failed);
    assert_eq!(r_spoof.diagnostics[0].code, "ACTOR_SPOOF");

    let r_stale = gw
        .execute_dummy_job(
            &make_req("job-w-st", "req-w-st", &in_hash, "out.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 2,
                input_dir: &in_dir,
                staging_dir: &tmp.path().join("st_st"),
                official_output_file: &official_dir.join("should_not_exist_st.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[],
            },
        )
        .unwrap();
    assert_eq!(r_stale.status, JobStatus::Failed);
    assert_eq!(r_stale.diagnostics[0].code, "STALE_REVISION");

    // 7. SEC-04 (Finding 2): Bounded stdio terminates flood job and caps Gateway memory
    let st_stdio = tmp.path().join("st_stdio");
    let stdio_out = official_dir.join("should_not_exist_stdio.json");
    let r_stdio = gw
        .execute_dummy_job(
            &JobRequest {
                resource_limits: ResourceLimits {
                    max_stdio_bytes: 32 * 1024,
                    ..ResourceLimits::default()
                },
                ..make_req("job-w-stdio", "req-w-stdio", &in_hash, "out.json")
            },
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st_stdio,
                official_output_file: &stdio_out,
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &["--mode".into(), "resource_stdio_flood".into()],
            },
        )
        .unwrap();
    assert_eq!(r_stdio.status, JobStatus::Cancelled);
    assert_eq!(r_stdio.error_code, Some(-32005));
    assert_eq!(r_stdio.diagnostics[0].code, "STDIO_LIMIT_EXCEEDED");
    assert!(r_stdio.diagnostics[0].message.len() <= 32 * 1024 + 128);
    assert!(!stdio_out.exists());

    // 8. SEC-04 (Finding 3): Runtime disk flood (single-file & multi-file spray) terminates and purges staging
    let st_disk1 = tmp.path().join("st_disk1");
    let r_disk1 = gw
        .execute_dummy_job(
            &JobRequest {
                resource_limits: ResourceLimits {
                    max_output_bytes: 256 * 1024,
                    ..ResourceLimits::default()
                },
                ..make_req("job-w-disk1", "req-w-disk1", &in_hash, "flood.bin")
            },
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st_disk1,
                official_output_file: &official_dir.join("should_not_exist_disk1.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "resource_disk_single".into(),
                    "--output".into(),
                    "{STAGING_DIR}\\flood.bin".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(r_disk1.status, JobStatus::Cancelled);
    assert_eq!(r_disk1.diagnostics[0].code, "DISK_LIMIT_EXCEEDED");
    let (d1_files, d1_bytes) = measure_staging_usage(&st_disk1).unwrap();
    assert_eq!(d1_files, 0);
    assert_eq!(d1_bytes, 0);
    assert!(quarantine_dir
        .join("job-w-disk1")
        .join("resource_limit_quarantine.json")
        .exists());

    let st_disk2 = tmp.path().join("st_disk2");
    let r_disk2 = gw
        .execute_dummy_job(
            &JobRequest {
                resource_limits: ResourceLimits {
                    max_output_bytes: 256 * 1024,
                    ..ResourceLimits::default()
                },
                ..make_req("job-w-disk2", "req-w-disk2", &in_hash, "out.json")
            },
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st_disk2,
                official_output_file: &official_dir.join("should_not_exist_disk2.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "resource_disk_spray".into(),
                    "--output".into(),
                    "{STAGING_DIR}".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(r_disk2.status, JobStatus::Cancelled);
    assert_eq!(r_disk2.diagnostics[0].code, "DISK_LIMIT_EXCEEDED");
    let (d2_files, d2_bytes) = measure_staging_usage(&st_disk2).unwrap();
    assert_eq!(d2_files, 0);
    assert_eq!(d2_bytes, 0);

    // Pre-existing official artifact & input remain intact after all resource limit aborts
    assert!(official_dir.join("w01.json").exists());
    assert_eq!(fs::read(&in_file).unwrap(), in_bytes);

    // Verify audit chain on the main audit log
    let (chain_ok, entries, reason) = HashChainedAuditLog::new(&audit_path, true)
        .verify_chain()
        .unwrap();
    assert!(chain_ok, "audit chain verification failed: {reason}");
    assert!(entries >= 5);

    stop_canary.store(true, Ordering::Relaxed);
    canary_thread.join().unwrap();
}
