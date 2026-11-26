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
use lecture_studio_security::{
    Actor, DataClassification, HashChainedAuditLog, JobExecutionContext, JobRequest, JobStatus,
    Operation, PolicyEngine, Purpose, ResourceLimits, SandboxMode, SecurityGateway,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

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

fn target_linux_mode() -> SandboxMode {
    if cfg!(target_os = "linux") {
        SandboxMode::LinuxBwrap
    } else {
        SandboxMode::WslLinuxBwrap
    }
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

fn make_req(job_id: &str, req_id: &str, input_hash: &str, staging_ref: &str) -> JobRequest {
    JobRequest {
        schema_version: "1.0.0".to_string(),
        request_id: req_id.to_string(),
        job_id: job_id.to_string(),
        actor: Actor::CliUser,
        claimed_actor: Actor::CliUser,
        project_id: "proj-linux-boundary".to_string(),
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
fn linux_bwrap_cgroups_seccomp_security_boundaries() {
    let mode = target_linux_mode();
    let backend = create_sandbox_backend(mode, "Ubuntu")
        .expect("Linux Bubblewrap (native or WSL2) must be available for boundary tests");

    let tmp = TempDir::new().unwrap();
    let in_dir = tmp.path().join("in");
    let official_dir = tmp.path().join("official");
    let quarantine_dir = tmp.path().join("quarantine");
    let audit_path = tmp.path().join("audit").join("audit.jsonl");
    for d in [&in_dir, &official_dir, &quarantine_dir] {
        fs::create_dir_all(d).unwrap();
    }

    let in_file = in_dir.join("lecture_sample.json");
    let in_bytes = br#"{"title":"Synthetic Linux Lecture","topic":"Bubblewrap"}"#;
    fs::write(&in_file, in_bytes).unwrap();
    let in_hash = hex::encode(Sha256::digest(in_bytes));

    let canary = start_canary_server();
    let canary_port = canary.port;
    let canary_hits = canary.hits;
    let stop_canary = canary.stop;
    let canary_thread = canary.handle;
    let worker = dummy_worker_path();
    let mut gw = SecurityGateway::new(
        PolicyEngine::default(),
        HashChainedAuditLog::new(&audit_path, true),
        mode,
        "Ubuntu",
        true,
    );

    // 1. Benign execution + seccomp verification inside bwrap
    let st1 = tmp.path().join("st1");
    let r1 = gw
        .execute_dummy_job(
            &make_req("job-l01", "req-l01", &in_hash, "out.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st1,
                official_output_file: &official_dir.join("l01.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "check_seccomp".into(),
                    "--output".into(),
                    "{STAGING_DIR}/out.json".into(),
                    "--job-id".into(),
                    "job-l01".into(),
                    "--revision".into(),
                    "1".into(),
                    "--input-hash".into(),
                    in_hash.clone(),
                ],
            },
        )
        .unwrap();
    assert_eq!(r1.status, JobStatus::Committed);
    assert!(r1.diagnostics[0].message.contains("Seccomp=2 Filters=1"));
    assert!(official_dir.join("l01.json").exists());

    // 2. SEC-01: unauthorized read, RO input write, outside write
    for (idx, args) in [
        vec![
            "--mode".into(),
            "escape_read_secret".into(),
            "--secret".into(),
            "/etc/shadow".into(),
        ],
        vec![
            "--mode".into(),
            "escape_write_ro_input".into(),
            "--input".into(),
            "{INPUT_DIR}/lecture_sample.json".into(),
        ],
        vec![
            "--mode".into(),
            "escape_write_outside".into(),
            "--outside".into(),
            "/var/tmp/ls_should_not_exist.txt".into(),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let st = tmp.path().join(format!("st_l_sec01_{idx}"));
        let res = backend
            .run(&SandboxedProcessSpec {
                job_id: format!("l-sec01-{idx}"),
                worker_script: worker.clone(),
                input_dir: in_dir.clone(),
                staging_dir: st,
                worker_args: args,
                limits: ResourceLimits::default(),
            })
            .unwrap();
        assert_ne!(res.exit_code, 0);
        assert!(!res.stdout.contains("BREACH:"));
    }
    assert_eq!(fs::read(&in_file).unwrap(), in_bytes);

    // 3. SEC-02: TCP ext, UDP DNS, IPv6, loopback canary, child proc network
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
        let st = tmp.path().join(format!("st_l_sec02_{idx}"));
        let res = backend
            .run(&SandboxedProcessSpec {
                job_id: format!("l-sec02-{idx}"),
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
    assert!(canary_hits.lock().unwrap().is_empty());

    // 4. SEC-04: Memory limit (64 MiB), TasksMax (8), Timeout + detached orphan kill
    let mem_res = backend
        .run(&SandboxedProcessSpec {
            job_id: "l-sec04-mem".into(),
            worker_script: worker.clone(),
            input_dir: in_dir.clone(),
            staging_dir: tmp.path().join("st_l_mem"),
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
            job_id: "l-sec04-fork".into(),
            worker_script: worker.clone(),
            input_dir: in_dir.clone(),
            staging_dir: tmp.path().join("st_l_fork"),
            worker_args: vec![
                "--mode".into(),
                "resource_fork".into(),
                "--fork-count".into(),
                "24".into(),
            ],
            limits: ResourceLimits {
                max_processes: 8,
                ..ResourceLimits::default()
            },
        })
        .unwrap();
    assert_ne!(fork_res.exit_code, 0);
    assert!(!fork_res.stdout.contains("FORK_SPAWNED=24/24"));

    let st_to = tmp.path().join("st_l_to");
    let to_res = gw
        .execute_dummy_job(
            &JobRequest {
                resource_limits: ResourceLimits {
                    timeout_ms: 2000,
                    ..ResourceLimits::default()
                },
                ..make_req("job-l-to", "req-l-to", &in_hash, "out.json")
            },
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &st_to,
                official_output_file: &official_dir.join("should_not_exist_l_to.json"),
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "resource_timeout_orphan".into(),
                    "--child-pid-file".into(),
                    "{STAGING_DIR}/orphan.pid".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(to_res.status, JobStatus::Cancelled);

    #[cfg(windows)]
    {
        let pgrep = Command::new("wsl")
            .args(["-d", "Ubuntu", "--", "pgrep", "-f", "time.sleep\\(30\\)"])
            .output()
            .unwrap();
        assert!(
            String::from_utf8_lossy(&pgrep.stdout).trim().is_empty(),
            "Linux orphan survived timeout!"
        );
    }

    // 5. SEC-01/05: Staging symlink created inside Linux sandbox is caught and quarantined
    let sym_out = official_dir.join("should_not_exist_sym.json");
    let r_sym = gw
        .execute_dummy_job(
            &make_req("job-l-sym", "req-l-sym", &in_hash, "sym.json"),
            &JobExecutionContext {
                trusted_channel_actor: Actor::CliUser,
                current_revision: 1,
                input_dir: &in_dir,
                staging_dir: &tmp.path().join("st_l_sym"),
                official_output_file: &sym_out,
                quarantine_dir: &quarantine_dir,
                worker_script: &worker,
                worker_args: &[
                    "--mode".into(),
                    "tamper_symlink_output".into(),
                    "--output".into(),
                    "{STAGING_DIR}/sym.json".into(),
                    "--secret".into(),
                    "/etc/passwd".into(),
                ],
            },
        )
        .unwrap();
    assert_eq!(r_sym.status, JobStatus::Quarantined);
    assert!(!sym_out.exists());

    // 6. Verify hash-chained audit log
    let (ok, count, reason) = HashChainedAuditLog::new(&audit_path, true)
        .verify_chain()
        .unwrap();
    assert!(ok, "audit verification failed: {reason}");
    assert!(count >= 3);

    stop_canary.store(true, Ordering::Relaxed);
    canary_thread.join().unwrap();
}
