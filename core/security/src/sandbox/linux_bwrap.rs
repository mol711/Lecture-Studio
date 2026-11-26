//! Linux isolation backend: Bubblewrap + cgroups v2 (systemd-run) + seccomp-bpf.

use crate::errors::SecurityError;
use crate::sandbox::{IsolatedProcessResult, SandboxBackend, SandboxedProcessSpec};

#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxBwrapCgroupBackend;

#[cfg(target_os = "linux")]
mod imp {
    use std::fs;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::NamedTempFile;
    use uuid::Uuid;

    use crate::errors::SecurityError;
    use crate::sandbox::seccomp_bpf::build_x86_64_seccomp_bpf;
    use crate::sandbox::{IsolatedProcessResult, SandboxedProcessSpec};
    use crate::staging::measure_staging_usage;

    fn drain_reader_bounded<R: Read>(
        reader: Option<R>,
        max_bytes: usize,
        overflow: Arc<AtomicBool>,
    ) -> String {
        let Some(mut r) = reader else {
            return String::new();
        };
        let mut collected = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let remaining = max_bytes.saturating_sub(collected.len());
                    let take = n.min(remaining);
                    collected.extend_from_slice(&buf[..take]);
                    if n > remaining {
                        overflow.store(true, Ordering::SeqCst);
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&collected).trim().to_string()
    }

    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;

    extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }

    fn cmd_exists(bin: &str) -> bool {
        Command::new("which")
            .arg(bin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    pub fn is_available() -> bool {
        cfg!(target_arch = "x86_64") && cmd_exists("bwrap") && cmd_exists("systemd-run")
    }

    pub fn run(spec: &SandboxedProcessSpec) -> Result<IsolatedProcessResult, SecurityError> {
        if !is_available() {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "Linux Bubblewrap/systemd-run sandbox is unavailable.".to_string(),
                detail: "linux_bwrap".to_string(),
            });
        }

        fs::create_dir_all(&spec.staging_dir).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed to prepare Linux staging directory.".to_string(),
            detail: e.to_string(),
        })?;

        let mut tmp_bpf = NamedTempFile::new().map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed creating temporary seccomp-bpf file.".to_string(),
            detail: e.to_string(),
        })?;
        tmp_bpf
            .write_all(&build_x86_64_seccomp_bpf())
            .and_then(|()| tmp_bpf.flush())
            .map_err(|e| SecurityError::SandboxUnavailable {
                user_message: "Failed writing seccomp-bpf filter.".to_string(),
                detail: e.to_string(),
            })?;
        let bpf_file =
            fs::File::open(tmp_bpf.path()).map_err(|e| SecurityError::SandboxUnavailable {
                user_message: "Failed reopening seccomp-bpf file.".to_string(),
                detail: e.to_string(),
            })?;
        let bpf_fd = bpf_file.as_raw_fd();

        let unit_name = format!(
            "ls-sandbox-{}.scope",
            &Uuid::new_v4().simple().to_string()[..10]
        );
        let resolved_args: Vec<String> = spec
            .worker_args
            .iter()
            .map(|a| {
                a.replace("{INPUT_DIR}", "/work/in")
                    .replace("{STAGING_DIR}", "/work/staging")
            })
            .collect();

        let max_tmp_bytes = spec.limits.max_output_bytes.max(65_536);
        let mut cmd = Command::new("systemd-run");
        cmd.args([
            "--user",
            "--scope",
            &format!("--unit={unit_name}"),
            "-p",
            &format!(
                "MemoryMax={}",
                spec.limits.max_memory_bytes.max(1024 * 1024)
            ),
            "-p",
            "MemorySwapMax=0",
            "-p",
            &format!("TasksMax={}", spec.limits.max_processes),
            "-p",
            &format!("CPUQuota={}%", spec.limits.cpu_quota_percent),
            "--",
            "prlimit",
            &format!("--fsize={}", spec.limits.max_output_bytes),
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
        ]);
        if Path::new("/etc/alternatives").exists() {
            cmd.args(["--ro-bind", "/etc/alternatives", "/etc/alternatives"]);
        }
        if Path::new("/etc/ld.so.cache").exists() {
            cmd.args(["--ro-bind", "/etc/ld.so.cache", "/etc/ld.so.cache"]);
        }
        cmd.args([
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--size",
            &max_tmp_bytes.to_string(),
            "--tmpfs",
            "/tmp",
            "--ro-bind",
            &spec.input_dir.to_string_lossy(),
            "/work/in",
            "--bind",
            &spec.staging_dir.to_string_lossy(),
            "/work/staging",
            "--ro-bind",
            &spec.worker_script.to_string_lossy(),
            "/work/worker.py",
            "--chdir",
            "/work/staging",
            "--seccomp",
            &bpf_fd.to_string(),
            "/usr/bin/python3",
            "-I",
            "-X",
            "utf8",
            "/work/worker.py",
        ]);
        cmd.args(&resolved_args);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // SAFETY: clears FD_CLOEXEC only on `bpf_fd` in the forked child before exec.
        unsafe {
            cmd.pre_exec(move || {
                let flags = fcntl(bpf_fd, F_GETFD);
                if flags >= 0 {
                    let _ = fcntl(bpf_fd, F_SETFD, flags & !FD_CLOEXEC);
                }
                Ok(())
            });
        }

        let t0 = Instant::now();
        let mut child = cmd.spawn().map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed spawning Linux sandboxed process.".to_string(),
            detail: e.to_string(),
        })?;
        drop(bpf_file);

        let max_stdio = usize::try_from(spec.limits.max_stdio_bytes).unwrap_or(256 * 1024);
        let stdio_overflow = Arc::new(AtomicBool::new(false));
        let out_ov = Arc::clone(&stdio_overflow);
        let err_ov = Arc::clone(&stdio_overflow);
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let out_handle =
            thread::spawn(move || drain_reader_bounded(stdout_pipe, max_stdio, out_ov));
        let err_handle =
            thread::spawn(move || drain_reader_bounded(stderr_pipe, max_stdio, err_ov));

        let timeout = Duration::from_millis(spec.limits.timeout_ms);
        let mut timed_out = false;
        let mut stdio_limit_exceeded = false;
        let mut disk_limit_exceeded = false;
        let kill_scope = |child: &mut std::process::Child| {
            let _ = Command::new("systemctl")
                .args(["--user", "kill", &unit_name])
                .output();
            let _ = Command::new("systemctl")
                .args(["--user", "stop", &unit_name])
                .output();
            let _ = child.kill();
            child.wait()
        };

        let status = loop {
            if let Some(st) = child
                .try_wait()
                .map_err(|e| SecurityError::SandboxUnavailable {
                    user_message: "Failed polling sandboxed process.".to_string(),
                    detail: e.to_string(),
                })?
            {
                break st;
            }
            if stdio_overflow.load(Ordering::SeqCst) {
                stdio_limit_exceeded = true;
                break kill_scope(&mut child).map_err(|e| SecurityError::SandboxUnavailable {
                    user_message: "Failed killing process after stdio overflow.".to_string(),
                    detail: e.to_string(),
                })?;
            }
            if measure_staging_usage(&spec.staging_dir)
                .is_ok_and(|(files, bytes)| files > 32 || bytes > spec.limits.max_output_bytes)
            {
                disk_limit_exceeded = true;
                break kill_scope(&mut child).map_err(|e| SecurityError::SandboxUnavailable {
                    user_message: "Failed killing process after staging disk overflow.".to_string(),
                    detail: e.to_string(),
                })?;
            }
            if t0.elapsed() >= timeout {
                timed_out = true;
                break kill_scope(&mut child).map_err(|e| SecurityError::SandboxUnavailable {
                    user_message: "Failed waiting for killed sandboxed process.".to_string(),
                    detail: e.to_string(),
                })?;
            }
            thread::sleep(Duration::from_millis(20));
        };

        let stdout = out_handle.join().unwrap_or_default();
        let stderr = err_handle.join().unwrap_or_default();
        if stdio_overflow.load(Ordering::SeqCst) {
            stdio_limit_exceeded = true;
        }
        if !stdio_limit_exceeded
            && !timed_out
            && measure_staging_usage(&spec.staging_dir)
                .is_ok_and(|(files, bytes)| files > 32 || bytes > spec.limits.max_output_bytes)
        {
            disk_limit_exceeded = true;
        }
        let duration_ms = t0.elapsed().as_secs_f64() * 1000.0;

        Ok(IsolatedProcessResult {
            backend_name: "linux_bwrap".to_string(),
            exit_code: status.code().unwrap_or(-15),
            timed_out,
            stdio_limit_exceeded,
            disk_limit_exceeded,
            stdout,
            stderr,
            duration_ms,
            staging_violations: Vec::new(),
        })
    }
}

impl SandboxBackend for LinuxBwrapCgroupBackend {
    fn name(&self) -> &'static str {
        "linux_bwrap"
    }

    fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            imp::is_available()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    fn run(&self, spec: &SandboxedProcessSpec) -> Result<IsolatedProcessResult, SecurityError> {
        #[cfg(target_os = "linux")]
        {
            imp::run(spec)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = spec;
            Err(SecurityError::SandboxUnavailable {
                user_message: "Linux Bubblewrap sandbox is only available on Linux.".to_string(),
                detail: "not_linux".to_string(),
            })
        }
    }
}
