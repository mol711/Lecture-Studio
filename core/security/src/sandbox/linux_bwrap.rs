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

    use tempfile::{Builder, NamedTempFile};
    use uuid::Uuid;

    use crate::errors::SecurityError;
    use crate::sandbox::seccomp_bpf::build_x86_64_seccomp_bpf;
    use crate::sandbox::{IsolatedProcessResult, SandboxedProcessSpec};

    #[derive(serde::Deserialize)]
    struct InnerResult {
        exit_code: i32,
        disk_limit_exceeded: bool,
        #[serde(default)]
        staging_violations: Vec<String>,
    }

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
        cfg!(target_arch = "x86_64")
            && cmd_exists("bwrap")
            && cmd_exists("systemd-run")
            && cmd_exists("unshare")
            && cmd_exists("mount")
            && cmd_exists("python3")
    }

    pub fn run(spec: &SandboxedProcessSpec) -> Result<IsolatedProcessResult, SecurityError> {
        if !is_available() {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "Linux Bubblewrap/unshare/mount sandbox is unavailable.".to_string(),
                detail: "linux_bwrap".to_string(),
            });
        }

        fs::create_dir_all(&spec.staging_dir).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed to prepare Linux staging directory.".to_string(),
            detail: e.to_string(),
        })?;

        let tmp_work = Builder::new()
            .prefix("ls_bwrap_tmpfs_")
            .tempdir()
            .map_err(|e| SecurityError::SandboxUnavailable {
                user_message: "Failed creating temporary Linux work directory.".to_string(),
                detail: e.to_string(),
            })?;
        let mnt_staging = tmp_work.path().join("mnt_staging");
        fs::create_dir_all(&mnt_staging).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed creating tmpfs staging mountpoint.".to_string(),
            detail: e.to_string(),
        })?;
        let inner_result_path = tmp_work.path().join("inner_result.json");
        let inner_spec_path = tmp_work.path().join("inner_spec.json");

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

        let max_out_bytes = spec.limits.max_output_bytes;
        let max_tmp_bytes = max_out_bytes.max(65_536);
        let staging_cap_bytes = max_out_bytes
            .saturating_add(4095)
            .checked_div(4096)
            .unwrap_or(1)
            .saturating_mul(4096)
            .max(4096);

        let inner_spec = serde_json::json!({
            "in_dir": spec.input_dir.to_string_lossy(),
            "mnt_dir": mnt_staging.to_string_lossy(),
            "host_st": spec.staging_dir.to_string_lossy(),
            "worker_script": spec.worker_script.to_string_lossy(),
            "worker_args": resolved_args,
            "max_out_bytes": max_out_bytes,
            "tmp_cap_bytes": max_tmp_bytes,
            "staging_cap_bytes": staging_cap_bytes,
            "staging_nr_inodes": 33,
            "result_file": inner_result_path.to_string_lossy(),
            "bpf_fd": bpf_fd,
        });
        fs::write(&inner_spec_path, inner_spec.to_string()).map_err(|e| {
            SecurityError::SandboxUnavailable {
                user_message: "Failed writing Linux tmpfs wrapper spec.".to_string(),
                detail: e.to_string(),
            }
        })?;

        let wrapper_py = r#"
import json, os, pathlib, shutil, stat, subprocess, sys
s = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
mnt, host_st = pathlib.Path(s['mnt_dir']), pathlib.Path(s['host_st'])
max_out = int(s['max_out_bytes'])
subprocess.run(['mount', '-t', 'tmpfs', '-o', f"size={s['staging_cap_bytes']},nr_inodes={s['staging_nr_inodes']},mode=0700", 'tmpfs', str(mnt)], check=True)
cmd = ['prlimit', f'--fsize={max_out}', '--', 'bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--clearenv', '--setenv', 'PATH', '/usr/bin:/bin', '--ro-bind', '/usr', '/usr', '--symlink', 'usr/lib', '/lib', '--symlink', 'usr/lib64', '/lib64', '--symlink', 'usr/bin', '/bin']
for p in ('/etc/alternatives', '/etc/ld.so.cache'):
    if pathlib.Path(p).exists():
        cmd.extend(['--ro-bind', p, p])
cmd.extend(['--proc', '/proc', '--dev', '/dev', '--size', str(s['tmp_cap_bytes']), '--tmpfs', '/tmp', '--ro-bind', s['in_dir'], '/work/in', '--bind', str(mnt), '/work/staging', '--ro-bind', s['worker_script'], '/work/worker.py', '--chdir', '/work/staging', '--seccomp', str(s['bpf_fd']), '/usr/bin/python3', '-I', '-X', 'utf8', '/work/worker.py', *s['worker_args']])
proc = subprocess.run(cmd, pass_fds=(int(s['bpf_fd']),))
rc = int(proc.returncode)
sv = os.statvfs(mnt)
files, total_b, violations, regs = 0, 0, [], []
for dp, dn, fn in os.walk(mnt, followlinks=False):
    dpp = pathlib.Path(dp)
    dn[:] = [d for d in dn if not stat.S_ISLNK(os.lstat(dpp / d).st_mode)]
    for f in fn:
        p = dpp / f
        st = os.lstat(p)
        rel = p.relative_to(mnt).as_posix()
        if stat.S_ISLNK(st.st_mode): violations.append(f'SYMLINK_IN_STAGING:{rel}')
        elif not stat.S_ISREG(st.st_mode): violations.append(f'NON_REGULAR_IN_STAGING:{rel}')
        else: files += 1; total_b += st.st_size; regs.append(p)
fsize_killed = rc in (-25, 153)
space_exhausted = (rc != 0 and (sv.f_bavail == 0 or sv.f_favail == 0)) or (sv.f_blocks > 1 and sv.f_bavail == 0) or sv.f_favail == 0
disk_exceeded = files > 32 or total_b > max_out or fsize_killed or space_exhausted
if not disk_exceeded and not violations and rc == 0:
    for src in regs:
        dst = host_st / src.relative_to(mnt)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
pathlib.Path(s['result_file']).write_text(json.dumps({'exit_code': rc, 'disk_limit_exceeded': disk_exceeded, 'staging_violations': violations}), encoding='utf-8')
"#;

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
            "unshare",
            "-Ur",
            "-m",
            "--",
            "/usr/bin/python3",
            "-I",
            "-c",
            wrapper_py,
            &inner_spec_path.to_string_lossy(),
        ]);
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
        let duration_ms = t0.elapsed().as_secs_f64() * 1000.0;

        let mut exit_code = status.code().unwrap_or(-15);
        let mut disk_limit_exceeded = false;
        let mut staging_violations = Vec::new();
        if !stdio_limit_exceeded && !timed_out {
            if let Ok(raw) = fs::read_to_string(&inner_result_path) {
                if let Ok(parsed) = serde_json::from_str::<InnerResult>(&raw) {
                    exit_code = parsed.exit_code;
                    disk_limit_exceeded = parsed.disk_limit_exceeded;
                    staging_violations = parsed.staging_violations;
                }
            } else if exit_code == 0 {
                exit_code = -1;
            }
        }

        Ok(IsolatedProcessResult {
            backend_name: "linux_bwrap".to_string(),
            exit_code,
            timed_out,
            stdio_limit_exceeded,
            disk_limit_exceeded,
            stdout,
            stderr,
            duration_ms,
            staging_violations,
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
