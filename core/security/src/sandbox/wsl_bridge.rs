//! Windows-to-WSL2 bridge allowing explicit switching to Linux bwrap+cgroups+seccomp.

use crate::errors::SecurityError;
use crate::sandbox::{IsolatedProcessResult, SandboxBackend, SandboxedProcessSpec};

#[derive(Debug, Clone)]
pub struct WslLinuxBwrapBackend {
    pub distro: String,
}

impl WslLinuxBwrapBackend {
    #[must_use]
    pub fn new(distro: impl Into<String>) -> Self {
        Self {
            distro: distro.into(),
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use serde::Deserialize;
    use serde_json::json;

    use crate::errors::SecurityError;
    use crate::sandbox::seccomp_bpf::build_x86_64_seccomp_bpf;
    use crate::sandbox::{IsolatedProcessResult, SandboxedProcessSpec};

    pub fn windows_to_wsl_path(win_path: &Path) -> Result<String, SecurityError> {
        let resolved = fs::canonicalize(win_path).unwrap_or_else(|_| win_path.to_path_buf());
        let raw = resolved.to_string_lossy();
        let trimmed = raw.strip_prefix(r"\\?\").unwrap_or(&raw);
        let mut chars = trimmed.chars();
        let drive = chars.next().ok_or_else(|| SecurityError::InvalidParams {
            user_message: "Invalid Windows path for WSL conversion.".to_string(),
            detail: trimmed.to_string(),
        })?;
        let rest: String = chars.collect();
        let after_colon = rest.strip_prefix(':').unwrap_or(&rest).replace('\\', "/");
        Ok(format!(
            "/mnt/{}{}",
            drive.to_ascii_lowercase(),
            after_colon
        ))
    }

    pub fn is_available(distro: &str) -> bool {
        let Ok(out) = Command::new("wsl")
            .args([
                "-d",
                distro,
                "--",
                "which",
                "bwrap",
                "systemd-run",
                "python3",
            ])
            .output()
        else {
            return false;
        };
        out.status.success()
    }

    fn find_runner_script() -> Result<PathBuf, SecurityError> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let candidate = manifest_dir
            .parent()
            .and_then(Path::parent)
            .map(|root| {
                root.join("runtime")
                    .join("linux_sandbox_runner")
                    .join("runner.py")
            })
            .ok_or_else(|| SecurityError::SandboxUnavailable {
                user_message: "Could not locate runtime/linux_sandbox_runner/runner.py."
                    .to_string(),
                detail: manifest_dir.display().to_string(),
            })?;
        if !candidate.exists() {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "Missing runtime/linux_sandbox_runner/runner.py.".to_string(),
                detail: candidate.display().to_string(),
            });
        }
        Ok(candidate)
    }

    #[derive(Debug, Deserialize)]
    struct RunnerOutput {
        exit_code: i32,
        timed_out: bool,
        stdout: String,
        stderr: String,
        duration_ms: f64,
        #[serde(default)]
        staging_violations: Vec<String>,
    }

    pub fn run(
        distro: &str,
        spec: &SandboxedProcessSpec,
    ) -> Result<IsolatedProcessResult, SecurityError> {
        if !is_available(distro) {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "WSL2 Linux Bubblewrap backend is unavailable (fail-closed)."
                    .to_string(),
                detail: format!("distro={distro}"),
            });
        }

        fs::create_dir_all(&spec.staging_dir).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed creating host staging directory.".to_string(),
            detail: e.to_string(),
        })?;

        let runner_wsl = windows_to_wsl_path(&find_runner_script()?)?;
        let seccomp_b64 = B64.encode(build_x86_64_seccomp_bpf());
        let payload = json!({
            "job_id": spec.job_id,
            "worker_script_wsl": windows_to_wsl_path(&spec.worker_script)?,
            "input_dir_wsl": windows_to_wsl_path(&spec.input_dir)?,
            "staging_dir_wsl": windows_to_wsl_path(&spec.staging_dir)?,
            "worker_args": spec.worker_args,
            "limits": spec.limits,
            "seccomp_bpf_b64": seccomp_b64,
        });
        let b64 = B64.encode(payload.to_string().as_bytes());

        let proc_out = Command::new("wsl")
            .args([
                "-d",
                distro,
                "--",
                "python3",
                &runner_wsl,
                "--spec-b64",
                &b64,
            ])
            .output()
            .map_err(|e| SecurityError::SandboxUnavailable {
                user_message: "Failed invoking WSL2 Linux sandbox runner.".to_string(),
                detail: e.to_string(),
            })?;

        if !proc_out.status.success() {
            let err_s = String::from_utf8_lossy(&proc_out.stderr).trim().to_string();
            let out_s = String::from_utf8_lossy(&proc_out.stdout).trim().to_string();
            return Err(SecurityError::SandboxUnavailable {
                user_message: "WSL2 Linux sandbox runner failed (fail-closed).".to_string(),
                detail: if err_s.is_empty() { out_s } else { err_s },
            });
        }

        let stdout_full = String::from_utf8_lossy(&proc_out.stdout);
        let last_line = stdout_full
            .lines()
            .rfind(|ln| !ln.trim().is_empty())
            .ok_or_else(|| SecurityError::SandboxUnavailable {
                user_message: "WSL2 runner returned empty output.".to_string(),
                detail: String::new(),
            })?;
        let parsed: RunnerOutput =
            serde_json::from_str(last_line).map_err(|e| SecurityError::SandboxUnavailable {
                user_message: "Failed decoding WSL2 runner JSON output.".to_string(),
                detail: format!("{e}: {last_line}"),
            })?;

        Ok(IsolatedProcessResult {
            backend_name: "wsl_linux_bwrap".to_string(),
            exit_code: parsed.exit_code,
            timed_out: parsed.timed_out,
            stdout: parsed.stdout,
            stderr: parsed.stderr,
            duration_ms: parsed.duration_ms,
            staging_violations: parsed.staging_violations,
        })
    }
}

impl SandboxBackend for WslLinuxBwrapBackend {
    fn name(&self) -> &'static str {
        "wsl_linux_bwrap"
    }

    fn is_available(&self) -> bool {
        #[cfg(windows)]
        {
            imp::is_available(&self.distro)
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    fn run(&self, spec: &SandboxedProcessSpec) -> Result<IsolatedProcessResult, SecurityError> {
        #[cfg(windows)]
        {
            imp::run(&self.distro, spec)
        }
        #[cfg(not(windows))]
        {
            let _ = spec;
            Err(SecurityError::SandboxUnavailable {
                user_message: "WSL2 bridge is only available on Windows hosts.".to_string(),
                detail: "not_windows".to_string(),
            })
        }
    }
}
