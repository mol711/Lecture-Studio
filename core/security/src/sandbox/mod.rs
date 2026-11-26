//! Switchable OS sandbox backends (fail-closed: never falls back to unsandboxed host).

pub mod linux_bwrap;
pub mod seccomp_bpf;
pub mod windows_appcontainer;
pub mod wsl_bridge;

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::errors::SecurityError;
use crate::models::{ResourceLimits, SandboxMode};

#[derive(Debug, Clone)]
pub struct SandboxedProcessSpec {
    pub job_id: String,
    pub worker_script: PathBuf,
    pub input_dir: PathBuf,
    pub staging_dir: PathBuf,
    pub worker_args: Vec<String>,
    pub limits: ResourceLimits,
}

#[derive(Debug, Clone)]
pub struct IsolatedProcessResult {
    pub backend_name: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: f64,
    pub staging_violations: Vec<String>,
}

pub trait SandboxBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn is_available(&self) -> bool;
    fn run(&self, spec: &SandboxedProcessSpec) -> Result<IsolatedProcessResult, SecurityError>;
}

pub fn create_sandbox_backend(
    mode: SandboxMode,
    wsl_distro: &str,
) -> Result<Box<dyn SandboxBackend>, SecurityError> {
    match mode {
        SandboxMode::LinuxBwrap => {
            let b = linux_bwrap::LinuxBwrapCgroupBackend;
            if !b.is_available() {
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "Requested Linux Bubblewrap sandbox is unavailable on this host."
                        .to_string(),
                    detail: "mode=linux_bwrap".to_string(),
                });
            }
            Ok(Box::new(b))
        }
        SandboxMode::WindowsAppcontainer => {
            let b = windows_appcontainer::WindowsAppContainerJobBackend;
            if !b.is_available() {
                return Err(SecurityError::SandboxUnavailable {
                    user_message:
                        "Requested Windows AppContainer sandbox is unavailable on this host."
                            .to_string(),
                    detail: "mode=windows_appcontainer".to_string(),
                });
            }
            Ok(Box::new(b))
        }
        SandboxMode::WslLinuxBwrap => {
            let b = wsl_bridge::WslLinuxBwrapBackend::new(wsl_distro);
            if !b.is_available() {
                return Err(SecurityError::SandboxUnavailable {
                    user_message:
                        "Requested WSL2 Linux Bubblewrap sandbox is unavailable on this host."
                            .to_string(),
                    detail: format!("mode=wsl_linux_bwrap distro={wsl_distro}"),
                });
            }
            Ok(Box::new(b))
        }
        SandboxMode::Auto => {
            let candidates: Vec<Box<dyn SandboxBackend>> = vec![
                Box::new(linux_bwrap::LinuxBwrapCgroupBackend),
                Box::new(windows_appcontainer::WindowsAppContainerJobBackend),
                Box::new(wsl_bridge::WslLinuxBwrapBackend::new(wsl_distro)),
            ];
            for c in candidates {
                if c.is_available() {
                    return Ok(c);
                }
            }
            Err(SecurityError::SandboxUnavailable {
                user_message:
                    "No supported OS sandbox backend is available; refusing unsandboxed execution."
                        .to_string(),
                detail: "mode=auto".to_string(),
            })
        }
    }
}

#[must_use]
pub fn list_backend_availability(wsl_distro: &str) -> BTreeMap<&'static str, bool> {
    let mut map = BTreeMap::new();
    map.insert(
        "linux_bwrap",
        linux_bwrap::LinuxBwrapCgroupBackend.is_available(),
    );
    map.insert(
        "windows_appcontainer",
        windows_appcontainer::WindowsAppContainerJobBackend.is_available(),
    );
    map.insert(
        "wsl_linux_bwrap",
        wsl_bridge::WslLinuxBwrapBackend::new(wsl_distro).is_available(),
    );
    map
}
