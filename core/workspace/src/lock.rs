//! Exclusive per-project lock file guard preventing concurrent overwriting.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::errors::WorkspaceError;

#[derive(Debug)]
pub struct ProjectLockGuard {
    lock_path: PathBuf,
}

impl ProjectLockGuard {
    pub fn acquire(project_dir: &Path) -> Result<Self, WorkspaceError> {
        let lock_path = project_dir.join(".project.lock");
        let mut fh = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    WorkspaceError::new(
                        "LOCK_CONTENTION",
                        format!("project lock is already held: {}", lock_path.display()),
                    )
                } else {
                    WorkspaceError::new("LOCK_ERROR", format!("{}: {e}", lock_path.display()))
                }
            })?;
        let _ = writeln!(fh, "pid={}", std::process::id());
        let _ = fh.flush();
        Ok(Self { lock_path })
    }
}

impl Drop for ProjectLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
    }
}
