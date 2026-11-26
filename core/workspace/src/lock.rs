//! Crash-safe OS-level exclusive lock guards (automatically released on process crash/termination).

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use lecture_studio_security::staging::to_long_path;

use crate::errors::WorkspaceError;

#[derive(Debug)]
pub struct ProjectLockGuard {
    file: File,
    lock_path: PathBuf,
}

impl ProjectLockGuard {
    /// Acquire a non-blocking exclusive OS kernel lock on `<project_dir>/.project.lock`.
    pub fn acquire(project_dir: &Path) -> Result<Self, WorkspaceError> {
        Self::acquire_at(project_dir.join(".project.lock"))
    }

    /// Acquire a non-blocking exclusive OS kernel lock at `lock_path`.
    pub fn acquire_at(lock_path: PathBuf) -> Result<Self, WorkspaceError> {
        let ext_lock = to_long_path(&lock_path);
        if let Some(parent) = ext_lock.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                WorkspaceError::new("LOCK_ERROR", format!("{}: {e}", parent.display()))
            })?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&ext_lock)
            .map_err(|e| {
                WorkspaceError::new("LOCK_ERROR", format!("{}: {e}", lock_path.display()))
            })?;

        acquire_os_lock(&file, &lock_path)?;

        let _ = file.set_len(0);
        let _ = file.seek(SeekFrom::Start(0));
        let _ = writeln!(file, "pid={}", std::process::id());
        let _ = file.flush();

        Ok(Self { file, lock_path })
    }

    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

impl Drop for ProjectLockGuard {
    fn drop(&mut self) {
        release_os_lock(&self.file);
    }
}

#[cfg(windows)]
fn acquire_os_lock(file: &File, lock_path: &Path) -> Result<(), WorkspaceError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{GetLastError, ERROR_LOCK_VIOLATION, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    // SAFETY: zero-initialized OVERLAPPED for locking byte 0 at offset 0.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: valid file handle owned by `file` and initialized `overlapped`.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if ok == 0 {
        // SAFETY: reading last Win32 error immediately after LockFileEx failure.
        let err = unsafe { GetLastError() };
        if err == ERROR_LOCK_VIOLATION {
            return Err(WorkspaceError::new(
                "LOCK_CONTENTION",
                format!("OS lock is currently held: {}", lock_path.display()),
            ));
        }
        return Err(WorkspaceError::new(
            "LOCK_ERROR",
            format!("{}: WinError={err}", lock_path.display()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn release_os_lock(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;

    // SAFETY: zero-initialized OVERLAPPED matching acquisition byte 0 at offset 0.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    // SAFETY: valid file handle owned by `file`.
    unsafe {
        UnlockFileEx(file.as_raw_handle() as HANDLE, 0, 1, 0, &mut overlapped);
    }
}

#[cfg(unix)]
fn acquire_os_lock(file: &File, lock_path: &Path) -> Result<(), WorkspaceError> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: valid fd owned by `file`.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::WouldBlock
            || matches!(err.raw_os_error(), Some(libc::EWOULDBLOCK | libc::EAGAIN))
        {
            return Err(WorkspaceError::new(
                "LOCK_CONTENTION",
                format!("OS lock is currently held: {}", lock_path.display()),
            ));
        }
        return Err(WorkspaceError::new(
            "LOCK_ERROR",
            format!("{}: {err}", lock_path.display()),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn release_os_lock(file: &File) {
    use std::os::unix::io::AsRawFd;
    // SAFETY: valid fd owned by `file`.
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}
