//! Windows native isolation backend: AppContainer + Job Objects + SID NTFS ACLs.

use crate::errors::SecurityError;
use crate::sandbox::{IsolatedProcessResult, SandboxBackend, SandboxedProcessSpec};

pub const WINDOWS_STAGING_VOLUME_ENV: &str = "LECTURE_STUDIO_WINDOWS_STAGING_VOLUME";
pub const MAX_BOUNDED_STAGING_VOLUME_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsAppContainerJobBackend;

#[cfg(windows)]
mod imp {
    use std::ffi::c_void;
    use std::fs;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use tempfile::TempDir;
    use uuid::Uuid;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        FreeSid, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetVolumePathNameW, ReadFile,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAndIoAccountingInformation,
        JobObjectCpuRateControlInformation, JobObjectExtendedLimitInformation,
        QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
        JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
        JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
        InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute,
        WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
        LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    use super::MAX_BOUNDED_STAGING_VOLUME_BYTES;
    use crate::errors::SecurityError;
    use crate::sandbox::{IsolatedProcessResult, SandboxedProcessSpec};
    use crate::staging::measure_staging_usage;

    #[link(name = "userenv")]
    extern "system" {
        fn CreateAppContainerProfile(
            psz_app_container_name: *const u16,
            psz_display_name: *const u16,
            psz_description: *const u16,
            p_capabilities: *const SID_AND_ATTRIBUTES,
            dw_capability_count: u32,
            pp_sid_app_container_sid: *mut PSID,
        ) -> i32;

        fn DeleteAppContainerProfile(psz_app_container_name: *const u16) -> i32;
    }

    fn to_wide_nul(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn path_to_wide_nul(p: &Path) -> Vec<u16> {
        p.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: valid owned Win32 handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct AppContainerGuard {
        profile_name_w: Vec<u16>,
        sid: PSID,
    }
    impl Drop for AppContainerGuard {
        fn drop(&mut self) {
            if !self.sid.is_null() {
                // SAFETY: `self.sid` was allocated by CreateAppContainerProfile.
                unsafe { FreeSid(self.sid) };
            }
            // SAFETY: `self.profile_name_w` is NUL-terminated UTF-16 profile name.
            unsafe { DeleteAppContainerProfile(self.profile_name_w.as_ptr()) };
        }
    }

    fn grant_sid_acl(path: &Path, sid_str: &str, perm: &str) -> Result<(), SecurityError> {
        let out = Command::new("icacls")
            .arg(path)
            .arg("/grant")
            .arg(format!("*{sid_str}:{perm}"))
            .arg("/Q")
            .output()
            .map_err(|e| SecurityError::SandboxUnavailable {
                user_message: "Failed running icacls for AppContainer ACL setup.".to_string(),
                detail: e.to_string(),
            })?;
        if !out.status.success() {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "icacls failed setting AppContainer ACLs.".to_string(),
                detail: String::from_utf8_lossy(&out.stderr).into_owned(),
            });
        }
        Ok(())
    }

    fn discover_base_python_dir() -> Result<PathBuf, SecurityError> {
        let candidates: Vec<PathBuf> = [
            std::env::var_os("LECTURE_STUDIO_PYTHON").map(PathBuf::from),
            Some(PathBuf::from("python")),
            Some(PathBuf::from(r"C:\Python314\python.exe")),
        ]
        .into_iter()
        .flatten()
        .collect();

        for exe in candidates {
            if let Ok(out) = Command::new(&exe)
                .args(["-c", "import sys; print(sys.base_prefix)"])
                .output()
            {
                if out.status.success() {
                    let prefix = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !prefix.is_empty() {
                        let p = PathBuf::from(prefix);
                        if p.join("python.exe").exists() {
                            return Ok(p);
                        }
                    }
                }
            }
        }
        Err(SecurityError::SandboxUnavailable {
            user_message: "Could not locate host Python stdlib prefix for isolated runtime."
                .to_string(),
            detail: "discover_base_python_dir".to_string(),
        })
    }

    fn copy_tree_filtered(src: &Path, dst: &Path) -> std::io::Result<()> {
        fs::create_dir_all(dst)?;
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let name = entry.file_name();
            let name_s = name.to_string_lossy();
            if matches!(
                name_s.as_ref(),
                "site-packages" | "test" | "idlelib" | "tkinter" | "turtledemo" | "__pycache__"
            ) {
                continue;
            }
            let ty = entry.file_type()?;
            let target = dst.join(&name);
            if ty.is_dir() {
                copy_tree_filtered(&entry.path(), &target)?;
            } else if ty.is_file() {
                fs::copy(entry.path(), target)?;
            }
        }
        Ok(())
    }

    fn prepare_isolated_python(dst_dir: &Path) -> Result<PathBuf, SecurityError> {
        let base_py = discover_base_python_dir()?;
        fs::create_dir_all(dst_dir).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed creating isolated Python runtime directory.".to_string(),
            detail: e.to_string(),
        })?;

        let entries = fs::read_dir(&base_py).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed reading base Python directory.".to_string(),
            detail: e.to_string(),
        })?;
        for entry in entries.flatten() {
            let Ok(ty) = entry.file_type() else {
                continue;
            };
            if ty.is_file() {
                let name = entry.file_name();
                let lower = name.to_string_lossy().to_ascii_lowercase();
                if lower.starts_with("python") || lower.starts_with("vcruntime") {
                    let _ = fs::copy(entry.path(), dst_dir.join(name));
                }
            }
        }
        for sub in ["DLLs", "Lib"] {
            let sub_src = base_py.join(sub);
            if sub_src.exists() {
                copy_tree_filtered(&sub_src, &dst_dir.join(sub)).map_err(|e| {
                    SecurityError::SandboxUnavailable {
                        user_message: "Failed copying stdlib into isolated runtime.".to_string(),
                        detail: e.to_string(),
                    }
                })?;
            }
        }
        Ok(dst_dir.join("python.exe"))
    }

    fn quote_win_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.chars().any(|c| matches!(c, ' ' | '\t' | '"')) {
            return arg.to_string();
        }
        let mut out = String::from("\"");
        let mut backslashes = 0usize;
        for ch in arg.chars() {
            if ch == '\\' {
                backslashes += 1;
            } else if ch == '"' {
                out.push_str(&"\\".repeat(backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            } else {
                out.push_str(&"\\".repeat(backslashes));
                out.push(ch);
                backslashes = 0;
            }
        }
        out.push_str(&"\\".repeat(backslashes * 2));
        out.push('"');
        out
    }

    fn drain_pipe_bounded(
        handle_addr: usize,
        max_bytes: usize,
        overflow: Arc<AtomicBool>,
    ) -> String {
        let h = handle_addr as HANDLE;
        let mut collected = Vec::new();
        let mut buf = [0u8; 4096];
        let mut read_n = 0u32;
        loop {
            // SAFETY: `h` is a valid anonymous pipe read handle owned by this thread until join.
            let ok = unsafe {
                ReadFile(
                    h,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read_n,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read_n == 0 {
                break;
            }
            let n = read_n as usize;
            let remaining = max_bytes.saturating_sub(collected.len());
            let take = n.min(remaining);
            collected.extend_from_slice(&buf[..take]);
            if n > remaining {
                overflow.store(true, Ordering::SeqCst);
                break;
            }
        }
        String::from_utf8_lossy(&collected).trim().to_string()
    }

    fn verify_bounded_staging_volume(
        staging_dir: &Path,
        max_output_bytes: u64,
    ) -> Result<(), SecurityError> {
        let mut probe = fs::canonicalize(staging_dir).unwrap_or_else(|_| staging_dir.to_path_buf());
        while !probe.exists() {
            let Some(parent) = probe.parent() else {
                break;
            };
            probe = parent.to_path_buf();
        }
        if !probe.exists() {
            return Err(SecurityError::HardDiskQuotaUnavailable {
                user_message:
                    "Cannot resolve existing volume for Windows staging directory; refusing execution (fail-closed)."
                        .to_string(),
                detail: staging_dir.display().to_string(),
            });
        }
        let probe_canon = fs::canonicalize(&probe).unwrap_or(probe);
        let probe_raw = probe_canon.to_string_lossy();
        let probe_clean = probe_raw.strip_prefix(r"\\?\").unwrap_or(&probe_raw);
        let probe_w = to_wide_nul(probe_clean);

        let mut vol_buf = vec![0u16; 512];
        // SAFETY: `probe_w` is NUL-terminated UTF-16 path and `vol_buf` is 512 WCHARs.
        let got_vol = unsafe {
            GetVolumePathNameW(probe_w.as_ptr(), vol_buf.as_mut_ptr(), vol_buf.len() as u32)
        };
        if got_vol == 0 {
            return Err(SecurityError::HardDiskQuotaUnavailable {
                user_message:
                    "Failed querying Windows volume for staging directory; refusing execution (fail-closed)."
                        .to_string(),
                detail: format!("WinError={} path={probe_clean}", unsafe { GetLastError() }),
            });
        }
        let nul_idx = vol_buf
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(vol_buf.len());
        let vol_root = String::from_utf16_lossy(&vol_buf[..nul_idx]);

        if let Ok(sys_drive) = std::env::var("SystemDrive") {
            let sys_prefix = format!("{}\\", sys_drive.trim_end_matches('\\'));
            if vol_root.eq_ignore_ascii_case(&sys_prefix) {
                return Err(SecurityError::HardDiskQuotaUnavailable {
                    user_message:
                        "Windows AppContainer requires a dedicated capacity-bounded staging volume (e.g., pre-mounted VHDX <= 64 MiB); refusing execution on host system drive before worker launch."
                            .to_string(),
                    detail: format!("volume={vol_root}"),
                });
            }
        }

        let vol_w = to_wide_nul(&vol_root);
        let mut free_avail = 0u64;
        let mut total_bytes = 0u64;
        let mut total_free = 0u64;
        // SAFETY: valid NUL-terminated volume path and initialized output integers.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                vol_w.as_ptr(),
                &mut free_avail,
                &mut total_bytes,
                &mut total_free,
            )
        };
        if ok == 0 {
            return Err(SecurityError::HardDiskQuotaUnavailable {
                user_message:
                    "Failed querying Windows staging volume capacity; refusing execution (fail-closed)."
                        .to_string(),
                detail: format!("WinError={} volume={vol_root}", unsafe { GetLastError() }),
            });
        }

        let allowed_volume_cap =
            MAX_BOUNDED_STAGING_VOLUME_BYTES.max(max_output_bytes.saturating_mul(2));
        if total_bytes == 0 || total_bytes > allowed_volume_cap {
            return Err(SecurityError::HardDiskQuotaUnavailable {
                user_message:
                    "Windows AppContainer staging volume exceeds bounded capacity ceiling; refusing execution before worker launch."
                        .to_string(),
                detail: format!(
                    "volume={vol_root} total_bytes={total_bytes} cap={allowed_volume_cap}"
                ),
            });
        }
        if free_avail < max_output_bytes {
            return Err(SecurityError::HardDiskQuotaUnavailable {
                user_message:
                    "Windows AppContainer bounded staging volume has insufficient free space."
                        .to_string(),
                detail: format!(
                    "volume={vol_root} free_avail={free_avail} required={max_output_bytes}"
                ),
            });
        }
        Ok(())
    }

    pub fn run(spec: &SandboxedProcessSpec) -> Result<IsolatedProcessResult, SecurityError> {
        verify_bounded_staging_volume(&spec.staging_dir, spec.limits.max_output_bytes)?;

        fs::create_dir_all(&spec.staging_dir).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed creating Windows staging directory.".to_string(),
            detail: e.to_string(),
        })?;

        let temp_root =
            TempDir::with_prefix("ls_ac_").map_err(|e| SecurityError::SandboxUnavailable {
                user_message: "Failed creating temporary AppContainer workspace.".to_string(),
                detail: e.to_string(),
            })?;
        let profile_name = format!(
            "LectureStudio.Job.{}",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        let profile_name_w = to_wide_nul(&profile_name);
        let desc_w = to_wide_nul("Lecture-Studio isolated worker");

        let mut sid_ptr: PSID = std::ptr::null_mut();
        // SAFETY: valid UTF-16 strings and out-pointer for SID allocation.
        let hr = unsafe {
            CreateAppContainerProfile(
                profile_name_w.as_ptr(),
                profile_name_w.as_ptr(),
                desc_w.as_ptr(),
                std::ptr::null(),
                0,
                &mut sid_ptr,
            )
        };
        if hr != 0 || sid_ptr.is_null() {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "CreateAppContainerProfile failed (fail-closed).".to_string(),
                detail: format!("HRESULT=0x{:08x}", hr as u32),
            });
        }
        let ac_guard = AppContainerGuard {
            profile_name_w,
            sid: sid_ptr,
        };

        let mut sid_wstr: *mut u16 = std::ptr::null_mut();
        // SAFETY: `ac_guard.sid` is a valid AppContainer SID.
        if unsafe { ConvertSidToStringSidW(ac_guard.sid, &mut sid_wstr) } == 0 || sid_wstr.is_null()
        {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "ConvertSidToStringSidW failed.".to_string(),
                detail: format!("WinError={}", unsafe { GetLastError() }),
            });
        }
        let sid_str = unsafe {
            let mut len = 0usize;
            while *sid_wstr.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(sid_wstr, len));
            LocalFree(sid_wstr.cast());
            s
        };

        let runtime_dir = temp_root.path().join("py_runtime");
        let worker_dir = temp_root.path().join("worker_bin");
        fs::create_dir_all(&worker_dir).map_err(|e| SecurityError::SandboxUnavailable {
            user_message: "Failed creating isolated worker bin dir.".to_string(),
            detail: e.to_string(),
        })?;
        let worker_name = spec
            .worker_script
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("worker.py"));
        let isolated_worker = worker_dir.join(worker_name);
        fs::copy(&spec.worker_script, &isolated_worker).map_err(|e| {
            SecurityError::SandboxUnavailable {
                user_message: "Failed staging worker script.".to_string(),
                detail: e.to_string(),
            }
        })?;
        let py_exe = prepare_isolated_python(&runtime_dir)?;

        grant_sid_acl(&runtime_dir, &sid_str, "(OI)(CI)RX")?;
        grant_sid_acl(&worker_dir, &sid_str, "(OI)(CI)RX")?;
        grant_sid_acl(&spec.input_dir, &sid_str, "(OI)(CI)R")?;
        grant_sid_acl(&spec.staging_dir, &sid_str, "(OI)(CI)M")?;

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let (mut r_out, mut w_out) = (std::ptr::null_mut(), std::ptr::null_mut());
        let (mut r_err, mut w_err) = (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: creating anonymous pipes with valid pointers.
        unsafe {
            if CreatePipe(&mut r_out, &mut w_out, &sa, 0) == 0 {
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "CreatePipe(stdout) failed.".to_string(),
                    detail: format!("WinError={}", GetLastError()),
                });
            }
            windows_sys::Win32::Foundation::SetHandleInformation(r_out, HANDLE_FLAG_INHERIT, 0);
            if CreatePipe(&mut r_err, &mut w_err, &sa, 0) == 0 {
                CloseHandle(r_out);
                CloseHandle(w_out);
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "CreatePipe(stderr) failed.".to_string(),
                    detail: format!("WinError={}", GetLastError()),
                });
            }
            windows_sys::Win32::Foundation::SetHandleInformation(r_err, HANDLE_FLAG_INHERIT, 0);
        }
        let r_out_guard = HandleGuard(r_out);
        let r_err_guard = HandleGuard(r_err);
        let mut w_out_opt = Some(HandleGuard(w_out));
        let mut w_err_opt = Some(HandleGuard(w_err));

        let sec_caps = SECURITY_CAPABILITIES {
            AppContainerSid: ac_guard.sid,
            Capabilities: std::ptr::null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut handle_list = [w_out, w_err];

        let mut attr_size = 0usize;
        // SAFETY: querying required size for 2 proc-thread attributes.
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut attr_size);
        }
        let mut attr_buf = vec![0u8; attr_size];
        let attr_list_ptr = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;

        struct AttrListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for AttrListGuard {
            fn drop(&mut self) {
                // SAFETY: initialized attribute list pointer.
                unsafe { DeleteProcThreadAttributeList(self.0) };
            }
        }

        // SAFETY: `attr_buf` has `attr_size` bytes for 2 attributes.
        unsafe {
            if InitializeProcThreadAttributeList(attr_list_ptr, 2, 0, &mut attr_size) == 0 {
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "InitializeProcThreadAttributeList failed.".to_string(),
                    detail: format!("WinError={}", GetLastError()),
                });
            }
        }
        let _attr_guard = AttrListGuard(attr_list_ptr);

        // SAFETY: `sec_caps` and `handle_list` remain valid past CreateProcessW.
        unsafe {
            if UpdateProcThreadAttribute(
                attr_list_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                (&raw const sec_caps).cast::<c_void>(),
                std::mem::size_of::<SECURITY_CAPABILITIES>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "UpdateProcThreadAttribute(SECURITY_CAPABILITIES) failed."
                        .to_string(),
                    detail: format!("WinError={}", GetLastError()),
                });
            }
            if UpdateProcThreadAttribute(
                attr_list_ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handle_list.as_mut_ptr().cast::<c_void>(),
                std::mem::size_of_val(&handle_list),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) == 0
            {
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "UpdateProcThreadAttribute(HANDLE_LIST) failed.".to_string(),
                    detail: format!("WinError={}", GetLastError()),
                });
            }
        }

        // SAFETY: zeroed STARTUPINFOEXW with explicit `cb` and handles.
        let mut si_ex: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        si_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si_ex.StartupInfo.hStdOutput = w_out;
        si_ex.StartupInfo.hStdError = w_err;
        si_ex.lpAttributeList = attr_list_ptr;

        // SAFETY: creating anonymous Job Object.
        let job_handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job_handle.is_null() {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "CreateJobObjectW failed (fail-closed).".to_string(),
                detail: format!("WinError={}", unsafe { GetLastError() }),
            });
        }
        let job_guard = HandleGuard(job_handle);

        // SAFETY: zeroed limit struct populated with memory, active-process, and kill-on-close caps.
        let mut ext_lim: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        ext_lim.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        ext_lim.BasicLimitInformation.ActiveProcessLimit = spec.limits.max_processes;
        ext_lim.JobMemoryLimit = spec.limits.max_memory_bytes as usize;

        // SAFETY: setting extended limits on valid `job_handle`.
        unsafe {
            if SetInformationJobObject(
                job_handle,
                JobObjectExtendedLimitInformation,
                (&raw const ext_lim).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "SetInformationJobObject(ExtendedLimit) failed.".to_string(),
                    detail: format!("WinError={}", GetLastError()),
                });
            }
        }

        let mut cpu_lim: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = unsafe { std::mem::zeroed() };
        cpu_lim.ControlFlags =
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        cpu_lim.Anonymous.CpuRate = spec.limits.cpu_quota_percent * 100;
        // SAFETY: setting CPU hard cap on valid `job_handle`.
        unsafe {
            if SetInformationJobObject(
                job_handle,
                JobObjectCpuRateControlInformation,
                (&raw const cpu_lim).cast::<c_void>(),
                std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            ) == 0
            {
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "SetInformationJobObject(CpuRateControl) failed.".to_string(),
                    detail: format!("WinError={}", GetLastError()),
                });
            }
        }

        let input_str = spec.input_dir.to_string_lossy();
        let staging_str = spec.staging_dir.to_string_lossy();
        let mut full_args = vec![
            py_exe.to_string_lossy().into_owned(),
            "-I".to_string(),
            "-X".to_string(),
            "utf8".to_string(),
            isolated_worker.to_string_lossy().into_owned(),
        ];
        for arg in &spec.worker_args {
            full_args.push(
                arg.replace("{INPUT_DIR}", &input_str)
                    .replace("{STAGING_DIR}", &staging_str),
            );
        }
        let cmdline = full_args
            .iter()
            .map(|a| quote_win_arg(a))
            .collect::<Vec<_>>()
            .join(" ");
        let exe_w = path_to_wide_nul(&py_exe);
        let mut cmd_w = to_wide_nul(&cmdline);
        let cwd_w = path_to_wide_nul(&spec.staging_dir);
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let t0 = Instant::now();
        // SAFETY: valid NUL-terminated UTF-16 paths and initialized `STARTUPINFOEXW`.
        let created = unsafe {
            CreateProcessW(
                exe_w.as_ptr(),
                cmd_w.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                cwd_w.as_ptr(),
                (&raw const si_ex).cast(),
                &mut pi,
            )
        };
        if created == 0 {
            return Err(SecurityError::SandboxUnavailable {
                user_message: "CreateProcessW inside AppContainer failed (fail-closed)."
                    .to_string(),
                detail: format!("WinError={}", unsafe { GetLastError() }),
            });
        }
        let proc_guard = HandleGuard(pi.hProcess);
        let thread_guard = HandleGuard(pi.hThread);

        // Close parent write ends so reader threads see EOF when process tree exits.
        drop(w_out_opt.take());
        drop(w_err_opt.take());

        // SAFETY: `pi.hProcess` is suspended inside `job_handle`.
        unsafe {
            if AssignProcessToJobObject(job_handle, pi.hProcess) == 0 {
                let err = GetLastError();
                TerminateJobObject(job_handle, 1);
                return Err(SecurityError::SandboxUnavailable {
                    user_message: "AssignProcessToJobObject failed (fail-closed).".to_string(),
                    detail: format!("WinError={err}"),
                });
            }
            ResumeThread(pi.hThread);
        }

        let max_stdio = usize::try_from(spec.limits.max_stdio_bytes).unwrap_or(256 * 1024);
        let stdio_overflow = Arc::new(AtomicBool::new(false));
        let r_out_addr = r_out_guard.0 as usize;
        let r_err_addr = r_err_guard.0 as usize;
        let out_ov = Arc::clone(&stdio_overflow);
        let err_ov = Arc::clone(&stdio_overflow);
        let out_thread = thread::spawn(move || drain_pipe_bounded(r_out_addr, max_stdio, out_ov));
        let err_thread = thread::spawn(move || drain_pipe_bounded(r_err_addr, max_stdio, err_ov));

        let timeout = Duration::from_millis(spec.limits.timeout_ms);
        let io_write_cap = spec
            .limits
            .max_output_bytes
            .saturating_add(spec.limits.max_stdio_bytes)
            .saturating_add(512 * 1024);
        let mut timed_out = false;
        let mut stdio_limit_exceeded = false;
        let mut disk_limit_exceeded = false;

        loop {
            // SAFETY: polling child process handle for up to 20ms.
            let wait_res = unsafe { WaitForSingleObject(pi.hProcess, 20) };
            if wait_res == WAIT_OBJECT_0 {
                break;
            }
            if stdio_overflow.load(Ordering::SeqCst) {
                stdio_limit_exceeded = true;
                // SAFETY: terminate Job Object on stdio overflow.
                unsafe {
                    TerminateJobObject(job_handle, 0xE001);
                    WaitForSingleObject(pi.hProcess, 3000);
                }
                break;
            }
            let staging_exceeded = measure_staging_usage(&spec.staging_dir)
                .is_ok_and(|(files, bytes)| files > 32 || bytes > spec.limits.max_output_bytes);
            let mut acct: JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION =
                // SAFETY: zero-initialized Win32 accounting struct.
                unsafe { std::mem::zeroed() };
            let io_exceeded = unsafe {
                QueryInformationJobObject(
                    job_handle,
                    JobObjectBasicAndIoAccountingInformation,
                    (&raw mut acct).cast::<c_void>(),
                    std::mem::size_of::<JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                ) != 0
                    && acct.IoInfo.WriteTransferCount > io_write_cap
            };
            if staging_exceeded || io_exceeded {
                disk_limit_exceeded = true;
                // SAFETY: terminate Job Object on runtime disk/write cap violation.
                unsafe {
                    TerminateJobObject(job_handle, 0xE002);
                    WaitForSingleObject(pi.hProcess, 3000);
                }
                break;
            }
            if t0.elapsed() >= timeout {
                timed_out = true;
                // SAFETY: terminate entire Job Object tree on timeout.
                unsafe {
                    TerminateJobObject(job_handle, 0xDEAD);
                    WaitForSingleObject(pi.hProcess, 3000);
                }
                break;
            }
        }

        let mut exit_code = 0u32;
        // SAFETY: retrieving exit code of terminated/finished process.
        unsafe { GetExitCodeProcess(pi.hProcess, &mut exit_code) };

        // Close job & process handles before joining readers so no child keeps pipe handles open.
        drop(thread_guard);
        drop(proc_guard);
        drop(job_guard);

        let stdout = out_thread.join().unwrap_or_default();
        let stderr = err_thread.join().unwrap_or_default();
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

        drop(r_out_guard);
        drop(r_err_guard);
        drop(ac_guard);

        Ok(IsolatedProcessResult {
            backend_name: "windows_appcontainer".to_string(),
            exit_code: exit_code as i32,
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

impl SandboxBackend for WindowsAppContainerJobBackend {
    fn name(&self) -> &'static str {
        "windows_appcontainer"
    }

    fn is_available(&self) -> bool {
        cfg!(all(windows, target_pointer_width = "64"))
    }

    fn run(&self, spec: &SandboxedProcessSpec) -> Result<IsolatedProcessResult, SecurityError> {
        #[cfg(windows)]
        {
            imp::run(spec)
        }
        #[cfg(not(windows))]
        {
            let _ = spec;
            Err(SecurityError::SandboxUnavailable {
                user_message: "Windows AppContainer sandbox is only available on Windows."
                    .to_string(),
                detail: "not_windows".to_string(),
            })
        }
    }
}
