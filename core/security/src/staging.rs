//! Staging inspection (symlink/reparse-point rejection), quarantine, and atomic promotion.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};

use crate::errors::SecurityError;
use crate::models::{DummyWorkerOutput, OutputRef};

#[cfg(windows)]
fn is_reparse_or_link(meta: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

#[cfg(not(windows))]
fn is_reparse_or_link(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

#[derive(Debug, Clone)]
pub struct StagingInspector {
    pub max_files: usize,
    pub max_total_bytes: u64,
}

impl Default for StagingInspector {
    fn default() -> Self {
        Self {
            max_files: 32,
            max_total_bytes: 1024 * 1024,
        }
    }
}

impl StagingInspector {
    pub fn scan_directory(&self, staging_root: &Path) -> Result<Vec<PathBuf>, SecurityError> {
        let root_meta =
            fs::symlink_metadata(staging_root).map_err(|e| SecurityError::StagingInspection {
                code: "STAGING_MISSING",
                user_message: "Staging directory does not exist or cannot be inspected."
                    .to_string(),
                detail: format!("{}: {e}", staging_root.display()),
            })?;
        if is_reparse_or_link(&root_meta) || !root_meta.file_type().is_dir() {
            return Err(SecurityError::StagingInspection {
                code: "STAGING_ROOT_INVALID",
                user_message: "Staging root must be a real directory, not a link.".to_string(),
                detail: staging_root.display().to_string(),
            });
        }
        let canonical_root =
            fs::canonicalize(staging_root).map_err(|e| SecurityError::StagingInspection {
                code: "STAGING_MISSING",
                user_message: "Failed to resolve staging root.".to_string(),
                detail: e.to_string(),
            })?;

        let mut collected = Vec::new();
        let mut total_bytes = 0u64;
        self.walk_dir(
            staging_root,
            &canonical_root,
            &mut collected,
            &mut total_bytes,
        )?;
        Ok(collected)
    }

    fn walk_dir(
        &self,
        dir: &Path,
        canonical_root: &Path,
        collected: &mut Vec<PathBuf>,
        total_bytes: &mut u64,
    ) -> Result<(), SecurityError> {
        let entries = fs::read_dir(dir).map_err(|e| SecurityError::StagingInspection {
            code: "STAGING_READ_ERROR",
            user_message: "Failed reading staging directory.".to_string(),
            detail: e.to_string(),
        })?;

        for entry_res in entries {
            let entry = entry_res.map_err(|e| SecurityError::StagingInspection {
                code: "STAGING_READ_ERROR",
                user_message: "Failed enumerating staging entry.".to_string(),
                detail: e.to_string(),
            })?;
            let path = entry.path();
            let meta =
                fs::symlink_metadata(&path).map_err(|e| SecurityError::StagingInspection {
                    code: "STAGING_READ_ERROR",
                    user_message: "Failed inspecting staging entry metadata.".to_string(),
                    detail: e.to_string(),
                })?;

            if is_reparse_or_link(&meta) {
                return Err(SecurityError::StagingInspection {
                    code: "SYMLINK_OR_JUNCTION_DETECTED",
                    user_message:
                        "Disallowed symlink or reparse point found inside staging directory."
                            .to_string(),
                    detail: path.display().to_string(),
                });
            }

            let canonical_path =
                fs::canonicalize(&path).map_err(|e| SecurityError::StagingInspection {
                    code: "PATH_ESCAPE",
                    user_message: "Failed canonicalizing staging path.".to_string(),
                    detail: e.to_string(),
                })?;
            if !canonical_path.starts_with(canonical_root) {
                return Err(SecurityError::StagingInspection {
                    code: "PATH_ESCAPE",
                    user_message: "Staging output escaped allowed root.".to_string(),
                    detail: path.display().to_string(),
                });
            }

            if meta.file_type().is_dir() {
                self.walk_dir(&path, canonical_root, collected, total_bytes)?;
            } else if meta.file_type().is_file() {
                *total_bytes = total_bytes.saturating_add(meta.len());
                collected.push(path);
                if collected.len() > self.max_files {
                    return Err(SecurityError::StagingInspection {
                        code: "TOO_MANY_FILES",
                        user_message: "Staging output exceeds allowed file count.".to_string(),
                        detail: format!("count={}", collected.len()),
                    });
                }
                if *total_bytes > self.max_total_bytes {
                    return Err(SecurityError::StagingInspection {
                        code: "SIZE_LIMIT_EXCEEDED",
                        user_message: "Staging output exceeds allowed total byte limit."
                            .to_string(),
                        detail: format!("bytes={total_bytes} limit={}", self.max_total_bytes),
                    });
                }
            } else {
                return Err(SecurityError::StagingInspection {
                    code: "NON_REGULAR_FILE",
                    user_message: "Staging contains a non-regular file.".to_string(),
                    detail: path.display().to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn validate_dummy_output(
        &self,
        staging_root: &Path,
        output_file: &Path,
        expected_job_id: &str,
        expected_revision: u64,
        expected_input_hash: &str,
    ) -> Result<(Vec<u8>, OutputRef), SecurityError> {
        self.scan_directory(staging_root)?;

        let meta =
            fs::symlink_metadata(output_file).map_err(|e| SecurityError::StagingInspection {
                code: "MISSING_OUTPUT",
                user_message: "Expected output file was not produced in staging.".to_string(),
                detail: format!("{}: {e}", output_file.display()),
            })?;
        if is_reparse_or_link(&meta) || !meta.file_type().is_file() {
            return Err(SecurityError::StagingInspection {
                code: "SYMLINK_OR_JUNCTION_DETECTED",
                user_message: "Target output file is a link or non-regular file.".to_string(),
                detail: output_file.display().to_string(),
            });
        }

        let raw = fs::read(output_file).map_err(|e| SecurityError::StagingInspection {
            code: "MISSING_OUTPUT",
            user_message: "Failed reading staging output file.".to_string(),
            detail: e.to_string(),
        })?;
        let text = std::str::from_utf8(&raw).map_err(|e| SecurityError::StagingInspection {
            code: "INVALID_OUTPUT_SCHEMA",
            user_message: "Worker output is not valid UTF-8.".to_string(),
            detail: e.to_string(),
        })?;
        let parsed: DummyWorkerOutput =
            serde_json::from_str(text).map_err(|e| SecurityError::StagingInspection {
                code: "INVALID_OUTPUT_SCHEMA",
                user_message: "Worker output failed schema validation.".to_string(),
                detail: e.to_string(),
            })?;

        if parsed.schema_version != "1.0.0" || parsed.status != "ok" {
            return Err(SecurityError::StagingInspection {
                code: "INVALID_OUTPUT_SCHEMA",
                user_message: "Worker output schema_version or status invalid.".to_string(),
                detail: format!("schema={} status={}", parsed.schema_version, parsed.status),
            });
        }
        if parsed.job_id != expected_job_id {
            return Err(SecurityError::StagingInspection {
                code: "JOB_ID_MISMATCH",
                user_message: "Worker output job_id does not match request.".to_string(),
                detail: format!("expected={expected_job_id} got={}", parsed.job_id),
            });
        }
        if parsed.input_revision != expected_revision {
            return Err(SecurityError::StagingInspection {
                code: "REVISION_MISMATCH",
                user_message: "Worker output input_revision does not match request.".to_string(),
                detail: format!("expected={expected_revision} got={}", parsed.input_revision),
            });
        }
        if parsed.input_hash != expected_input_hash {
            return Err(SecurityError::StagingInspection {
                code: "INPUT_HASH_MISMATCH",
                user_message: "Worker output input_hash does not match input snapshot.".to_string(),
                detail: format!("expected={expected_input_hash} got={}", parsed.input_hash),
            });
        }

        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let digest = hex::encode(hasher.finalize());
        let file_name = output_file
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("output.json")
            .to_string();

        let size_bytes = raw.len() as u64;
        Ok((
            raw,
            OutputRef {
                path: file_name,
                sha256: digest,
                size_bytes,
            },
        ))
    }
}

pub fn quarantine_staging(
    staging_root: &Path,
    quarantine_root: &Path,
    job_id: &str,
) -> Result<PathBuf, SecurityError> {
    let q_dir = quarantine_root.join(job_id);
    fs::create_dir_all(&q_dir).map_err(|e| SecurityError::StagingInspection {
        code: "QUARANTINE_FAILED",
        user_message: "Failed to prepare quarantine directory.".to_string(),
        detail: e.to_string(),
    })?;
    if !staging_root.exists() {
        return Ok(q_dir);
    }

    let Ok(entries) = fs::read_dir(staging_root) else {
        return Ok(q_dir);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        let fname = entry.file_name().to_string_lossy().into_owned();
        if is_reparse_or_link(&meta) {
            let target = fs::read_link(&path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unreadable-reparse>".to_string());
            let meta_path = q_dir.join(format!("{fname}.link_meta.json"));
            let _ = fs::write(
                meta_path,
                json!({ "name": fname, "link_target": target }).to_string(),
            );
            if meta.file_type().is_dir() {
                let _ = fs::remove_dir(&path);
            } else {
                let _ = fs::remove_file(&path);
            }
        } else if meta.file_type().is_file() {
            let dst = q_dir.join(&fname);
            if fs::rename(&path, &dst).is_err() {
                let _ = fs::copy(&path, &dst);
                let _ = fs::remove_file(&path);
            }
        }
    }
    Ok(q_dir)
}

pub fn atomic_promote(raw_bytes: &[u8], destination: &Path) -> Result<(), SecurityError> {
    let parent = destination
        .parent()
        .ok_or_else(|| SecurityError::StagingInspection {
            code: "PROMOTE_FAILED",
            user_message: "Destination path has no parent directory.".to_string(),
            detail: destination.display().to_string(),
        })?;
    fs::create_dir_all(parent).map_err(|e| SecurityError::StagingInspection {
        code: "PROMOTE_FAILED",
        user_message: "Failed creating destination directory.".to_string(),
        detail: e.to_string(),
    })?;

    let name = destination
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output");
    let tmp_path = parent.join(format!(".{name}.{}.tmp", uuid::Uuid::new_v4()));
    {
        let mut fh = fs::File::create(&tmp_path).map_err(|e| SecurityError::StagingInspection {
            code: "PROMOTE_FAILED",
            user_message: "Failed creating temporary promotion file.".to_string(),
            detail: e.to_string(),
        })?;
        fh.write_all(raw_bytes)
            .and_then(|()| fh.sync_all())
            .map_err(|e| SecurityError::StagingInspection {
                code: "PROMOTE_FAILED",
                user_message: "Failed syncing temporary promotion file.".to_string(),
                detail: e.to_string(),
            })?;
    }

    replace_file_atomically(&tmp_path, destination).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        SecurityError::StagingInspection {
            code: "PROMOTE_FAILED",
            user_message: "Atomic file promotion failed.".to_string(),
            detail: e.to_string(),
        }
    })
}

#[cfg(windows)]
fn replace_file_atomically(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let src_w: Vec<u16> = src.as_os_str().encode_wide().chain(Some(0)).collect();
    let dst_w: Vec<u16> = dst.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both pointers are valid NUL-terminated UTF-16 strings for MoveFileExW.
    let ok = unsafe {
        MoveFileExW(
            src_w.as_ptr(),
            dst_w.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_file_atomically(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::rename(src, dst)
}
