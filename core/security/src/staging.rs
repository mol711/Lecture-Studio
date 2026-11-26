//! Staging inspection (containment, symlink/reparse-point rejection), quarantine, and atomic promotion.

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::errors::SecurityError;
use crate::models::{DummyWorkerOutput, OutputRef};

pub const STAGING_TAINT_MARKER: &str = ".lecture_studio_staging_tainted";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeFailure {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurgeReport {
    pub quarantine_dir: PathBuf,
    pub before_files: usize,
    pub before_bytes: u64,
    pub purged_files: usize,
    pub purged_bytes: u64,
    pub remaining_files: usize,
    pub remaining_bytes: u64,
    pub remaining_entries: usize,
    pub failed_entries: Vec<PurgeFailure>,
    pub tainted: bool,
}

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

/// Validate that `staging_ref` is a safe relative path strictly contained inside staging.
pub fn validate_relative_staging_ref(staging_ref: &str) -> Result<PathBuf, SecurityError> {
    if staging_ref.is_empty()
        || staging_ref
            .chars()
            .any(|c| c == '\0' || c.is_control() || c == ':')
        || staging_ref.starts_with('/')
        || staging_ref.starts_with('\\')
    {
        return Err(SecurityError::StagingInspection {
            code: "PATH_ESCAPE",
            user_message:
                "staging_output_ref must be a relative path without drive, colon, or root prefix."
                    .to_string(),
            detail: staging_ref.to_string(),
        });
    }

    let mut clean = PathBuf::new();
    for segment in staging_ref.split(['/', '\\']) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(SecurityError::StagingInspection {
                code: "PATH_ESCAPE",
                user_message: "staging_output_ref contains disallowed traversal or empty segments."
                    .to_string(),
                detail: staging_ref.to_string(),
            });
        }
        clean.push(segment);
    }

    if clean.as_os_str().is_empty()
        || clean
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(SecurityError::StagingInspection {
            code: "PATH_ESCAPE",
            user_message: "staging_output_ref must contain only normal path components."
                .to_string(),
            detail: staging_ref.to_string(),
        });
    }

    Ok(clean)
}

/// Measure current file count and total byte size inside `staging_root` without following links.
pub fn measure_staging_usage(staging_root: &Path) -> Result<(usize, u64), SecurityError> {
    let (files, bytes, _, _) = measure_staging_strict(staging_root);
    Ok((files, bytes))
}

fn sibling_taint_marker_path(staging_root: &Path) -> Option<PathBuf> {
    let parent = staging_root.parent()?;
    let name = staging_root.file_name()?.to_string_lossy();
    Some(parent.join(format!(".{name}.tainted.json")))
}

/// Return `true` when a staging directory (or its sibling sentinel) is marked tainted.
#[must_use]
pub fn is_staging_tainted(staging_root: &Path) -> bool {
    if staging_root.join(STAGING_TAINT_MARKER).exists() {
        return true;
    }
    sibling_taint_marker_path(staging_root).is_some_and(|p| p.exists())
}

/// Refuse reuse of any staging directory that is tainted, non-directory, or non-empty.
pub fn ensure_clean_staging_dir(staging_root: &Path) -> Result<(), SecurityError> {
    if is_staging_tainted(staging_root) {
        return Err(SecurityError::StagingInspection {
            code: "STAGING_TAINTED",
            user_message:
                "Staging directory is marked tainted after incomplete cleanup and cannot be reused."
                    .to_string(),
            detail: staging_root.display().to_string(),
        });
    }
    match fs::symlink_metadata(staging_root) {
        Ok(meta) => {
            if is_reparse_or_link(&meta) || !meta.file_type().is_dir() {
                return Err(SecurityError::StagingInspection {
                    code: "STAGING_ROOT_INVALID",
                    user_message: "Staging root must be a real directory, not a link or file."
                        .to_string(),
                    detail: staging_root.display().to_string(),
                });
            }
            let mut entries =
                fs::read_dir(staging_root).map_err(|e| SecurityError::StagingInspection {
                    code: "STAGING_READ_ERROR",
                    user_message: "Failed reading staging directory prior to job launch."
                        .to_string(),
                    detail: e.to_string(),
                })?;
            if let Some(first) = entries.next() {
                let first_path = first
                    .map(|ent| ent.path().display().to_string())
                    .unwrap_or_else(|e| format!("<unreadable-entry: {e}>"));
                return Err(SecurityError::StagingInspection {
                    code: "STAGING_DIRTY",
                    user_message:
                        "Staging directory is not empty; refusing reuse of unreclaimed staging area."
                            .to_string(),
                    detail: first_path,
                });
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SecurityError::StagingInspection {
            code: "STAGING_READ_ERROR",
            user_message: "Failed inspecting staging directory metadata.".to_string(),
            detail: e.to_string(),
        }),
    }
}

fn measure_staging_strict(staging_root: &Path) -> (usize, u64, usize, Vec<PurgeFailure>) {
    match fs::symlink_metadata(staging_root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return (0, 0, 0, Vec::new());
        }
        Err(e) => {
            return (
                0,
                0,
                1,
                vec![PurgeFailure {
                    path: staging_root.display().to_string(),
                    error: e.to_string(),
                }],
            );
        }
        Ok(_) => {}
    }

    let mut files = 0usize;
    let mut bytes = 0u64;
    let mut total_entries = 0usize;
    let mut errors = Vec::new();
    let mut stack = vec![staging_root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                total_entries = total_entries.saturating_add(1);
                errors.push(PurgeFailure {
                    path: dir.display().to_string(),
                    error: e.to_string(),
                });
                continue;
            }
        };
        for entry_res in entries {
            match entry_res {
                Err(e) => {
                    total_entries = total_entries.saturating_add(1);
                    errors.push(PurgeFailure {
                        path: dir.display().to_string(),
                        error: e.to_string(),
                    });
                }
                Ok(entry) => {
                    let p = entry.path();
                    if p.file_name().is_some_and(|n| n == STAGING_TAINT_MARKER) {
                        continue;
                    }
                    total_entries = total_entries.saturating_add(1);
                    match fs::symlink_metadata(&p) {
                        Err(e) => errors.push(PurgeFailure {
                            path: p.display().to_string(),
                            error: e.to_string(),
                        }),
                        Ok(meta) => {
                            if is_reparse_or_link(&meta) {
                                continue;
                            }
                            if meta.file_type().is_dir() {
                                stack.push(p);
                            } else if meta.file_type().is_file() {
                                files = files.saturating_add(1);
                                bytes = bytes.saturating_add(meta.len());
                            }
                        }
                    }
                }
            }
        }
    }
    (files, bytes, total_entries, errors)
}

fn write_taint_markers(staging_root: &Path, payload: &serde_json::Value) {
    let serialized = serde_json::to_string_pretty(payload).unwrap_or_else(|_| payload.to_string());
    if staging_root.is_dir() {
        let _ = fs::write(staging_root.join(STAGING_TAINT_MARKER), &serialized);
    }
    if let Some(sibling) = sibling_taint_marker_path(staging_root) {
        if let Some(parent) = sibling.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(sibling, &serialized);
    }
}

fn remove_dir_contents_strict(dir: &Path, failed: &mut Vec<PurgeFailure>) {
    let entries = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            failed.push(PurgeFailure {
                path: dir.display().to_string(),
                error: e.to_string(),
            });
            return;
        }
    };
    for entry_res in entries {
        let entry = match entry_res {
            Ok(ent) => ent,
            Err(e) => {
                failed.push(PurgeFailure {
                    path: dir.display().to_string(),
                    error: e.to_string(),
                });
                continue;
            }
        };
        let p = entry.path();
        if p.file_name().is_some_and(|n| n == STAGING_TAINT_MARKER) {
            continue;
        }
        let meta = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(e) => {
                failed.push(PurgeFailure {
                    path: p.display().to_string(),
                    error: e.to_string(),
                });
                continue;
            }
        };
        if is_reparse_or_link(&meta) {
            let res = if meta.file_type().is_dir() {
                fs::remove_dir(&p)
            } else {
                fs::remove_file(&p)
            };
            if let Err(e) = res {
                failed.push(PurgeFailure {
                    path: p.display().to_string(),
                    error: e.to_string(),
                });
            }
        } else if meta.file_type().is_dir() {
            remove_dir_contents_strict(&p, failed);
            if let Err(e) = fs::remove_dir(&p) {
                failed.push(PurgeFailure {
                    path: p.display().to_string(),
                    error: e.to_string(),
                });
            }
        } else if let Err(e) = fs::remove_file(&p) {
            failed.push(PurgeFailure {
                path: p.display().to_string(),
                error: e.to_string(),
            });
        }
    }
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
    pub fn scan_directory(&self, staging_root: &Path) -> Result<HashSet<PathBuf>, SecurityError> {
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

        let mut collected = HashSet::new();
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
        collected: &mut HashSet<PathBuf>,
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
                collected.insert(canonical_path);
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
        staging_output_ref: &str,
        expected_job_id: &str,
        expected_revision: u64,
        expected_input_hash: &str,
    ) -> Result<(Vec<u8>, OutputRef), SecurityError> {
        let rel = validate_relative_staging_ref(staging_output_ref)?;
        let scanned_files = self.scan_directory(staging_root)?;
        let canonical_root =
            fs::canonicalize(staging_root).map_err(|e| SecurityError::StagingInspection {
                code: "STAGING_MISSING",
                user_message: "Failed to resolve staging root.".to_string(),
                detail: e.to_string(),
            })?;

        let output_file = staging_root.join(&rel);
        let meta =
            fs::symlink_metadata(&output_file).map_err(|e| SecurityError::StagingInspection {
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
        if meta.len() > self.max_total_bytes {
            return Err(SecurityError::StagingInspection {
                code: "SIZE_LIMIT_EXCEEDED",
                user_message: "Target output file exceeds allowed byte limit.".to_string(),
                detail: format!("bytes={} limit={}", meta.len(), self.max_total_bytes),
            });
        }

        let canonical_output =
            fs::canonicalize(&output_file).map_err(|e| SecurityError::StagingInspection {
                code: "PATH_ESCAPE",
                user_message: "Failed canonicalizing target output file.".to_string(),
                detail: e.to_string(),
            })?;
        if !canonical_output.starts_with(&canonical_root)
            || !scanned_files.contains(&canonical_output)
        {
            return Err(SecurityError::StagingInspection {
                code: "PATH_ESCAPE",
                user_message: "Target output file is outside scanned staging containment."
                    .to_string(),
                detail: canonical_output.display().to_string(),
            });
        }

        let fh = fs::File::open(&output_file).map_err(|e| SecurityError::StagingInspection {
            code: "MISSING_OUTPUT",
            user_message: "Failed opening staging output file.".to_string(),
            detail: e.to_string(),
        })?;
        let mut raw = Vec::new();
        fh.take(self.max_total_bytes.saturating_add(1))
            .read_to_end(&mut raw)
            .map_err(|e| SecurityError::StagingInspection {
                code: "MISSING_OUTPUT",
                user_message: "Failed reading staging output file.".to_string(),
                detail: e.to_string(),
            })?;
        if raw.len() as u64 > self.max_total_bytes {
            return Err(SecurityError::StagingInspection {
                code: "SIZE_LIMIT_EXCEEDED",
                user_message: "Target output exceeded allowed byte limit while reading."
                    .to_string(),
                detail: format!("bytes={} limit={}", raw.len(), self.max_total_bytes),
            });
        }

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
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let size_bytes = raw.len() as u64;
        Ok((
            raw,
            OutputRef {
                path: rel_str,
                sha256: digest,
                size_bytes,
            },
        ))
    }
}

/// Purge oversized or resource-aborted staging contents immediately, verify deletion, and record failures.
pub fn purge_oversized_staging(
    staging_root: &Path,
    quarantine_root: &Path,
    job_id: &str,
    reason: &str,
) -> Result<PurgeReport, SecurityError> {
    let q_dir = quarantine_root.join(job_id);
    fs::create_dir_all(&q_dir).map_err(|e| SecurityError::StagingInspection {
        code: "QUARANTINE_FAILED",
        user_message: "Failed to prepare quarantine directory.".to_string(),
        detail: e.to_string(),
    })?;

    let (before_files, before_bytes, _, mut failed_entries) = measure_staging_strict(staging_root);
    if staging_root.exists() {
        remove_dir_contents_strict(staging_root, &mut failed_entries);
    }
    let (remaining_files, remaining_bytes, remaining_entries, post_errors) =
        measure_staging_strict(staging_root);
    failed_entries.extend(post_errors);

    let purged_files = before_files.saturating_sub(remaining_files);
    let purged_bytes = before_bytes.saturating_sub(remaining_bytes);
    let tainted = !failed_entries.is_empty()
        || remaining_files > 0
        || remaining_bytes > 0
        || remaining_entries > 0;
    let status = if tainted {
        "purge_incomplete_tainted"
    } else {
        "reclaimed"
    };

    let report_json = json!({
        "job_id": job_id,
        "reason": reason,
        "status": status,
        "before_files": before_files,
        "before_bytes": before_bytes,
        "purged_files": purged_files,
        "purged_bytes": purged_bytes,
        "remaining_files": remaining_files,
        "remaining_bytes": remaining_bytes,
        "remaining_entries": remaining_entries,
        "failed_entries": &failed_entries,
        "tainted": tainted,
    });

    fs::write(
        q_dir.join("resource_limit_quarantine.json"),
        serde_json::to_string_pretty(&report_json).unwrap_or_else(|_| report_json.to_string()),
    )
    .map_err(|e| SecurityError::StagingInspection {
        code: "QUARANTINE_FAILED",
        user_message: "Failed recording staging purge report in quarantine.".to_string(),
        detail: e.to_string(),
    })?;

    if tainted {
        write_taint_markers(staging_root, &report_json);
        return Err(SecurityError::StagingInspection {
            code: "STAGING_PURGE_FAILED",
            user_message:
                "Failed to reclaim all staging contents; remaining bytes recorded and staging marked tainted."
                    .to_string(),
            detail: format!(
                "remaining_files={remaining_files} remaining_bytes={remaining_bytes} remaining_entries={remaining_entries} failures={}",
                failed_entries.len()
            ),
        });
    }

    Ok(PurgeReport {
        quarantine_dir: q_dir,
        before_files,
        before_bytes,
        purged_files,
        purged_bytes,
        remaining_files,
        remaining_bytes,
        remaining_entries,
        failed_entries,
        tainted: false,
    })
}

fn quarantine_dir_recursive(src_dir: &Path, dst_dir: &Path, failed: &mut Vec<PurgeFailure>) {
    let entries = match fs::read_dir(src_dir) {
        Ok(rd) => rd,
        Err(e) => {
            failed.push(PurgeFailure {
                path: src_dir.display().to_string(),
                error: e.to_string(),
            });
            return;
        }
    };
    for entry_res in entries {
        let entry = match entry_res {
            Ok(ent) => ent,
            Err(e) => {
                failed.push(PurgeFailure {
                    path: src_dir.display().to_string(),
                    error: e.to_string(),
                });
                continue;
            }
        };
        let path = entry.path();
        if path.file_name().is_some_and(|n| n == STAGING_TAINT_MARKER) {
            continue;
        }
        let meta = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                failed.push(PurgeFailure {
                    path: path.display().to_string(),
                    error: e.to_string(),
                });
                continue;
            }
        };
        let fname = entry.file_name().to_string_lossy().into_owned();
        if is_reparse_or_link(&meta) {
            let target = fs::read_link(&path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unreadable-reparse>".to_string());
            let meta_path = dst_dir.join(format!("{fname}.link_meta.json"));
            if let Err(e) = fs::write(
                &meta_path,
                json!({ "name": fname, "link_target": target }).to_string(),
            ) {
                failed.push(PurgeFailure {
                    path: meta_path.display().to_string(),
                    error: e.to_string(),
                });
            }
            let rm_res = if meta.file_type().is_dir() {
                fs::remove_dir(&path)
            } else {
                fs::remove_file(&path)
            };
            if let Err(e) = rm_res {
                failed.push(PurgeFailure {
                    path: path.display().to_string(),
                    error: e.to_string(),
                });
            }
        } else if meta.file_type().is_dir() {
            let sub_dst = dst_dir.join(&fname);
            if let Err(e) = fs::create_dir_all(&sub_dst) {
                failed.push(PurgeFailure {
                    path: sub_dst.display().to_string(),
                    error: e.to_string(),
                });
                continue;
            }
            quarantine_dir_recursive(&path, &sub_dst, failed);
            if let Err(e) = fs::remove_dir(&path) {
                failed.push(PurgeFailure {
                    path: path.display().to_string(),
                    error: e.to_string(),
                });
            }
        } else if meta.file_type().is_file() {
            let dst = dst_dir.join(&fname);
            if let Err(rename_err) = fs::rename(&path, &dst) {
                match fs::copy(&path, &dst) {
                    Ok(_) => {
                        if let Err(rm_err) = fs::remove_file(&path) {
                            failed.push(PurgeFailure {
                                path: path.display().to_string(),
                                error: rm_err.to_string(),
                            });
                        }
                    }
                    Err(copy_err) => {
                        failed.push(PurgeFailure {
                            path: path.display().to_string(),
                            error: format!("rename={rename_err}; copy={copy_err}"),
                        });
                    }
                }
            }
        } else if let Err(e) = fs::remove_file(&path) {
            failed.push(PurgeFailure {
                path: path.display().to_string(),
                error: e.to_string(),
            });
        }
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

    let mut failed_entries = Vec::new();
    quarantine_dir_recursive(staging_root, &q_dir, &mut failed_entries);
    let (remaining_files, remaining_bytes, remaining_entries, post_errors) =
        measure_staging_strict(staging_root);
    failed_entries.extend(post_errors);

    if !failed_entries.is_empty()
        || remaining_files > 0
        || remaining_bytes > 0
        || remaining_entries > 0
    {
        let report_json = json!({
            "job_id": job_id,
            "status": "quarantine_incomplete_tainted",
            "remaining_files": remaining_files,
            "remaining_bytes": remaining_bytes,
            "remaining_entries": remaining_entries,
            "failed_entries": &failed_entries,
            "tainted": true,
        });
        let _ = fs::write(
            q_dir.join("quarantine_incomplete.json"),
            serde_json::to_string_pretty(&report_json).unwrap_or_else(|_| report_json.to_string()),
        );
        write_taint_markers(staging_root, &report_json);
        return Err(SecurityError::StagingInspection {
            code: "STAGING_QUARANTINE_FAILED",
            user_message:
                "Failed to quarantine all staging contents; staging directory marked tainted."
                    .to_string(),
            detail: format!(
                "remaining_files={remaining_files} remaining_bytes={remaining_bytes} remaining_entries={remaining_entries} failures={}",
                failed_entries.len()
            ),
        });
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
