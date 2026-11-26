//! Content-addressed project snapshots with pre-restore backup and integrity verification.

use std::collections::HashSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use lecture_studio_security::staging::{atomic_promote, to_long_path};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::HistoryError;
use crate::models::{
    RestoreReport, SnapshotFileEntry, SnapshotManifest, SnapshotStatus,
    CURRENT_HISTORY_SCHEMA_VERSION,
};

pub const CANONICAL_CONTENT_DIRS: &[&str] = &["latex", "typst", "assets", "code"];

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

fn validate_snapshot_id(id: &str) -> Result<(), HistoryError> {
    if id.is_empty()
        || id.contains("..")
        || id.contains('/')
        || id.contains('\\')
        || id.contains(':')
        || id.chars().any(char::is_control)
    {
        return Err(HistoryError::InvalidPath(format!(
            "invalid snapshot_id: {id}"
        )));
    }
    Ok(())
}

fn validate_rel_path(rel_path: &str) -> Result<PathBuf, HistoryError> {
    if rel_path.is_empty()
        || rel_path.starts_with('/')
        || rel_path.starts_with('\\')
        || rel_path.contains(':')
    {
        return Err(HistoryError::InvalidPath(rel_path.to_string()));
    }
    let mut pb = PathBuf::new();
    for seg in rel_path.split(['/', '\\']) {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(HistoryError::InvalidPath(rel_path.to_string()));
        }
        pb.push(seg);
    }
    if pb.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(HistoryError::InvalidPath(rel_path.to_string()));
    }
    Ok(pb)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn collect_project_files(
    project_dir: &Path,
) -> Result<Vec<(String, PathBuf, Vec<u8>)>, HistoryError> {
    let ext_project_dir = to_long_path(project_dir);
    let mut collected = Vec::new();
    for sub in CANONICAL_CONTENT_DIRS {
        let base = ext_project_dir.join(sub);
        let Ok(base_meta) = fs::symlink_metadata(&base) else {
            continue;
        };
        if is_reparse_or_link(&base_meta) || !base_meta.file_type().is_dir() {
            return Err(HistoryError::InvalidPath(format!(
                "canonical directory cannot be a symlink or file: {}",
                base.display()
            )));
        }
        let mut stack = vec![base];
        while let Some(dir) = stack.pop() {
            let entries = fs::read_dir(&dir).map_err(|e| HistoryError::Io {
                code: "SNAPSHOT_SCAN_FAILED",
                message: format!("{}: {e}", dir.display()),
            })?;
            for entry_res in entries {
                let entry = entry_res.map_err(|e| HistoryError::Io {
                    code: "SNAPSHOT_SCAN_FAILED",
                    message: format!("{}: {e}", dir.display()),
                })?;
                let p = entry.path();
                let meta = fs::symlink_metadata(&p).map_err(|e| HistoryError::Io {
                    code: "SNAPSHOT_SCAN_FAILED",
                    message: format!("{}: {e}", p.display()),
                })?;
                if is_reparse_or_link(&meta) {
                    return Err(HistoryError::InvalidPath(format!(
                        "disallowed symlink/reparse inside project: {}",
                        p.display()
                    )));
                }
                if meta.file_type().is_dir() {
                    stack.push(p);
                } else if meta.file_type().is_file() {
                    let rel = p
                        .strip_prefix(&ext_project_dir)
                        .map_err(|e| HistoryError::InvalidPath(e.to_string()))?
                        .to_string_lossy()
                        .replace('\\', "/");
                    let bytes = fs::read(&p).map_err(|e| HistoryError::Io {
                        code: "SNAPSHOT_READ_FAILED",
                        message: format!("{}: {e}", p.display()),
                    })?;
                    collected.push((rel, p, bytes));
                }
            }
        }
    }
    collected.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(collected)
}

pub fn create_snapshot(
    project_dir: &Path,
    snapshots_dir: &Path,
    project_id: &str,
    revision: u64,
    reason: Option<String>,
    creation_status: SnapshotStatus,
) -> Result<SnapshotManifest, HistoryError> {
    let ext_snapshots_dir = to_long_path(snapshots_dir);
    let blobs_dir = ext_snapshots_dir.join("blobs");
    fs::create_dir_all(&blobs_dir).map_err(|e| HistoryError::Io {
        code: "SNAPSHOT_DIR_FAILED",
        message: format!("{}: {e}", blobs_dir.display()),
    })?;

    let collected = collect_project_files(project_dir)?;
    let mut files = Vec::with_capacity(collected.len());
    let mut restore_refs = Vec::with_capacity(collected.len());

    for (rel_path, _abs, raw) in collected {
        let digest = sha256_hex(&raw);
        let size_bytes = raw.len() as u64;
        let blob_path = blobs_dir.join(&digest);
        let need_write = match fs::read(&blob_path) {
            Ok(existing) => sha256_hex(&existing) != digest,
            Err(_) => true,
        };
        if need_write {
            atomic_promote(&raw, &blob_path)?;
        }
        files.push(SnapshotFileEntry {
            rel_path,
            sha256: digest.clone(),
            size_bytes,
        });
        restore_refs.push(format!("blobs/{digest}"));
    }

    let snapshot_id = format!("snap-{}", Uuid::new_v4().simple());
    let manifest = SnapshotManifest {
        schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
        snapshot_id: snapshot_id.clone(),
        project_id: project_id.to_string(),
        revision,
        files,
        restore_refs,
        created_at_utc: Utc::now().to_rfc3339(),
        creation_status,
        reason,
    };

    let manifest_path = ext_snapshots_dir.join(format!("{snapshot_id}.json"));
    let serialized = serde_json::to_string_pretty(&manifest)
        .map_err(|e| HistoryError::JsonParse(e.to_string()))?;
    atomic_promote(serialized.as_bytes(), &manifest_path)?;
    Ok(manifest)
}

pub fn verify_snapshot(
    snapshots_dir: &Path,
    snapshot_id: &str,
) -> Result<SnapshotManifest, HistoryError> {
    validate_snapshot_id(snapshot_id)?;
    let ext_snapshots_dir = to_long_path(snapshots_dir);
    let manifest_path = ext_snapshots_dir.join(format!("{snapshot_id}.json"));
    if !manifest_path.exists() {
        return Err(HistoryError::SnapshotNotFound(snapshot_id.to_string()));
    }
    let raw = fs::read_to_string(&manifest_path).map_err(|e| {
        HistoryError::SnapshotCorrupted(format!("{}: {e}", manifest_path.display()))
    })?;
    let manifest: SnapshotManifest = serde_json::from_str(&raw).map_err(|e| {
        HistoryError::SnapshotCorrupted(format!("{}: {e}", manifest_path.display()))
    })?;

    if manifest.schema_version != CURRENT_HISTORY_SCHEMA_VERSION {
        return Err(HistoryError::SchemaVersionIncompatible {
            expected: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
            found: manifest.schema_version,
        });
    }

    let blobs_dir = ext_snapshots_dir.join("blobs");
    for entry in &manifest.files {
        validate_rel_path(&entry.rel_path)?;
        let blob_path = blobs_dir.join(&entry.sha256);
        let bytes = fs::read(&blob_path).map_err(|e| {
            HistoryError::SnapshotCorrupted(format!(
                "missing blob {} for {}: {e}",
                entry.sha256, entry.rel_path
            ))
        })?;
        let actual_hash = sha256_hex(&bytes);
        if actual_hash != entry.sha256 || bytes.len() as u64 != entry.size_bytes {
            return Err(HistoryError::SnapshotCorrupted(format!(
                "blob hash/size mismatch for {}: expected {} ({}), got {} ({})",
                entry.rel_path,
                entry.sha256,
                entry.size_bytes,
                actual_hash,
                bytes.len()
            )));
        }
    }
    Ok(manifest)
}

/// Restore canonical project files from `target_snapshot_id` after capturing a pre-restore backup.
pub fn restore_snapshot(
    project_dir: &Path,
    snapshots_dir: &Path,
    project_id: &str,
    current_revision: u64,
    target_snapshot_id: &str,
) -> Result<RestoreReport, HistoryError> {
    let target = verify_snapshot(snapshots_dir, target_snapshot_id)?;
    if target.project_id != project_id {
        return Err(HistoryError::SnapshotCorrupted(format!(
            "snapshot {} belongs to project {}, not {}",
            target_snapshot_id, target.project_id, project_id
        )));
    }

    let backup = create_snapshot(
        project_dir,
        snapshots_dir,
        project_id,
        current_revision,
        Some(format!("pre_restore_before_{target_snapshot_id}")),
        SnapshotStatus::PreRestoreBackup,
    )?;

    let ext_project_dir = to_long_path(project_dir);
    let ext_snapshots_dir = to_long_path(snapshots_dir);
    let target_paths: HashSet<String> = target.files.iter().map(|f| f.rel_path.clone()).collect();
    let current_files = collect_project_files(&ext_project_dir)?;
    for (rel_path, abs_path, _) in current_files {
        if !target_paths.contains(&rel_path) {
            fs::remove_file(&abs_path).map_err(|e| HistoryError::Io {
                code: "RESTORE_REMOVE_STALE_FAILED",
                message: format!("{}: {e}", abs_path.display()),
            })?;
        }
    }

    let blobs_dir = ext_snapshots_dir.join("blobs");
    for entry in &target.files {
        let rel_pb = validate_rel_path(&entry.rel_path)?;
        let blob_bytes = fs::read(blobs_dir.join(&entry.sha256))
            .map_err(|e| HistoryError::SnapshotCorrupted(format!("blob {}: {e}", entry.sha256)))?;
        let dest = ext_project_dir.join(rel_pb);
        atomic_promote(&blob_bytes, &dest)?;
    }

    Ok(RestoreReport {
        target_snapshot_id: target_snapshot_id.to_string(),
        pre_restore_backup_id: backup.snapshot_id,
        restored_files: target.files.len(),
    })
}
