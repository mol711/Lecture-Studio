//! Canonical path containment, symlink/reparse rejection, and allowed root validation.

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::errors::WorkspaceError;

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

pub fn validate_relative_path(rel: &str) -> Result<PathBuf, WorkspaceError> {
    if rel.is_empty()
        || rel.chars().any(|c| c == '\0' || c.is_control() || c == ':')
        || rel.starts_with('/')
        || rel.starts_with('\\')
    {
        return Err(WorkspaceError::new(
            "PATH_ESCAPE",
            format!("disallowed path form: {rel}"),
        ));
    }
    let mut pb = PathBuf::new();
    for seg in rel.split(['/', '\\']) {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(WorkspaceError::new(
                "PATH_ESCAPE",
                format!("disallowed traversal segment in path: {rel}"),
            ));
        }
        pb.push(seg);
    }
    if pb.as_os_str().is_empty() || pb.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(WorkspaceError::new(
            "PATH_ESCAPE",
            format!("path must consist solely of normal components: {rel}"),
        ));
    }
    Ok(pb)
}

pub fn ensure_no_symlink_in_path(path: &Path) -> Result<(), WorkspaceError> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp.as_os_str());
        if matches!(comp, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_reparse_or_link(&meta) {
                    return Err(WorkspaceError::new(
                        "SYMLINK_NOT_ALLOWED",
                        format!("disallowed symlink or reparse point: {}", cur.display()),
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => {
                return Err(WorkspaceError::new(
                    "PATH_INSPECTION_FAILED",
                    format!("{}: {e}", cur.display()),
                ))
            }
        }
    }
    Ok(())
}

/// Resolve existing ancestor + non-existing normal tail safely without following reparse points.
pub fn resolve_without_symlinks(path: &Path) -> Result<PathBuf, WorkspaceError> {
    ensure_no_symlink_in_path(path)?;
    let mut existing = path.to_path_buf();
    let mut missing_tail: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        let Some(name) = existing.file_name().map(std::ffi::OsStr::to_os_string) else {
            break;
        };
        missing_tail.push(name);
        let Some(parent) = existing.parent() else {
            break;
        };
        existing = parent.to_path_buf();
    }
    let mut resolved = fs::canonicalize(&existing).map_err(|e| {
        WorkspaceError::new(
            "PATH_RESOLUTION_FAILED",
            format!("{}: {e}", existing.display()),
        )
    })?;
    for seg in missing_tail.into_iter().rev() {
        resolved.push(seg);
    }
    Ok(resolved)
}

/// Verify `candidate` is strictly contained within at least one directory in `allowed_roots`.
pub fn verify_path_within_allowed_roots(
    candidate: &Path,
    allowed_roots: &[PathBuf],
    violation_code: &'static str,
) -> Result<PathBuf, WorkspaceError> {
    let abs_candidate = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| WorkspaceError::new("IO_ERROR", e.to_string()))?
            .join(candidate)
    };
    let resolved_candidate = resolve_without_symlinks(&abs_candidate)?;

    for root in allowed_roots {
        if !root.exists() {
            continue;
        }
        ensure_no_symlink_in_path(root)?;
        let Ok(canon_root) = fs::canonicalize(root) else {
            continue;
        };
        if resolved_candidate.starts_with(&canon_root) {
            return Ok(resolved_candidate);
        }
    }

    Err(WorkspaceError::new(
        violation_code,
        format!(
            "path is outside allowed workspace boundaries: {}",
            candidate.display()
        ),
    ))
}
