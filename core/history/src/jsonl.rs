//! Durable append-only JSONL I/O and crash/disk-full tail recovery.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use lecture_studio_security::staging::atomic_promote;
use serde::de::DeserializeOwned;
use serde::Serialize;
use uuid::Uuid;

use crate::errors::HistoryError;
use crate::models::TailRecoveryReport;

/// Append one single-line JSON record and flush/sync to disk.
pub fn append_jsonl_record<T: Serialize>(path: &Path, record: &T) -> Result<(), HistoryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| HistoryError::Io {
            code: "CREATE_DIR_FAILED",
            message: format!("{}: {e}", parent.display()),
        })?;
    }
    let line = serde_json::to_string(record).map_err(|e| HistoryError::JsonParse(e.to_string()))?;
    let mut fh = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| HistoryError::Io {
            code: "JSONL_OPEN_FAILED",
            message: format!("{}: {e}", path.display()),
        })?;
    writeln!(fh, "{line}")
        .and_then(|()| fh.flush())
        .and_then(|()| fh.sync_all())
        .map_err(|e| HistoryError::Io {
            code: "JSONL_WRITE_FAILED",
            message: format!("{}: {e}", path.display()),
        })?;
    Ok(())
}

/// Strictly parse all records in a JSONL file; rejects malformed lines rather than ignoring them.
pub fn read_jsonl_strict<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>, HistoryError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read(path).map_err(|e| HistoryError::Io {
        code: "JSONL_READ_FAILED",
        message: format!("{}: {e}", path.display()),
    })?;
    let text = std::str::from_utf8(&raw)
        .map_err(|e| HistoryError::JsonParse(format!("{}: invalid UTF-8: {e}", path.display())))?;

    let mut out = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rec: T = serde_json::from_str(trimmed)
            .map_err(|e| HistoryError::JsonParse(format!("{}:{}: {e}", path.display(), idx + 1)))?;
        out.push(rec);
    }
    Ok(out)
}

/// Recover a JSONL file whose trailing bytes were truncated/corrupted by crash or disk exhaustion.
pub fn recover_jsonl_tail<T: DeserializeOwned>(
    path: &Path,
) -> Result<TailRecoveryReport, HistoryError> {
    if !path.exists() {
        return Ok(TailRecoveryReport {
            file_path: path.display().to_string(),
            valid_records: 0,
            dropped_tail_lines: 0,
            sidecar_path: None,
        });
    }
    let raw = fs::read(path).map_err(|e| HistoryError::Io {
        code: "JSONL_READ_FAILED",
        message: format!("{}: {e}", path.display()),
    })?;
    if raw.is_empty() {
        return Ok(TailRecoveryReport {
            file_path: path.display().to_string(),
            valid_records: 0,
            dropped_tail_lines: 0,
            sidecar_path: None,
        });
    }

    let mut valid_lines: Vec<String> = Vec::new();
    let mut dropped_tail_chunks: Vec<String> = Vec::new();
    let mut split_failed = false;

    for chunk in raw.split(|&b| b == b'\n') {
        if split_failed {
            if !chunk.is_empty() {
                dropped_tail_chunks.push(String::from_utf8_lossy(chunk).into_owned());
            }
            continue;
        }
        if chunk.is_empty() || chunk.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        match std::str::from_utf8(chunk) {
            Ok(line) if serde_json::from_str::<T>(line.trim()).is_ok() => {
                valid_lines.push(line.trim().to_string());
            }
            _ => {
                split_failed = true;
                dropped_tail_chunks.push(String::from_utf8_lossy(chunk).into_owned());
            }
        }
    }

    if !split_failed {
        return Ok(TailRecoveryReport {
            file_path: path.display().to_string(),
            valid_records: valid_lines.len(),
            dropped_tail_lines: 0,
            sidecar_path: None,
        });
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("history.jsonl");
    let sidecar = path.with_file_name(format!(
        "{file_name}.corrupt_tail.{}.txt",
        Uuid::new_v4().simple()
    ));
    atomic_promote(dropped_tail_chunks.join("\n").as_bytes(), &sidecar)?;

    let mut clean_content = valid_lines.join("\n");
    if !clean_content.is_empty() {
        clean_content.push('\n');
    }
    atomic_promote(clean_content.as_bytes(), path)?;

    Ok(TailRecoveryReport {
        file_path: path.display().to_string(),
        valid_records: valid_lines.len(),
        dropped_tail_lines: dropped_tail_chunks.len(),
        sidecar_path: Some(sidecar.display().to_string()),
    })
}
