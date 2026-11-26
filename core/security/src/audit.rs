//! Metadata-only, hash-chained JSONL audit logger with fail-closed & tail recovery.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::errors::SecurityError;
use crate::models::{AuditDecision, AuditRecord, DataClassification};
use crate::staging::to_long_path;

const FORBIDDEN_METADATA_KEYS: &[&str] = &[
    "prompt",
    "raw_text",
    "document_body",
    "secret",
    "password",
    "token",
    "content",
];

fn canonical_record_hash(rec: &AuditRecord) -> Result<String, SecurityError> {
    let mut map: BTreeMap<&'static str, Value> = BTreeMap::new();
    map.insert("actor", Value::String(rec.actor.clone()));
    map.insert("audit_id", Value::String(rec.audit_id.clone()));
    map.insert(
        "classification",
        Value::String(rec.classification.as_str().to_string()),
    );
    map.insert("decision", Value::String(rec.decision.as_str().to_string()));
    map.insert(
        "error_code",
        rec.error_code
            .map_or(Value::Null, |c| Value::Number(c.into())),
    );
    map.insert("input_hash", Value::String(rec.input_hash.clone()));
    map.insert("job_id", Value::String(rec.job_id.clone()));
    map.insert("operation", Value::String(rec.operation.clone()));
    map.insert(
        "output_hash",
        rec.output_hash
            .as_ref()
            .map_or(Value::Null, |h| Value::String(h.clone())),
    );
    map.insert("policy_version", Value::String(rec.policy_version.clone()));
    map.insert("prev_hash", Value::String(rec.prev_hash.clone()));
    map.insert("project_id", Value::String(rec.project_id.clone()));
    map.insert("purpose", Value::String(rec.purpose.clone()));
    map.insert("reason_code", Value::String(rec.reason_code.clone()));
    map.insert("timestamp_utc", Value::String(rec.timestamp_utc.clone()));

    let bytes = serde_json::to_vec(&map).map_err(|e| SecurityError::AuditFailure {
        user_message: "Failed to serialize canonical audit payload.".to_string(),
        detail: e.to_string(),
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn verify_record_hash(rec: &AuditRecord, expected_prev: &str) -> Result<bool, SecurityError> {
    if rec.prev_hash != expected_prev {
        return Ok(false);
    }
    Ok(rec.entry_hash == canonical_record_hash(rec)?)
}

#[derive(Debug, Clone)]
pub struct AuditAppendInput<'a> {
    pub actor: &'a str,
    pub operation: &'a str,
    pub purpose: &'a str,
    pub project_id: &'a str,
    pub job_id: &'a str,
    pub policy_version: &'a str,
    pub classification: DataClassification,
    pub input_hash: &'a str,
    pub output_hash: Option<&'a str>,
    pub decision: AuditDecision,
    pub reason_code: &'a str,
    pub error_code: Option<i32>,
    pub extra_keys: &'a [&'a str],
}

#[derive(Debug, Clone)]
pub struct HashChainedAuditLog {
    log_path: PathBuf,
    writable: bool,
}

impl HashChainedAuditLog {
    #[must_use]
    pub fn new(log_path: impl Into<PathBuf>, writable: bool) -> Self {
        Self {
            log_path: log_path.into(),
            writable,
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.log_path
    }

    fn last_hash(&self) -> Result<String, SecurityError> {
        let ext = to_long_path(&self.log_path);
        if !ext.exists() {
            return Ok("0".repeat(64));
        }
        let raw = fs::read_to_string(&ext).map_err(|e| SecurityError::AuditFailure {
            user_message: "Failed to read audit log tail (fail-closed).".to_string(),
            detail: e.to_string(),
        })?;
        let Some(last_line) = raw.lines().rev().find(|ln| !ln.trim().is_empty()) else {
            return Ok("0".repeat(64));
        };
        let rec: AuditRecord =
            serde_json::from_str(last_line).map_err(|e| SecurityError::AuditFailure {
                user_message: "Audit log tail is corrupted (fail-closed).".to_string(),
                detail: e.to_string(),
            })?;
        Ok(rec.entry_hash)
    }

    pub fn append(&self, input: AuditAppendInput<'_>) -> Result<AuditRecord, SecurityError> {
        for key in input.extra_keys {
            let lower = key.to_ascii_lowercase();
            if FORBIDDEN_METADATA_KEYS.contains(&lower.as_str()) {
                return Err(SecurityError::AuditFailure {
                    user_message: "Audit log refused forbidden content field.".to_string(),
                    detail: format!("forbidden_key={key}"),
                });
            }
        }
        if !self.writable {
            return Err(SecurityError::AuditFailure {
                user_message: "Audit log is not writable; operation aborted (fail-closed)."
                    .to_string(),
                detail: self.log_path.display().to_string(),
            });
        }

        let prev_hash = self.last_hash()?;
        let mut record = AuditRecord {
            audit_id: format!("aud-{}", Uuid::new_v4()),
            timestamp_utc: Utc::now().to_rfc3339(),
            actor: input.actor.to_string(),
            operation: input.operation.to_string(),
            purpose: input.purpose.to_string(),
            project_id: input.project_id.to_string(),
            job_id: input.job_id.to_string(),
            policy_version: input.policy_version.to_string(),
            classification: input.classification,
            input_hash: input.input_hash.to_string(),
            output_hash: input.output_hash.map(ToOwned::to_owned),
            decision: input.decision,
            reason_code: input.reason_code.to_string(),
            error_code: input.error_code,
            prev_hash,
            entry_hash: String::new(),
        };
        record.entry_hash = canonical_record_hash(&record)?;

        let ext = to_long_path(&self.log_path);
        if let Some(parent) = ext.parent() {
            fs::create_dir_all(parent).map_err(|e| SecurityError::AuditFailure {
                user_message: "Failed to create audit directory (fail-closed).".to_string(),
                detail: e.to_string(),
            })?;
        }
        let mut line = serde_json::to_string(&record).map_err(|e| SecurityError::AuditFailure {
            user_message: "Failed to encode audit record.".to_string(),
            detail: e.to_string(),
        })?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&ext)
            .map_err(|e| SecurityError::AuditFailure {
                user_message: "Failed to open audit log for append (fail-closed).".to_string(),
                detail: e.to_string(),
            })?;
        file.write_all(line.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| SecurityError::AuditFailure {
                user_message: "Failed to flush audit record to disk (fail-closed).".to_string(),
                detail: e.to_string(),
            })?;

        Ok(record)
    }

    pub fn verify_chain(&self) -> Result<(bool, usize, String), SecurityError> {
        if !self.log_path.exists() {
            return Ok((true, 0, "empty".to_string()));
        }
        let raw = fs::read_to_string(&self.log_path).map_err(|e| SecurityError::AuditFailure {
            user_message: "Failed to read audit log for verification.".to_string(),
            detail: e.to_string(),
        })?;

        let mut expected_prev = "0".repeat(64);
        let mut count = 0usize;
        for (idx, line) in raw.lines().filter(|ln| !ln.trim().is_empty()).enumerate() {
            let rec: AuditRecord = match serde_json::from_str(line) {
                Ok(r) => r,
                Err(e) => {
                    return Ok((
                        false,
                        count,
                        format!("invalid record at line {}: {e}", idx + 1),
                    ));
                }
            };
            if !verify_record_hash(&rec, &expected_prev)? {
                return Ok((
                    false,
                    count,
                    format!("hash chain mismatch at line {}", idx + 1),
                ));
            }
            expected_prev = rec.entry_hash;
            count += 1;
        }
        Ok((true, count, "ok".to_string()))
    }

    /// Recover from a crash-truncated trailing JSONL line by isolating only the corrupt tail.
    pub fn recover_truncated_tail(&self) -> Result<(usize, Option<PathBuf>), SecurityError> {
        if !self.log_path.exists() {
            return Ok((0, None));
        }
        let raw = fs::read_to_string(&self.log_path).map_err(|e| SecurityError::AuditFailure {
            user_message: "Failed to read audit log for tail recovery.".to_string(),
            detail: e.to_string(),
        })?;
        let lines: Vec<&str> = raw.lines().filter(|ln| !ln.trim().is_empty()).collect();
        let mut valid_lines: Vec<String> = Vec::new();
        let mut corrupt_tail: Vec<String> = Vec::new();
        let mut expected_prev = "0".repeat(64);

        for (idx, line) in lines.iter().enumerate() {
            let parsed = serde_json::from_str::<AuditRecord>(line);
            let valid = match parsed {
                Ok(ref rec) if verify_record_hash(rec, &expected_prev)? => {
                    expected_prev = rec.entry_hash.clone();
                    true
                }
                _ => false,
            };
            if valid {
                valid_lines.push((*line).to_string());
            } else if idx + 1 < lines.len() {
                return Err(SecurityError::AuditFailure {
                    user_message:
                        "Audit log corruption detected before tail; manual inspection required."
                            .to_string(),
                    detail: format!("line={}", idx + 1),
                });
            } else {
                corrupt_tail.push((*line).to_string());
            }
        }

        if corrupt_tail.is_empty() {
            return Ok((valid_lines.len(), None));
        }

        let sidecar = PathBuf::from(format!("{}.corrupt_tail", self.log_path.display()));
        fs::write(&sidecar, format!("{}\n", corrupt_tail.join("\n"))).map_err(|e| {
            SecurityError::AuditFailure {
                user_message: "Failed to write corrupt tail quarantine sidecar.".to_string(),
                detail: e.to_string(),
            }
        })?;

        let tmp = PathBuf::from(format!("{}.tmp", self.log_path.display()));
        {
            let mut fh = fs::File::create(&tmp).map_err(|e| SecurityError::AuditFailure {
                user_message: "Failed to create temporary audit recovery file.".to_string(),
                detail: e.to_string(),
            })?;
            if !valid_lines.is_empty() {
                fh.write_all(format!("{}\n", valid_lines.join("\n")).as_bytes())
                    .map_err(|e| SecurityError::AuditFailure {
                        user_message: "Failed writing recovered audit prefix.".to_string(),
                        detail: e.to_string(),
                    })?;
            }
            fh.sync_all().map_err(|e| SecurityError::AuditFailure {
                user_message: "Failed syncing recovered audit log.".to_string(),
                detail: e.to_string(),
            })?;
        }
        fs::rename(&tmp, &self.log_path).map_err(|e| SecurityError::AuditFailure {
            user_message: "Failed replacing recovered audit log.".to_string(),
            detail: e.to_string(),
        })?;

        Ok((valid_lines.len(), Some(sidecar)))
    }
}
