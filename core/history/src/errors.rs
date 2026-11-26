//! Structured errors for history persistence, snapshots, and consent logs.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("[HISTORY_IO / {code}] {message}")]
    Io { code: &'static str, message: String },

    #[error("[JSONL_CORRUPT] {0}")]
    JsonParse(String),

    #[error("[SNAPSHOT_NOT_FOUND] {0}")]
    SnapshotNotFound(String),

    #[error("[SNAPSHOT_CORRUPTED] {0}")]
    SnapshotCorrupted(String),

    #[error("[SCHEMA_VERSION_INCOMPATIBLE] expected={expected} found={found}")]
    SchemaVersionIncompatible { expected: String, found: String },

    #[error("[CONSENT_NOT_FOUND] {0}")]
    ConsentNotFound(String),

    #[error("[INVALID_HISTORY_PATH] {0}")]
    InvalidPath(String),

    #[error(transparent)]
    Security(#[from] lecture_studio_security::SecurityError),
}
