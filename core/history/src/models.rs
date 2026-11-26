//! Canonical history, decision, snapshot, and consent domain records (SPEC §6.1).

use serde::{Deserialize, Serialize};

pub const CURRENT_HISTORY_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginType {
    Editor,
    ExternalDiff,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub schema_version: String,
    pub event_id: String,
    pub timestamp_utc: String,
    pub actor: String,
    pub target_path: String,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
    pub base_revision: u64,
    pub new_revision: u64,
    pub origin_type: OriginType,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Accepted,
    Rejected,
    Edited,
    Deferred,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    pub schema_version: String,
    pub decision_id: String,
    pub timestamp_utc: String,
    pub actor: String,
    pub proposal_id: String,
    pub outcome: DecisionOutcome,
    /// Explicit rationale stated directly by the teacher (never fabricated).
    pub explicit_reason: Option<String>,
    /// Strictly separated inferred rationale, if any.
    pub inferred_reason: Option<String>,
    pub generation_context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Complete,
    PreRestoreBackup,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotFileEntry {
    pub rel_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotManifest {
    pub schema_version: String,
    pub snapshot_id: String,
    pub project_id: String,
    pub revision: u64,
    pub files: Vec<SnapshotFileEntry>,
    pub restore_refs: Vec<String>,
    pub created_at_utc: String,
    pub creation_status: SnapshotStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreReport {
    pub target_snapshot_id: String,
    pub pre_restore_backup_id: String,
    pub restored_files: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentPurpose {
    HistorySave,
    LearningTrain,
    ExternalExchange,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRecord {
    pub schema_version: String,
    pub consent_id: String,
    pub subject_scope: String,
    pub purpose: ConsentPurpose,
    pub grantor: String,
    pub granted_at_utc: String,
    pub policy_version: String,
    pub revoked_at_utc: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRecoveryReport {
    pub file_path: String,
    pub valid_records: usize,
    pub dropped_tail_lines: usize,
    pub sidecar_path: Option<String>,
}
