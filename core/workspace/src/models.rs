//! Domain models for Workspace, Project, Source, ExternalDiff, and Exchange tasks (SPEC §6.1 / §7.1).

use std::collections::BTreeMap;

use lecture_studio_security::DataClassification;
use serde::{Deserialize, Serialize};

pub const CURRENT_WORKSPACE_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPolicy {
    pub max_snapshot_count: Option<u64>,
    pub retention_days: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfig {
    pub schema_version: String,
    pub workspace_id: String,
    pub created_at_utc: String,
    pub allowed_input_roots: Vec<String>,
    pub allowed_output_roots: Vec<String>,
    pub retention_policy: Option<RetentionPolicy>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectMode {
    LatexFirst,
    TypstFirst,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileFingerprint {
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    pub schema_version: String,
    pub project_id: String,
    pub title: String,
    pub mode: ProjectMode,
    pub canonical_entry: String,
    pub compiler_profile: String,
    pub classification: DataClassification,
    pub revision: u64,
    pub tracked_files: BTreeMap<String, FileFingerprint>,
    pub created_at_utc: String,
    pub updated_at_utc: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePermissions {
    pub usage: bool,
    pub learning: bool,
    pub export: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRecord {
    pub schema_version: String,
    pub source_id: String,
    pub origin_ref: String,
    pub stored_rel_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub original_revision: u64,
    pub page_or_line_range: String,
    pub usage_permission: bool,
    pub learning_permission: bool,
    pub export_permission: bool,
    pub classification: DataClassification,
    pub imported_at_utc: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalFileChange {
    pub rel_path: String,
    pub kind: ExternalChangeKind,
    pub before_hash: Option<String>,
    pub after_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalChangeReport {
    pub project_id: String,
    pub observed_changes: Vec<ExternalFileChange>,
    pub new_revision: u64,
    pub snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExchangeTaskStatus {
    Pending,
    Proposed,
    Accepted,
    Rejected,
    Conflicted,
    Expired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeTask {
    pub schema_version: String,
    pub task_id: String,
    pub request_id: String,
    pub project_id: String,
    pub actor: String,
    pub allowed_operation: String,
    pub target_rel_path: String,
    pub target_revision: u64,
    pub input_hash: String,
    pub status: ExchangeTaskStatus,
    pub expires_at_utc: String,
    pub output_hash: Option<String>,
    pub audit_id: Option<String>,
    pub proposal_content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessedExchangeKey {
    pub project_id: String,
    pub allowed_operation: String,
    pub target_revision: u64,
    pub request_id: String,
    pub task_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexRebuildStats {
    pub projects_indexed: usize,
    pub sources_indexed: usize,
    pub operations_indexed: usize,
    pub decisions_indexed: usize,
    pub snapshots_indexed: usize,
    pub files_indexed: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitPhase {
    Prepared,
    Audited,
    Conflicted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitJournal {
    pub schema_version: String,
    pub tx_id: String,
    pub project_id: String,
    pub target_rel_path: String,
    pub base_revision: u64,
    pub target_revision: u64,
    pub before_hash: Option<String>,
    pub after_hash: String,
    pub after_size_bytes: u64,
    pub actor: String,
    pub op_event_id: String,
    pub timestamp_utc: String,
    pub staged_temp_rel_path: String,
    pub audit_id: Option<String>,
    pub phase: CommitPhase,
    #[serde(default)]
    pub conflict_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryReport {
    pub audit_dropped_lines: usize,
    pub consent_dropped_lines: usize,
    pub sources_dropped_lines: usize,
    pub exchange_keys_dropped_lines: usize,
    pub project_history_dropped_lines: usize,
    pub rolled_back_journals: usize,
    pub rolled_forward_journals: usize,
    pub conflicted_journals: usize,
    pub conflicted_projects: Vec<String>,
    pub skipped_locked_projects: usize,
    pub removed_orphan_temps: usize,
    pub index_rebuilt: bool,
    pub index_stats: IndexRebuildStats,
}
