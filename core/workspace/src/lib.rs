//! Lecture-Studio Phase 2 Workspace management, indexing, and exchange gateway crate.

pub mod errors;
pub mod lock;
pub mod manager;
pub mod models;
pub mod path_guard;
pub mod sqlite_index;

pub use errors::WorkspaceError;
pub use lock::ProjectLockGuard;
pub use manager::WorkspaceManager;
pub use models::{
    CommitJournal, CommitPhase, ExchangeTask, ExchangeTaskStatus, ExternalChangeKind,
    ExternalChangeReport, ExternalFileChange, FileFingerprint, IndexRebuildStats,
    ProcessedExchangeKey, ProjectConfig, ProjectMode, RecoveryReport, RetentionPolicy,
    SourcePermissions, SourceRecord, WorkspaceConfig, CURRENT_WORKSPACE_SCHEMA_VERSION,
};
pub use path_guard::{
    ensure_no_symlink_in_path, resolve_without_symlinks, validate_relative_path,
    verify_path_within_allowed_roots,
};
pub use sqlite_index::WorkspaceSqliteIndex;
