//! Lecture-Studio Phase 2 History, Snapshot, Consent, and Recovery crate.

pub mod consent;
pub mod errors;
pub mod jsonl;
pub mod models;
pub mod snapshot;

pub use consent::ConsentStore;
pub use errors::HistoryError;
pub use jsonl::{append_jsonl_record, read_jsonl_strict, recover_jsonl_tail};
pub use models::{
    ConsentPurpose, ConsentRecord, DecisionOutcome, DecisionRecord, OperationRecord, OriginType,
    RestoreReport, SnapshotFileEntry, SnapshotManifest, SnapshotStatus, TailRecoveryReport,
    CURRENT_HISTORY_SCHEMA_VERSION,
};
pub use snapshot::{create_snapshot, restore_snapshot, verify_snapshot, CANONICAL_CONTENT_DIRS};
