//! Readable canonical consent store separating history, learning training, and external exchange.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use uuid::Uuid;

use crate::errors::HistoryError;
use crate::jsonl::{append_jsonl_record, read_jsonl_strict, recover_jsonl_tail};
use crate::models::{
    ConsentPurpose, ConsentRecord, TailRecoveryReport, CURRENT_HISTORY_SCHEMA_VERSION,
};

#[derive(Debug, Clone)]
pub struct ConsentStore {
    path: PathBuf,
}

impl ConsentStore {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn grant(
        &self,
        subject_scope: impl Into<String>,
        purpose: ConsentPurpose,
        grantor: impl Into<String>,
        policy_version: impl Into<String>,
    ) -> Result<ConsentRecord, HistoryError> {
        let rec = ConsentRecord {
            schema_version: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
            consent_id: format!("consent-{}", Uuid::new_v4().simple()),
            subject_scope: subject_scope.into(),
            purpose,
            grantor: grantor.into(),
            granted_at_utc: Utc::now().to_rfc3339(),
            policy_version: policy_version.into(),
            revoked_at_utc: None,
        };
        append_jsonl_record(&self.path, &rec)?;
        Ok(rec)
    }

    /// Append an immutable revocation event for `consent_id`.
    pub fn revoke(&self, consent_id: &str) -> Result<ConsentRecord, HistoryError> {
        let current = self.latest_by_id()?;
        let Some(existing) = current.get(consent_id) else {
            return Err(HistoryError::ConsentNotFound(consent_id.to_string()));
        };
        let mut revoked = existing.clone();
        if revoked.revoked_at_utc.is_none() {
            revoked.revoked_at_utc = Some(Utc::now().to_rfc3339());
        }
        append_jsonl_record(&self.path, &revoked)?;
        Ok(revoked)
    }

    /// Fold append-only events into the latest consent state keyed by `consent_id`.
    pub fn list_records(&self) -> Result<Vec<ConsentRecord>, HistoryError> {
        let raw = read_jsonl_strict::<ConsentRecord>(&self.path)?;
        let mut order: Vec<String> = Vec::new();
        let mut by_id: HashMap<String, ConsentRecord> = HashMap::new();
        for rec in raw {
            if rec.schema_version != CURRENT_HISTORY_SCHEMA_VERSION {
                return Err(HistoryError::SchemaVersionIncompatible {
                    expected: CURRENT_HISTORY_SCHEMA_VERSION.to_string(),
                    found: rec.schema_version,
                });
            }
            if !by_id.contains_key(&rec.consent_id) {
                order.push(rec.consent_id.clone());
            }
            by_id.insert(rec.consent_id.clone(), rec);
        }
        Ok(order
            .into_iter()
            .filter_map(|id| by_id.remove(&id))
            .collect())
    }

    fn latest_by_id(&self) -> Result<HashMap<String, ConsentRecord>, HistoryError> {
        Ok(self
            .list_records()?
            .into_iter()
            .map(|r| (r.consent_id.clone(), r))
            .collect())
    }

    /// Check active (unrevoked) consent strictly for `(subject_scope, purpose)`.
    pub fn has_active_consent(
        &self,
        subject_scope: &str,
        purpose: ConsentPurpose,
    ) -> Result<bool, HistoryError> {
        Ok(self.list_records()?.into_iter().any(|r| {
            r.subject_scope == subject_scope && r.purpose == purpose && r.revoked_at_utc.is_none()
        }))
    }

    pub fn recover_corrupt_tail(&self) -> Result<TailRecoveryReport, HistoryError> {
        recover_jsonl_tail::<ConsentRecord>(&self.path)
    }
}
