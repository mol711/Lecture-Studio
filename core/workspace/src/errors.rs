//! Structured workspace, locking, revision, exchange, and index errors.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("[{code}] {message}")]
    Domain { code: &'static str, message: String },

    #[error(transparent)]
    History(#[from] lecture_studio_history::HistoryError),

    #[error(transparent)]
    Security(#[from] lecture_studio_security::SecurityError),
}

impl WorkspaceError {
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self::Domain {
            code,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Domain { code, .. } => code,
            Self::History(_) => "HISTORY_ERROR",
            Self::Security(err) => err.code(),
        }
    }
}
