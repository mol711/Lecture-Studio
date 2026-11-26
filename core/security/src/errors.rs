//! Structured security errors mapped to fixed JSON-RPC 2.0 error codes.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("[IPC_PARSE_ERROR / -32700] {user_message}")]
    IpcParse {
        user_message: String,
        detail: String,
    },

    #[error("[INVALID_REQUEST / -32600] {user_message}")]
    InvalidRequest {
        user_message: String,
        detail: String,
    },

    #[error("[OPERATION_NOT_ALLOWED / -32601] {user_message}")]
    OperationNotAllowed {
        user_message: String,
        detail: String,
    },

    #[error("[INVALID_PARAMS / -32602] {user_message}")]
    InvalidParams {
        user_message: String,
        detail: String,
    },

    #[error("[{code} / -32001] {user_message}")]
    PolicyDenied {
        code: &'static str,
        user_message: String,
        detail: String,
    },

    #[error("[SANDBOX_UNAVAILABLE / -32002] {user_message}")]
    SandboxUnavailable {
        user_message: String,
        detail: String,
    },

    #[error("[HARD_DISK_QUOTA_UNAVAILABLE / -32002] {user_message}")]
    HardDiskQuotaUnavailable {
        user_message: String,
        detail: String,
    },

    #[error("[{code} / -32003] {user_message}")]
    StagingInspection {
        code: &'static str,
        user_message: String,
        detail: String,
    },

    #[error("[AUDIT_FAILURE / -32004] {user_message}")]
    AuditFailure {
        user_message: String,
        detail: String,
    },

    #[error("[CANCELLED_OR_TIMED_OUT / -32005] {user_message}")]
    CancelledOrTimedOut {
        user_message: String,
        detail: String,
    },
}

impl SecurityError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::IpcParse { .. } => "IPC_PARSE_ERROR",
            Self::InvalidRequest { .. } => "INVALID_REQUEST",
            Self::OperationNotAllowed { .. } => "OPERATION_NOT_ALLOWED",
            Self::InvalidParams { .. } => "INVALID_PARAMS",
            Self::PolicyDenied { code, .. } => code,
            Self::SandboxUnavailable { .. } => "SANDBOX_UNAVAILABLE",
            Self::HardDiskQuotaUnavailable { .. } => "HARD_DISK_QUOTA_UNAVAILABLE",
            Self::StagingInspection { code, .. } => code,
            Self::AuditFailure { .. } => "AUDIT_FAILURE",
            Self::CancelledOrTimedOut { .. } => "CANCELLED_OR_TIMED_OUT",
        }
    }

    #[must_use]
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::IpcParse { .. } => -32700,
            Self::InvalidRequest { .. } => -32600,
            Self::OperationNotAllowed { .. } => -32601,
            Self::InvalidParams { .. } => -32602,
            Self::PolicyDenied { .. } => -32001,
            Self::SandboxUnavailable { .. } | Self::HardDiskQuotaUnavailable { .. } => -32002,
            Self::StagingInspection { .. } => -32003,
            Self::AuditFailure { .. } => -32004,
            Self::CancelledOrTimedOut { .. } => -32005,
        }
    }

    #[must_use]
    pub fn user_message(&self) -> &str {
        match self {
            Self::IpcParse { user_message, .. }
            | Self::InvalidRequest { user_message, .. }
            | Self::OperationNotAllowed { user_message, .. }
            | Self::InvalidParams { user_message, .. }
            | Self::PolicyDenied { user_message, .. }
            | Self::SandboxUnavailable { user_message, .. }
            | Self::HardDiskQuotaUnavailable { user_message, .. }
            | Self::StagingInspection { user_message, .. }
            | Self::AuditFailure { user_message, .. }
            | Self::CancelledOrTimedOut { user_message, .. } => user_message,
        }
    }
}
