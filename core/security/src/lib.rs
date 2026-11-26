//! Lecture-Studio Phase 1 Security Foundation core crate.

pub mod audit;
pub mod errors;
pub mod gateway;
pub mod ipc;
pub mod models;
pub mod policy;
pub mod sandbox;
pub mod staging;

pub use audit::{AuditAppendInput, HashChainedAuditLog};
pub use errors::SecurityError;
pub use gateway::{JobExecutionContext, SecurityGateway};
pub use models::{
    Actor, AuditDecision, AuditRecord, DataClassification, JobRequest, JobResponse, JobStatus,
    Operation, PolicyConfig, Purpose, ResourceLimits, SandboxMode,
};
pub use policy::PolicyEngine;
