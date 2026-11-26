//! Typed domain models for Lecture-Studio Phase 1 Security Foundation.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DataClassification {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Restricted = 3,
}

impl DataClassification {
    /// Derived artifacts always inherit the strictest source classification.
    #[must_use]
    pub fn inherit_from(levels: &[Self]) -> Self {
        levels.iter().copied().max().unwrap_or(Self::Restricted)
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "Public",
            Self::Internal => "Internal",
            Self::Confidential => "Confidential",
            Self::Restricted => "Restricted",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    GuiUser,
    CliUser,
    ExternalAgent,
    WorkerDummy,
    WorkerCompiler,
    WorkerConverter,
    WorkerAi,
    WorkerTrainer,
    WorkerCodeTest,
}

impl Actor {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GuiUser => "gui_user",
            Self::CliUser => "cli_user",
            Self::ExternalAgent => "external_agent",
            Self::WorkerDummy => "worker_dummy",
            Self::WorkerCompiler => "worker_compiler",
            Self::WorkerConverter => "worker_converter",
            Self::WorkerAi => "worker_ai",
            Self::WorkerTrainer => "worker_trainer",
            Self::WorkerCodeTest => "worker_code_test",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    DummyEcho,
    DummyProbe,
    CompileLatex,
    CompileTypst,
    ConvertIr,
    AiPropose,
    CodeTest,
}

impl Operation {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DummyEcho => "dummy_echo",
            Self::DummyProbe => "dummy_probe",
            Self::CompileLatex => "compile_latex",
            Self::CompileTypst => "compile_typst",
            Self::ConvertIr => "convert_ir",
            Self::AiPropose => "ai_propose",
            Self::CodeTest => "code_test",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    SecurityVerification,
    EditPreview,
    ExportZip,
    AiAssist,
    Evaluation,
}

impl Purpose {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecurityVerification => "security_verification",
            Self::EditPreview => "edit_preview",
            Self::ExportZip => "export_zip",
            Self::AiAssist => "ai_assist",
            Self::Evaluation => "evaluation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Inspecting,
    Proposed,
    Committed,
    Failed,
    Cancelled,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxMode {
    Auto,
    LinuxBwrap,
    WindowsAppcontainer,
    WslLinuxBwrap,
}

impl SandboxMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::LinuxBwrap => "linux_bwrap",
            Self::WindowsAppcontainer => "windows_appcontainer",
            Self::WslLinuxBwrap => "wsl_linux_bwrap",
        }
    }
}

fn default_max_stdio_bytes() -> u64 {
    256 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    pub max_memory_bytes: u64,
    pub max_processes: u32,
    pub cpu_quota_percent: u32,
    pub timeout_ms: u64,
    pub max_output_bytes: u64,
    #[serde(default = "default_max_stdio_bytes")]
    pub max_stdio_bytes: u64,
    pub allow_network: bool,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_processes: 8,
            cpu_quota_percent: 50,
            timeout_ms: 15_000,
            max_output_bytes: 1024 * 1024,
            max_stdio_bytes: default_max_stdio_bytes(),
            allow_network: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobRequest {
    pub schema_version: String,
    pub request_id: String,
    pub job_id: String,
    pub actor: Actor,
    pub claimed_actor: Actor,
    pub project_id: String,
    pub operation: Operation,
    pub purpose: Purpose,
    pub policy_version: String,
    pub input_revision: u64,
    pub input_hash: String,
    pub classification: DataClassification,
    pub allowed_inputs: Vec<String>,
    pub staging_output_ref: String,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputRef {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticItem {
    pub severity: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobMetrics {
    pub duration_ms: f64,
    pub backend: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobResponse {
    pub schema_version: String,
    pub job_id: String,
    pub status: JobStatus,
    pub output_refs: Vec<OutputRef>,
    pub diagnostics: Vec<DiagnosticItem>,
    pub source_revision: u64,
    pub engine_version: String,
    pub metrics: JobMetrics,
    pub audit_id: Option<String>,
    pub error_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    pub actor: Actor,
    pub allowed_operations: Vec<Operation>,
    pub max_classification: DataClassification,
    pub can_commit_official: bool,
    pub allow_network: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub schema_version: String,
    pub policy_version: String,
    pub default_allow_network: bool,
    pub rules: Vec<PolicyRule>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditDecision {
    Allow,
    Deny,
    Quarantine,
    FailClosed,
    Proposed,
}

impl AuditDecision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Quarantine => "quarantine",
            Self::FailClosed => "fail_closed",
            Self::Proposed => "proposed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub audit_id: String,
    pub timestamp_utc: String,
    pub actor: String,
    pub operation: String,
    pub purpose: String,
    pub project_id: String,
    pub job_id: String,
    pub policy_version: String,
    pub classification: DataClassification,
    pub input_hash: String,
    pub output_hash: Option<String>,
    pub decision: AuditDecision,
    pub reason_code: String,
    pub error_code: Option<i32>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DummyWorkerOutput {
    pub schema_version: String,
    pub job_id: String,
    pub input_revision: u64,
    pub input_hash: String,
    pub worker_pid: u64,
    pub echo_title: String,
    pub status: String,
}
