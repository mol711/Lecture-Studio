//! SecurityGateway: 6-stage fail-closed orchestrator across switchable OS sandboxes.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::audit::{AuditAppendInput, HashChainedAuditLog};
use crate::errors::SecurityError;
use crate::models::{
    Actor, AuditDecision, DiagnosticItem, JobMetrics, JobRequest, JobResponse, JobStatus,
    SandboxMode,
};
use crate::policy::PolicyEngine;
use crate::sandbox::{create_sandbox_backend, SandboxBackend, SandboxedProcessSpec};
use crate::staging::{
    atomic_promote, ensure_clean_staging_dir, is_staging_tainted, purge_oversized_staging,
    quarantine_staging, validate_relative_staging_ref, StagingInspector,
};

pub struct SecurityGateway {
    pub policy: PolicyEngine,
    pub audit_log: HashChainedAuditLog,
    pub sandbox_mode: SandboxMode,
    pub wsl_distro: String,
    pub healthy: bool,
    seen_idempotency_keys: HashSet<(String, String, u64, String)>,
    tainted_staging_dirs: HashSet<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct JobExecutionContext<'a> {
    pub trusted_channel_actor: Actor,
    pub current_revision: u64,
    pub input_dir: &'a Path,
    pub staging_dir: &'a Path,
    pub official_output_file: &'a Path,
    pub quarantine_dir: &'a Path,
    pub worker_script: &'a Path,
    pub worker_args: &'a [String],
}

impl SecurityGateway {
    #[must_use]
    pub fn new(
        policy: PolicyEngine,
        audit_log: HashChainedAuditLog,
        sandbox_mode: SandboxMode,
        wsl_distro: impl Into<String>,
        healthy: bool,
    ) -> Self {
        Self {
            policy,
            audit_log,
            sandbox_mode,
            wsl_distro: wsl_distro.into(),
            healthy,
            seen_idempotency_keys: HashSet::new(),
            tainted_staging_dirs: HashSet::new(),
        }
    }

    fn mark_staging_tainted(&mut self, staging_dir: &Path) {
        self.tainted_staging_dirs.insert(staging_dir.to_path_buf());
        if let Ok(canon) = fs::canonicalize(staging_dir) {
            self.tainted_staging_dirs.insert(canon);
        }
    }

    fn is_staging_tainted_in_gateway(&self, staging_dir: &Path) -> bool {
        if is_staging_tainted(staging_dir) || self.tainted_staging_dirs.contains(staging_dir) {
            return true;
        }
        fs::canonicalize(staging_dir).is_ok_and(|canon| self.tainted_staging_dirs.contains(&canon))
    }

    fn handle_cleanup_failure(
        &mut self,
        req: &JobRequest,
        staging_dir: &Path,
        err: &SecurityError,
        diagnostics: &mut Vec<DiagnosticItem>,
    ) -> Result<(), SecurityError> {
        self.mark_staging_tainted(staging_dir);
        diagnostics.push(DiagnosticItem {
            severity: "error".to_string(),
            code: err.code().to_string(),
            message: err.user_message().to_string(),
        });
        self.record_audit(
            req,
            AuditDecision::FailClosed,
            err.code(),
            None,
            Some(err.jsonrpc_code()),
        )?;
        Ok(())
    }

    fn record_audit(
        &self,
        req: &JobRequest,
        decision: AuditDecision,
        reason_code: &str,
        output_hash: Option<&str>,
        error_code: Option<i32>,
    ) -> Result<String, SecurityError> {
        let rec = self.audit_log.append(AuditAppendInput {
            actor: req.actor.as_str(),
            operation: req.operation.as_str(),
            purpose: req.purpose.as_str(),
            project_id: &req.project_id,
            job_id: &req.job_id,
            policy_version: &req.policy_version,
            classification: req.classification,
            input_hash: &req.input_hash,
            output_hash,
            decision,
            reason_code,
            error_code,
            extra_keys: &[],
        })?;
        Ok(rec.audit_id)
    }

    pub fn execute_dummy_job(
        &mut self,
        req: &JobRequest,
        ctx: &JobExecutionContext<'_>,
    ) -> Result<JobResponse, SecurityError> {
        let trusted_channel_actor = ctx.trusted_channel_actor;
        let current_revision = ctx.current_revision;
        let input_dir = ctx.input_dir;
        let staging_dir = ctx.staging_dir;
        let official_output_file = ctx.official_output_file;
        let quarantine_dir = ctx.quarantine_dir;
        let worker_script = ctx.worker_script;
        let worker_args = ctx.worker_args;
        let backend_label = self.sandbox_mode.as_str().to_string();

        // Stage 0: Fail-Closed when Gateway is marked unhealthy
        if !self.healthy {
            let aid = self
                .record_audit(
                    req,
                    AuditDecision::FailClosed,
                    "GATEWAY_DOWN",
                    None,
                    Some(-32002),
                )
                .ok();
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Failed,
                output_refs: Vec::new(),
                diagnostics: vec![DiagnosticItem {
                    severity: "error".to_string(),
                    code: "GATEWAY_DOWN".to_string(),
                    message: "Gateway unhealthy; execution refused (fail-closed).".to_string(),
                }],
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: 0.0,
                    backend: backend_label,
                    exit_code: None,
                },
                audit_id: aid,
                error_code: Some(-32002),
            });
        }

        // Stage 1: Idempotency check (SEC-06)
        let idem_key = (
            req.project_id.clone(),
            req.operation.as_str().to_string(),
            req.input_revision,
            req.request_id.clone(),
        );
        if self.seen_idempotency_keys.contains(&idem_key) {
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                "DUPLICATE_REQUEST",
                None,
                Some(-32602),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Failed,
                output_refs: Vec::new(),
                diagnostics: vec![DiagnosticItem {
                    severity: "error".to_string(),
                    code: "DUPLICATE_REQUEST".to_string(),
                    message: "Duplicate request_id rejected (idempotency).".to_string(),
                }],
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: 0.0,
                    backend: backend_label,
                    exit_code: None,
                },
                audit_id: Some(aid),
                error_code: Some(-32602),
            });
        }
        self.seen_idempotency_keys.insert(idem_key);

        // Stage 2: Revision freshness check (SEC-06)
        if req.input_revision != current_revision {
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                "STALE_REVISION",
                None,
                Some(-32602),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Failed,
                output_refs: Vec::new(),
                diagnostics: vec![DiagnosticItem {
                    severity: "error".to_string(),
                    code: "STALE_REVISION".to_string(),
                    message: "Input revision is stale; refusing promotion.".to_string(),
                }],
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: 0.0,
                    backend: backend_label,
                    exit_code: None,
                },
                audit_id: Some(aid),
                error_code: Some(-32602),
            });
        }

        // Stage 2.5: Validate staging_output_ref containment BEFORE spawning worker
        if let Err(exc) = validate_relative_staging_ref(&req.staging_output_ref) {
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                exc.code(),
                None,
                Some(exc.jsonrpc_code()),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Failed,
                output_refs: Vec::new(),
                diagnostics: vec![DiagnosticItem {
                    severity: "error".to_string(),
                    code: exc.code().to_string(),
                    message: exc.user_message().to_string(),
                }],
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: 0.0,
                    backend: backend_label,
                    exit_code: None,
                },
                audit_id: Some(aid),
                error_code: Some(exc.jsonrpc_code()),
            });
        }

        // Stage 2.6: Refuse reuse of tainted or non-empty staging areas BEFORE spawning worker
        if self.is_staging_tainted_in_gateway(staging_dir) {
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                "STAGING_TAINTED",
                None,
                Some(-32003),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Failed,
                output_refs: Vec::new(),
                diagnostics: vec![DiagnosticItem {
                    severity: "error".to_string(),
                    code: "STAGING_TAINTED".to_string(),
                    message:
                        "Staging directory is tainted after incomplete cleanup and cannot be reused."
                            .to_string(),
                }],
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: 0.0,
                    backend: backend_label,
                    exit_code: None,
                },
                audit_id: Some(aid),
                error_code: Some(-32003),
            });
        }
        if let Err(exc) = ensure_clean_staging_dir(staging_dir) {
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                exc.code(),
                None,
                Some(exc.jsonrpc_code()),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Failed,
                output_refs: Vec::new(),
                diagnostics: vec![DiagnosticItem {
                    severity: "error".to_string(),
                    code: exc.code().to_string(),
                    message: exc.user_message().to_string(),
                }],
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: 0.0,
                    backend: backend_label,
                    exit_code: None,
                },
                audit_id: Some(aid),
                error_code: Some(exc.jsonrpc_code()),
            });
        }

        // Stage 3: Policy authorization + Sandbox backend selection (no unsandboxed fallback)
        let rule = match self.policy.evaluate(req, trusted_channel_actor) {
            Ok(r) => r.clone(),
            Err(exc) => {
                let aid = self
                    .record_audit(
                        req,
                        AuditDecision::Deny,
                        exc.code(),
                        None,
                        Some(exc.jsonrpc_code()),
                    )
                    .ok();
                return Ok(JobResponse {
                    schema_version: "1.0.0".to_string(),
                    job_id: req.job_id.clone(),
                    status: JobStatus::Failed,
                    output_refs: Vec::new(),
                    diagnostics: vec![DiagnosticItem {
                        severity: "error".to_string(),
                        code: exc.code().to_string(),
                        message: exc.user_message().to_string(),
                    }],
                    source_revision: req.input_revision,
                    engine_version: "security-gateway-1.0.0".to_string(),
                    metrics: JobMetrics {
                        duration_ms: 0.0,
                        backend: backend_label,
                        exit_code: None,
                    },
                    audit_id: aid,
                    error_code: Some(exc.jsonrpc_code()),
                });
            }
        };

        let backend: Box<dyn SandboxBackend> =
            match create_sandbox_backend(self.sandbox_mode, &self.wsl_distro) {
                Ok(b) => b,
                Err(exc) => {
                    let aid = self
                        .record_audit(
                            req,
                            AuditDecision::FailClosed,
                            exc.code(),
                            None,
                            Some(exc.jsonrpc_code()),
                        )
                        .ok();
                    return Ok(JobResponse {
                        schema_version: "1.0.0".to_string(),
                        job_id: req.job_id.clone(),
                        status: JobStatus::Failed,
                        output_refs: Vec::new(),
                        diagnostics: vec![DiagnosticItem {
                            severity: "error".to_string(),
                            code: exc.code().to_string(),
                            message: exc.user_message().to_string(),
                        }],
                        source_revision: req.input_revision,
                        engine_version: "security-gateway-1.0.0".to_string(),
                        metrics: JobMetrics {
                            duration_ms: 0.0,
                            backend: backend_label,
                            exit_code: None,
                        },
                        audit_id: aid,
                        error_code: Some(exc.jsonrpc_code()),
                    });
                }
            };

        // Stage 4: Execute inside isolated OS sandbox
        let proc_res = match backend.run(&SandboxedProcessSpec {
            job_id: req.job_id.clone(),
            worker_script: worker_script.to_path_buf(),
            input_dir: input_dir.to_path_buf(),
            staging_dir: staging_dir.to_path_buf(),
            worker_args: worker_args.to_vec(),
            limits: req.resource_limits.clone(),
        }) {
            Ok(res) => res,
            Err(exc) => {
                let aid = self.record_audit(
                    req,
                    AuditDecision::FailClosed,
                    exc.code(),
                    None,
                    Some(exc.jsonrpc_code()),
                )?;
                return Ok(JobResponse {
                    schema_version: "1.0.0".to_string(),
                    job_id: req.job_id.clone(),
                    status: JobStatus::Failed,
                    output_refs: Vec::new(),
                    diagnostics: vec![DiagnosticItem {
                        severity: "error".to_string(),
                        code: exc.code().to_string(),
                        message: exc.user_message().to_string(),
                    }],
                    source_revision: req.input_revision,
                    engine_version: "security-gateway-1.0.0".to_string(),
                    metrics: JobMetrics {
                        duration_ms: 0.0,
                        backend: backend.name().to_string(),
                        exit_code: None,
                    },
                    audit_id: Some(aid),
                    error_code: Some(exc.jsonrpc_code()),
                });
            }
        };

        if proc_res.stdio_limit_exceeded {
            let mut diagnostics = vec![DiagnosticItem {
                severity: "error".to_string(),
                code: "STDIO_LIMIT_EXCEEDED".to_string(),
                message: proc_res.stdout,
            }];
            if let Err(cleanup_err) = purge_oversized_staging(
                staging_dir,
                quarantine_dir,
                &req.job_id,
                "STDIO_LIMIT_EXCEEDED",
            ) {
                self.handle_cleanup_failure(req, staging_dir, &cleanup_err, &mut diagnostics)?;
            }
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                "STDIO_LIMIT_EXCEEDED",
                None,
                Some(-32005),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Cancelled,
                output_refs: Vec::new(),
                diagnostics,
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: proc_res.duration_ms,
                    backend: proc_res.backend_name,
                    exit_code: Some(proc_res.exit_code),
                },
                audit_id: Some(aid),
                error_code: Some(-32005),
            });
        }

        if proc_res.disk_limit_exceeded {
            let mut diagnostics = vec![DiagnosticItem {
                severity: "error".to_string(),
                code: "DISK_LIMIT_EXCEEDED".to_string(),
                message: "Worker exceeded runtime staging disk limit and was terminated."
                    .to_string(),
            }];
            if let Err(cleanup_err) = purge_oversized_staging(
                staging_dir,
                quarantine_dir,
                &req.job_id,
                "DISK_LIMIT_EXCEEDED",
            ) {
                self.handle_cleanup_failure(req, staging_dir, &cleanup_err, &mut diagnostics)?;
            }
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                "DISK_LIMIT_EXCEEDED",
                None,
                Some(-32005),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Cancelled,
                output_refs: Vec::new(),
                diagnostics,
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: proc_res.duration_ms,
                    backend: proc_res.backend_name,
                    exit_code: Some(proc_res.exit_code),
                },
                audit_id: Some(aid),
                error_code: Some(-32005),
            });
        }

        if proc_res.timed_out {
            let mut diagnostics = vec![DiagnosticItem {
                severity: "error".to_string(),
                code: "TIMEOUT_CANCELLED".to_string(),
                message: proc_res.stdout,
            }];
            if let Err(cleanup_err) = quarantine_staging(staging_dir, quarantine_dir, &req.job_id) {
                self.handle_cleanup_failure(req, staging_dir, &cleanup_err, &mut diagnostics)?;
            }
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                "TIMEOUT_CANCELLED",
                None,
                Some(-32005),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Cancelled,
                output_refs: Vec::new(),
                diagnostics,
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: proc_res.duration_ms,
                    backend: proc_res.backend_name,
                    exit_code: Some(proc_res.exit_code),
                },
                audit_id: Some(aid),
                error_code: Some(-32005),
            });
        }

        if !proc_res.staging_violations.is_empty() {
            let mut diagnostics = vec![DiagnosticItem {
                severity: "error".to_string(),
                code: "STAGING_VIOLATION".to_string(),
                message: proc_res.staging_violations.join(";"),
            }];
            if let Err(cleanup_err) = quarantine_staging(staging_dir, quarantine_dir, &req.job_id) {
                self.handle_cleanup_failure(req, staging_dir, &cleanup_err, &mut diagnostics)?;
            }
            let aid = self.record_audit(
                req,
                AuditDecision::Quarantine,
                "STAGING_VIOLATION",
                None,
                Some(-32003),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Quarantined,
                output_refs: Vec::new(),
                diagnostics,
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: proc_res.duration_ms,
                    backend: proc_res.backend_name,
                    exit_code: Some(proc_res.exit_code),
                },
                audit_id: Some(aid),
                error_code: Some(-32003),
            });
        }

        if proc_res.exit_code != 0 {
            let msg = if proc_res.stdout.is_empty() {
                proc_res.stderr
            } else {
                proc_res.stdout
            };
            let mut diagnostics = vec![DiagnosticItem {
                severity: "error".to_string(),
                code: "WORKER_FAILED".to_string(),
                message: msg,
            }];
            if let Err(cleanup_err) = quarantine_staging(staging_dir, quarantine_dir, &req.job_id) {
                self.handle_cleanup_failure(req, staging_dir, &cleanup_err, &mut diagnostics)?;
            }
            let aid = self.record_audit(
                req,
                AuditDecision::Deny,
                "WORKER_FAILED",
                None,
                Some(-32001),
            )?;
            return Ok(JobResponse {
                schema_version: "1.0.0".to_string(),
                job_id: req.job_id.clone(),
                status: JobStatus::Failed,
                output_refs: Vec::new(),
                diagnostics,
                source_revision: req.input_revision,
                engine_version: "security-gateway-1.0.0".to_string(),
                metrics: JobMetrics {
                    duration_ms: proc_res.duration_ms,
                    backend: proc_res.backend_name,
                    exit_code: Some(proc_res.exit_code),
                },
                audit_id: Some(aid),
                error_code: Some(-32001),
            });
        }

        // Stage 5: Inspect staging after worker termination
        let inspector = StagingInspector {
            max_files: 32,
            max_total_bytes: req.resource_limits.max_output_bytes,
        };
        let (raw_bytes, out_ref) = match inspector.validate_dummy_output(
            staging_dir,
            &req.staging_output_ref,
            &req.job_id,
            req.input_revision,
            &req.input_hash,
        ) {
            Ok(v) => v,
            Err(exc) => {
                let mut diagnostics = vec![DiagnosticItem {
                    severity: "error".to_string(),
                    code: exc.code().to_string(),
                    message: exc.user_message().to_string(),
                }];
                if let Err(cleanup_err) =
                    quarantine_staging(staging_dir, quarantine_dir, &req.job_id)
                {
                    self.handle_cleanup_failure(req, staging_dir, &cleanup_err, &mut diagnostics)?;
                }
                let aid = self.record_audit(
                    req,
                    AuditDecision::Quarantine,
                    exc.code(),
                    None,
                    Some(exc.jsonrpc_code()),
                )?;
                return Ok(JobResponse {
                    schema_version: "1.0.0".to_string(),
                    job_id: req.job_id.clone(),
                    status: JobStatus::Quarantined,
                    output_refs: Vec::new(),
                    diagnostics,
                    source_revision: req.input_revision,
                    engine_version: "security-gateway-1.0.0".to_string(),
                    metrics: JobMetrics {
                        duration_ms: proc_res.duration_ms,
                        backend: proc_res.backend_name,
                        exit_code: Some(proc_res.exit_code),
                    },
                    audit_id: Some(aid),
                    error_code: Some(exc.jsonrpc_code()),
                });
            }
        };

        // Stage 6: Mandatory audit BEFORE atomic promotion (Fail-Closed SEC-03)
        let (final_status, decision) = if rule.can_commit_official {
            (JobStatus::Committed, AuditDecision::Allow)
        } else {
            (JobStatus::Proposed, AuditDecision::Proposed)
        };
        let aid = match self.record_audit(req, decision, "OK", Some(&out_ref.sha256), None) {
            Ok(id) => id,
            Err(exc) => {
                return Ok(JobResponse {
                    schema_version: "1.0.0".to_string(),
                    job_id: req.job_id.clone(),
                    status: JobStatus::Failed,
                    output_refs: Vec::new(),
                    diagnostics: vec![DiagnosticItem {
                        severity: "error".to_string(),
                        code: exc.code().to_string(),
                        message: exc.user_message().to_string(),
                    }],
                    source_revision: req.input_revision,
                    engine_version: "security-gateway-1.0.0".to_string(),
                    metrics: JobMetrics {
                        duration_ms: proc_res.duration_ms,
                        backend: proc_res.backend_name,
                        exit_code: Some(proc_res.exit_code),
                    },
                    audit_id: None,
                    error_code: Some(exc.jsonrpc_code()),
                });
            }
        };

        if rule.can_commit_official {
            atomic_promote(&raw_bytes, official_output_file)?;
        }

        Ok(JobResponse {
            schema_version: "1.0.0".to_string(),
            job_id: req.job_id.clone(),
            status: final_status,
            output_refs: vec![out_ref],
            diagnostics: vec![DiagnosticItem {
                severity: "info".to_string(),
                code: "OK".to_string(),
                message: proc_res.stdout,
            }],
            source_revision: req.input_revision,
            engine_version: "security-gateway-1.0.0".to_string(),
            metrics: JobMetrics {
                duration_ms: proc_res.duration_ms,
                backend: proc_res.backend_name,
                exit_code: Some(proc_res.exit_code),
            },
            audit_id: Some(aid),
            error_code: None,
        })
    }
}
