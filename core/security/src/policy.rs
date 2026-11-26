//! Fail-closed policy engine and actor/classification authorization.

use std::collections::HashMap;
use std::path::Path;

use crate::errors::SecurityError;
use crate::models::{Actor, DataClassification, JobRequest, Operation, PolicyConfig, PolicyRule};

#[must_use]
pub fn default_policy() -> PolicyConfig {
    PolicyConfig {
        schema_version: "1.0.0".to_string(),
        policy_version: "1.0.0".to_string(),
        default_allow_network: false,
        rules: vec![
            PolicyRule {
                actor: Actor::GuiUser,
                allowed_operations: vec![
                    Operation::DummyEcho,
                    Operation::DummyProbe,
                    Operation::CompileLatex,
                    Operation::CompileTypst,
                    Operation::ConvertIr,
                    Operation::AiPropose,
                    Operation::CodeTest,
                ],
                max_classification: DataClassification::Confidential,
                can_commit_official: true,
                allow_network: false,
            },
            PolicyRule {
                actor: Actor::CliUser,
                allowed_operations: vec![
                    Operation::DummyEcho,
                    Operation::DummyProbe,
                    Operation::CompileLatex,
                    Operation::CompileTypst,
                    Operation::ConvertIr,
                    Operation::AiPropose,
                    Operation::CodeTest,
                ],
                max_classification: DataClassification::Confidential,
                can_commit_official: true,
                allow_network: false,
            },
            PolicyRule {
                actor: Actor::ExternalAgent,
                allowed_operations: vec![Operation::DummyEcho, Operation::ConvertIr],
                max_classification: DataClassification::Internal,
                can_commit_official: false,
                allow_network: false,
            },
            PolicyRule {
                actor: Actor::WorkerDummy,
                allowed_operations: vec![Operation::DummyEcho, Operation::DummyProbe],
                max_classification: DataClassification::Internal,
                can_commit_official: false,
                allow_network: false,
            },
        ],
    }
}

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    config: PolicyConfig,
    rules_by_actor: HashMap<Actor, PolicyRule>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new(default_policy())
    }
}

impl PolicyEngine {
    #[must_use]
    pub fn new(config: PolicyConfig) -> Self {
        let rules_by_actor = config.rules.iter().map(|r| (r.actor, r.clone())).collect();
        Self {
            config,
            rules_by_actor,
        }
    }

    pub fn from_yaml_file(path: &Path) -> Result<Self, SecurityError> {
        let content = std::fs::read_to_string(path).map_err(|e| SecurityError::PolicyDenied {
            code: "POLICY_INVALID",
            user_message: "Security policy could not be read; execution blocked (fail-closed)."
                .to_string(),
            detail: e.to_string(),
        })?;
        let cfg: PolicyConfig =
            serde_yaml::from_str(&content).map_err(|e| SecurityError::PolicyDenied {
                code: "POLICY_INVALID",
                user_message:
                    "Security policy failed schema parsing; execution blocked (fail-closed)."
                        .to_string(),
                detail: e.to_string(),
            })?;
        if cfg.schema_version != "1.0.0" || cfg.default_allow_network {
            return Err(SecurityError::PolicyDenied {
                code: "POLICY_INVALID",
                user_message: "Policy violated mandatory invariants (schema_version or default_allow_network)."
                    .to_string(),
                detail: format!("schema_version={}", cfg.schema_version),
            });
        }
        if cfg.rules.iter().any(|r| r.allow_network) {
            return Err(SecurityError::PolicyDenied {
                code: "POLICY_INVALID",
                user_message: "Policy rule attempted to enable network access by default."
                    .to_string(),
                detail: "allow_network=true in rule".to_string(),
            });
        }
        Ok(Self::new(cfg))
    }

    #[must_use]
    pub fn policy_version(&self) -> &str {
        &self.config.policy_version
    }

    pub fn evaluate(
        &self,
        req: &JobRequest,
        trusted_channel_actor: Actor,
    ) -> Result<&PolicyRule, SecurityError> {
        if req.schema_version != "1.0.0" {
            return Err(SecurityError::InvalidRequest {
                user_message: "Unsupported JobRequest schema_version.".to_string(),
                detail: req.schema_version.clone(),
            });
        }
        if req.actor != trusted_channel_actor || req.claimed_actor != trusted_channel_actor {
            return Err(SecurityError::PolicyDenied {
                code: "ACTOR_SPOOF",
                user_message: "Actor identity mismatch against trusted channel credentials."
                    .to_string(),
                detail: format!(
                    "trusted={} actor={} claimed={}",
                    trusted_channel_actor.as_str(),
                    req.actor.as_str(),
                    req.claimed_actor.as_str()
                ),
            });
        }
        if req.policy_version != self.config.policy_version {
            return Err(SecurityError::PolicyDenied {
                code: "POLICY_VERSION_MISMATCH",
                user_message: "Policy version mismatch; request rejected.".to_string(),
                detail: format!(
                    "expected={} got={}",
                    self.config.policy_version, req.policy_version
                ),
            });
        }
        if req.resource_limits.allow_network {
            return Err(SecurityError::PolicyDenied {
                code: "NETWORK_DENIED",
                user_message: "Worker network access is disabled by default security policy."
                    .to_string(),
                detail: "allow_network=true".to_string(),
            });
        }

        let rule = self
            .rules_by_actor
            .get(&trusted_channel_actor)
            .ok_or_else(|| SecurityError::PolicyDenied {
                code: "ACTOR_NOT_ALLOWED",
                user_message: "Actor is not permitted by current security policy.".to_string(),
                detail: trusted_channel_actor.as_str().to_string(),
            })?;

        if !rule.allowed_operations.contains(&req.operation) {
            return Err(SecurityError::PolicyDenied {
                code: "OPERATION_DENIED",
                user_message: "Requested operation is not permitted for this actor.".to_string(),
                detail: format!(
                    "actor={} op={}",
                    trusted_channel_actor.as_str(),
                    req.operation.as_str()
                ),
            });
        }

        if req.classification > rule.max_classification {
            return Err(SecurityError::PolicyDenied {
                code: "CLASSIFICATION_DENIED",
                user_message: "Data classification exceeds actor clearance.".to_string(),
                detail: format!(
                    "actor={} class={} max={}",
                    trusted_channel_actor.as_str(),
                    req.classification.as_str(),
                    rule.max_classification.as_str()
                ),
            });
        }

        Ok(rule)
    }
}
