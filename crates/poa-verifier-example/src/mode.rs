use std::{fmt, str::FromStr};

use poa_protocol::{DeploymentMode, EffectivePolicy, OsBackend};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerifierMode {
    AccessOnly,
    TransitionOnly,
    RuntimeOnly,
    FullPbea,
}

impl VerifierMode {
    pub const ALL: [Self; 4] = [
        Self::AccessOnly,
        Self::TransitionOnly,
        Self::RuntimeOnly,
        Self::FullPbea,
    ];

    pub fn policy_digest_required(self) -> bool {
        matches!(self, Self::TransitionOnly | Self::FullPbea)
    }

    pub fn transition_guards_enabled(self) -> bool {
        matches!(self, Self::TransitionOnly | Self::FullPbea)
    }

    pub fn runtime_constraints_enabled(self) -> bool {
        matches!(self, Self::RuntimeOnly | Self::FullPbea)
    }
}

impl fmt::Display for VerifierMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AccessOnly => "access-only",
            Self::TransitionOnly => "transition-only",
            Self::RuntimeOnly => "runtime-only",
            Self::FullPbea => "full-pbea",
        })
    }
}

impl FromStr for VerifierMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "access-only" => Ok(Self::AccessOnly),
            "transition-only" => Ok(Self::TransitionOnly),
            "runtime-only" => Ok(Self::RuntimeOnly),
            "full-pbea" => Ok(Self::FullPbea),
            _ => anyhow::bail!("unknown verifier mode: {value}"),
        }
    }
}

pub fn validate_mode_policy(mode: VerifierMode, policy: &EffectivePolicy) -> anyhow::Result<()> {
    if matches!(mode, VerifierMode::RuntimeOnly | VerifierMode::FullPbea) {
        let label = if mode == VerifierMode::RuntimeOnly {
            "Runtime-only"
        } else {
            "Full-PBEA"
        };
        anyhow::ensure!(
            policy.mode == DeploymentMode::Production,
            "{label} requires production policy mode"
        );
        anyhow::ensure!(
            policy.process_constraints.os_backend == OsBackend::Openbsd,
            "{label} requires os_backend=openbsd"
        );
        anyhow::ensure!(
            policy.process_constraints.lock_after_initialization,
            "{label} requires a locked unveil table"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use poa_protocol::{
        DataConstraints, FailurePolicy, NetworkPolicy, OperationPolicy, ProcessConstraints,
    };

    fn policy() -> EffectivePolicy {
        EffectivePolicy {
            schema: "test".into(),
            protocol_id: "test".into(),
            version: "1".into(),
            extends: None,
            mode: DeploymentMode::Production,
            operations: vec![OperationPolicy {
                name: "verify_transition".into(),
                allowed_actors: vec!["actor".into()],
                required_context: vec![],
            }],
            process_constraints: ProcessConstraints {
                os_backend: OsBackend::Openbsd,
                pledge_promises: vec!["stdio".into()],
                unveil_paths: vec![],
                lock_after_initialization: true,
            },
            data_constraints: DataConstraints {
                input_schema: "test".into(),
                maximum_message_bytes: 1,
                canonical_encoding: "JCS".into(),
                maximum_nesting_depth: 1,
            },
            failure_policy: FailurePolicy {
                invalid_request: "reject".into(),
                policy_violation: "reject".into(),
                repeated_violation: "quarantine".into(),
                internal_error: "abort".into(),
                quarantine_threshold: 3,
            },
            network_policy: Some(NetworkPolicy::default()),
            risk_evidence: None,
            privilege_expansion: None,
        }
    }

    #[test]
    fn mode_001_closed_parser() {
        assert!("access-only".parse::<VerifierMode>().is_ok());
        assert!("runtime-only".parse::<VerifierMode>().is_ok());
        assert!("full".parse::<VerifierMode>().is_err());
    }

    #[test]
    fn mode_002_capability_boundaries() {
        assert!(!VerifierMode::AccessOnly.transition_guards_enabled());
        assert!(!VerifierMode::AccessOnly.runtime_constraints_enabled());
        assert!(VerifierMode::TransitionOnly.transition_guards_enabled());
        assert!(!VerifierMode::TransitionOnly.runtime_constraints_enabled());
        assert!(!VerifierMode::RuntimeOnly.transition_guards_enabled());
        assert!(VerifierMode::RuntimeOnly.runtime_constraints_enabled());
        assert!(VerifierMode::FullPbea.transition_guards_enabled());
        assert!(VerifierMode::FullPbea.runtime_constraints_enabled());
    }

    #[test]
    fn mode_004_full_pbea_rejects_noop_backend() {
        let mut value = policy();
        value.process_constraints.os_backend = OsBackend::Noop;
        assert!(validate_mode_policy(VerifierMode::FullPbea, &value).is_err());
        assert!(validate_mode_policy(VerifierMode::RuntimeOnly, &value).is_err());
    }

    #[test]
    fn mode_005_transition_only_does_not_claim_runtime_enforcement() {
        assert!(!VerifierMode::TransitionOnly.runtime_constraints_enabled());
        assert!(validate_mode_policy(VerifierMode::TransitionOnly, &policy()).is_ok());
    }

    #[test]
    fn mode_006_runtime_only_symmetry() {
        assert!(!VerifierMode::RuntimeOnly.policy_digest_required());
        assert!(!VerifierMode::RuntimeOnly.transition_guards_enabled());
        assert!(VerifierMode::RuntimeOnly.runtime_constraints_enabled());
        assert!(validate_mode_policy(VerifierMode::RuntimeOnly, &policy()).is_ok());
    }
}
