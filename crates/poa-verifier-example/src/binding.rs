//! Worker-lifetime identity consistency, not kernel attestation.
use poa_protocol::{EffectivePolicy, canonicalize_value, policy_digest};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub policy_id: String,
    pub policy_epoch: String,
    pub backend: String,
    pub plan_id: String,
    pub pledge: String,
    pub unveil: Vec<poa_protocol::UnveilPath>,
    pub locked: bool,
}

impl RuntimePlan {
    pub fn from_policy(policy: &EffectivePolicy) -> anyhow::Result<Self> {
        let pledge = poa_sandbox::mapper::pledge_string(&policy.process_constraints)?;
        let unveil = poa_sandbox::mapper::unveil_plan(&policy.process_constraints)?;
        let bytes = canonicalize_value(&(
            &pledge,
            &unveil,
            &policy.network_policy,
            policy.process_constraints.lock_after_initialization,
        ))?;
        Ok(Self {
            policy_id: policy_digest(policy)?,
            policy_epoch: policy.version.clone(),
            backend: "openbsd-pledge-unveil-v1".into(),
            plan_id: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            pledge,
            unveil,
            locked: policy.process_constraints.lock_after_initialization,
        })
    }
}

pub fn check_identity_contract(
    request_id: &str,
    transition_id: &str,
    runtime_id: &str,
    evidence_id: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request_id == transition_id && transition_id == runtime_id && runtime_id == evidence_id,
        "policy identity mismatch across request, transition, runtime plan, or evidence"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_skew_is_rejected_but_same_identity_is_not_attestation() {
        assert!(check_identity_contract("a", "a", "a", "a").is_ok());
        assert!(check_identity_contract("a", "a", "b", "a").is_err());
        assert!(check_identity_contract("a", "a", "a", "b").is_err());
    }
}
