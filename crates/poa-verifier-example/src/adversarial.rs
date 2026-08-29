use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{DomainState, mode::VerifierMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ScenarioId {
    S0,
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
}

impl ScenarioId {
    pub const ALL: [Self; 9] = [
        Self::S0,
        Self::S1,
        Self::S2,
        Self::S3,
        Self::S4,
        Self::S5,
        Self::S6,
        Self::S7,
        Self::S8,
    ];
}

impl fmt::Display for ScenarioId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl FromStr for ScenarioId {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "S0" => Ok(Self::S0),
            "S1" => Ok(Self::S1),
            "S2" => Ok(Self::S2),
            "S3" => Ok(Self::S3),
            "S4" => Ok(Self::S4),
            "S5" => Ok(Self::S5),
            "S6" => Ok(Self::S6),
            "S7" => Ok(Self::S7),
            "S8" => Ok(Self::S8),
            _ => anyhow::bail!("unknown scenario: {value}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub run_id: String,
    pub experiment_id: String,
    pub scenario_id: ScenarioId,
    pub mode: VerifierMode,
    pub iteration: u32,
    pub seed: u64,
    pub timestamp: String,
    pub source_commit: String,
    pub platform: String,
    pub build_profile: String,
    pub policy_digest: Option<String>,
    pub actor_authenticated: bool,
    pub access_authorized: bool,
    pub operation: String,
    pub expected_outcome: String,
    pub observed_outcome: String,
    pub malicious_effect_attempted: bool,
    pub malicious_effect_succeeded: bool,
    pub state_hash_before: String,
    pub state_hash_after: String,
    pub state_changed: bool,
    pub capability_type: Option<String>,
    pub target: Option<String>,
    pub os_errno: Option<i32>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub listener_opened: bool,
    pub business_loop_entered: bool,
    pub duration_us: u64,
    pub status: String,
    pub details: Option<BTreeMap<String, String>>,
}

pub fn state_hash(state: &DomainState) -> String {
    let bytes = serde_json::to_vec(&state.committed_assets).expect("BTreeMap serialization");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adv_s0_001_deterministic_state_hash() {
        let mut state = DomainState::default();
        state.committed_assets.insert("asset-b".into(), 2);
        state.committed_assets.insert("asset-a".into(), 1);
        assert_eq!(state_hash(&state), state_hash(&state));
    }

    #[test]
    fn mode_003_scenario_parser_is_closed() {
        assert_eq!("S8".parse::<ScenarioId>().unwrap(), ScenarioId::S8);
        assert!("S9".parse::<ScenarioId>().is_err());
    }
}
