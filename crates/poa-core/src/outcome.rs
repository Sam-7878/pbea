use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    DisallowedOperation,
    DisallowedActor,
    MissingContext(String),
    InvalidInput(String),
    PolicyDigestMismatch,
    InvariantViolation(String),
    RiskEvidenceInsufficient,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    RepeatedPolicyViolation,
    RiskEvidenceThreshold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbortReason {
    InternalFailure(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "reason", rename_all = "snake_case")]
pub enum TransitionOutcome {
    Commit,
    Reject(RejectReason),
    Quarantine(QuarantineReason),
    Abort(AbortReason),
}

impl TransitionOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Reject(_) => "reject",
            Self::Quarantine(_) => "quarantine",
            Self::Abort(_) => "abort",
        }
    }
}
