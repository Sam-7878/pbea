use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::RiskAssessment;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub transition_id: String,
    pub protocol_id: String,
    pub protocol_version: String,
    pub policy_digest: String,
    pub actor: String,
    pub operation: String,
    pub outcome: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_evidence: Option<RiskAssessment>,
}
