use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentMode {
    Development,
    Production,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OsBackend {
    Openbsd,
    Noop,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPolicy {
    pub name: String,
    pub allowed_actors: Vec<String>,
    pub required_context: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnveilPath {
    pub path: String,
    pub permissions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessConstraints {
    pub os_backend: OsBackend,
    pub pledge_promises: Vec<String>,
    pub unveil_paths: Vec<UnveilPath>,
    pub lock_after_initialization: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataConstraints {
    pub input_schema: String,
    pub maximum_message_bytes: u64,
    pub canonical_encoding: String,
    #[serde(default = "default_nesting_depth")]
    pub maximum_nesting_depth: usize,
}

fn default_nesting_depth() -> usize {
    32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailurePolicy {
    pub invalid_request: String,
    pub policy_violation: String,
    pub repeated_violation: String,
    pub internal_error: String,
    #[serde(default = "default_quarantine_threshold")]
    pub quarantine_threshold: u32,
}

fn default_quarantine_threshold() -> u32 {
    3
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRule {
    pub protocol: String,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub inbound: Vec<EndpointRule>,
    #[serde(default)]
    pub outbound: Vec<EndpointRule>,
    #[serde(default)]
    pub dns_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegeExpansion {
    pub approved: bool,
    pub approval_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskEvidenceAggregation {
    AllThresholds,
    AnyThreshold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskEvidencePolicy {
    pub enabled: bool,
    pub minimum_occurrences: u32,
    pub minimum_severity_bps: u16,
    pub minimum_confidence_bps: u16,
    pub aggregation: RiskEvidenceAggregation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolSpec {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub protocol_id: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extends: Option<String>,
    pub mode: DeploymentMode,
    pub operations: Vec<OperationPolicy>,
    pub process_constraints: ProcessConstraints,
    pub data_constraints: DataConstraints,
    pub failure_policy: FailurePolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<NetworkPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_evidence: Option<RiskEvidencePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privilege_expansion: Option<PrivilegeExpansion>,
}

pub type EffectivePolicy = ProtocolSpec;
