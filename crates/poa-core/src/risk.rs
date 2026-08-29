use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::{AbortReason, QuarantineReason, RejectReason, TransitionOutcome};

pub const MAX_BASIS_POINTS: u16 = 10_000;
pub const MAX_CORRELATION_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskModelError {
    BasisPointsOutOfRange(u16),
    OccurrencesMustBePositive,
    EmptyCorrelationId,
    CorrelationIdTooLong(usize),
    CorrelationIdHasSurroundingWhitespace,
    CorrelationIdContainsControl,
}

impl fmt::Display for RiskModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BasisPointsOutOfRange(value) => {
                write!(
                    formatter,
                    "basis points must be 0..={MAX_BASIS_POINTS}, got {value}"
                )
            }
            Self::OccurrencesMustBePositive => {
                write!(formatter, "occurrences must be at least one")
            }
            Self::EmptyCorrelationId => write!(formatter, "correlation ID must not be empty"),
            Self::CorrelationIdTooLong(length) => write!(
                formatter,
                "correlation ID must be at most {MAX_CORRELATION_ID_BYTES} bytes, got {length}"
            ),
            Self::CorrelationIdHasSurroundingWhitespace => {
                write!(
                    formatter,
                    "correlation ID must not have surrounding whitespace"
                )
            }
            Self::CorrelationIdContainsControl => {
                write!(
                    formatter,
                    "correlation ID must not contain control characters"
                )
            }
        }
    }
}

impl std::error::Error for RiskModelError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct BasisPoints(u16);

impl BasisPoints {
    pub fn new(value: u16) -> Result<Self, RiskModelError> {
        if value <= MAX_BASIS_POINTS {
            Ok(Self(value))
        } else {
            Err(RiskModelError::BasisPointsOutOfRange(value))
        }
    }

    pub const fn value(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for BasisPoints {
    type Error = RiskModelError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<BasisPoints> for u16 {
    fn from(value: BasisPoints) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for BasisPoints {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct CorrelationId(String);

impl CorrelationId {
    pub fn new(value: impl Into<String>) -> Result<Self, RiskModelError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RiskModelError::EmptyCorrelationId);
        }
        if value.trim() != value {
            return Err(RiskModelError::CorrelationIdHasSurroundingWhitespace);
        }
        if value.len() > MAX_CORRELATION_ID_BYTES {
            return Err(RiskModelError::CorrelationIdTooLong(value.len()));
        }
        if value.chars().any(char::is_control) {
            return Err(RiskModelError::CorrelationIdContainsControl);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CorrelationId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    ReplayAttack,
    GeofenceViolation,
    AuthenticationFailure,
    PolicyEscalation,
    FraudSignal,
    AnomalySignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    ReplayWindow,
    GeofenceEngine,
    AuthenticationVerifier,
    PolicyValidator,
    PatternDetector,
    ExternalOracle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RiskEvidence {
    category: RiskCategory,
    severity_bps: BasisPoints,
    confidence_bps: BasisPoints,
    occurrences: u32,
    source: EvidenceSource,
    observed_at_ms: u64,
    correlation_id: CorrelationId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskEvidenceWire {
    category: RiskCategory,
    severity_bps: BasisPoints,
    confidence_bps: BasisPoints,
    occurrences: u32,
    source: EvidenceSource,
    observed_at_ms: u64,
    correlation_id: CorrelationId,
}

impl RiskEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        category: RiskCategory,
        severity_bps: BasisPoints,
        confidence_bps: BasisPoints,
        occurrences: u32,
        source: EvidenceSource,
        observed_at_ms: u64,
        correlation_id: CorrelationId,
    ) -> Result<Self, RiskModelError> {
        if occurrences == 0 {
            return Err(RiskModelError::OccurrencesMustBePositive);
        }
        Ok(Self {
            category,
            severity_bps,
            confidence_bps,
            occurrences,
            source,
            observed_at_ms,
            correlation_id,
        })
    }

    pub const fn category(&self) -> RiskCategory {
        self.category
    }
    pub const fn severity(&self) -> BasisPoints {
        self.severity_bps
    }
    pub const fn confidence(&self) -> BasisPoints {
        self.confidence_bps
    }
    pub const fn occurrences(&self) -> u32 {
        self.occurrences
    }
    pub const fn source(&self) -> EvidenceSource {
        self.source
    }
    pub const fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }
    pub fn correlation_id(&self) -> &CorrelationId {
        &self.correlation_id
    }
}

impl<'de> Deserialize<'de> for RiskEvidence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = RiskEvidenceWire::deserialize(deserializer)?;
        Self::new(
            wire.category,
            wire.severity_bps,
            wire.confidence_bps,
            wire.occurrences,
            wire.source,
            wire.observed_at_ms,
            wire.correlation_id,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceAggregation {
    AllThresholds,
    AnyThreshold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuarantinePolicy {
    enabled: bool,
    minimum_occurrences: u32,
    minimum_severity_bps: BasisPoints,
    minimum_confidence_bps: BasisPoints,
    aggregation: EvidenceAggregation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QuarantinePolicyWire {
    enabled: bool,
    minimum_occurrences: u32,
    minimum_severity_bps: BasisPoints,
    minimum_confidence_bps: BasisPoints,
    aggregation: EvidenceAggregation,
}

impl QuarantinePolicy {
    pub fn new(
        enabled: bool,
        minimum_occurrences: u32,
        minimum_severity_bps: BasisPoints,
        minimum_confidence_bps: BasisPoints,
        aggregation: EvidenceAggregation,
    ) -> Result<Self, RiskModelError> {
        if minimum_occurrences == 0 {
            return Err(RiskModelError::OccurrencesMustBePositive);
        }
        Ok(Self {
            enabled,
            minimum_occurrences,
            minimum_severity_bps,
            minimum_confidence_bps,
            aggregation,
        })
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }
    pub const fn minimum_occurrences(&self) -> u32 {
        self.minimum_occurrences
    }
    pub const fn minimum_severity(&self) -> BasisPoints {
        self.minimum_severity_bps
    }
    pub const fn minimum_confidence(&self) -> BasisPoints {
        self.minimum_confidence_bps
    }
    pub const fn aggregation(&self) -> EvidenceAggregation {
        self.aggregation
    }
}

impl<'de> Deserialize<'de> for QuarantinePolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = QuarantinePolicyWire::deserialize(deserializer)?;
        Self::new(
            wire.enabled,
            wire.minimum_occurrences,
            wire.minimum_severity_bps,
            wire.minimum_confidence_bps,
            wire.aggregation,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceThreshold {
    Occurrences,
    Severity,
    Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceDecision {
    ExtensionDisabled,
    Insufficient {
        failed_thresholds: Vec<EvidenceThreshold>,
    },
    Quarantine {
        score_bps: BasisPoints,
        matched_thresholds: Vec<EvidenceThreshold>,
    },
}

pub fn evaluate_evidence(evidence: &RiskEvidence, policy: &QuarantinePolicy) -> EvidenceDecision {
    if !policy.enabled {
        return EvidenceDecision::ExtensionDisabled;
    }
    let checks = [
        (
            EvidenceThreshold::Occurrences,
            evidence.occurrences >= policy.minimum_occurrences,
        ),
        (
            EvidenceThreshold::Severity,
            evidence.severity_bps >= policy.minimum_severity_bps,
        ),
        (
            EvidenceThreshold::Confidence,
            evidence.confidence_bps >= policy.minimum_confidence_bps,
        ),
    ];
    let matched: Vec<_> = checks
        .iter()
        .filter_map(|(threshold, passed)| passed.then_some(*threshold))
        .collect();
    let satisfied = match policy.aggregation {
        EvidenceAggregation::AllThresholds => matched.len() == checks.len(),
        EvidenceAggregation::AnyThreshold => !matched.is_empty(),
    };
    if satisfied {
        EvidenceDecision::Quarantine {
            score_bps: evidence.severity_bps.min(evidence.confidence_bps),
            matched_thresholds: matched,
        }
    } else {
        EvidenceDecision::Insufficient {
            failed_thresholds: checks
                .iter()
                .filter_map(|(threshold, passed)| (!passed).then_some(*threshold))
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskReasonCode {
    ExtensionDisabled,
    InsufficientEvidence,
    ThresholdSatisfied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskAssessment {
    pub evidence: RiskEvidence,
    pub decision: EvidenceDecision,
    pub reason_code: RiskReasonCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionFailure {
    Policy(RejectReason),
    Risk(RiskEvidence),
    Internal(AbortReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionResult {
    pub outcome: TransitionOutcome,
    pub risk_assessment: Option<RiskAssessment>,
}

pub fn classify_failure(
    failure: TransitionFailure,
    policy: Option<&QuarantinePolicy>,
) -> TransitionResult {
    match failure {
        TransitionFailure::Policy(reason) => TransitionResult {
            outcome: TransitionOutcome::Reject(reason),
            risk_assessment: None,
        },
        TransitionFailure::Internal(reason) => TransitionResult {
            outcome: TransitionOutcome::Abort(reason),
            risk_assessment: None,
        },
        TransitionFailure::Risk(evidence) => {
            let decision = policy.map_or(EvidenceDecision::ExtensionDisabled, |p| {
                evaluate_evidence(&evidence, p)
            });
            let (outcome, reason_code) = match decision {
                EvidenceDecision::Quarantine { .. } => (
                    TransitionOutcome::Quarantine(QuarantineReason::RiskEvidenceThreshold),
                    RiskReasonCode::ThresholdSatisfied,
                ),
                EvidenceDecision::ExtensionDisabled => (
                    TransitionOutcome::Reject(RejectReason::RiskEvidenceInsufficient),
                    RiskReasonCode::ExtensionDisabled,
                ),
                EvidenceDecision::Insufficient { .. } => (
                    TransitionOutcome::Reject(RejectReason::RiskEvidenceInsufficient),
                    RiskReasonCode::InsufficientEvidence,
                ),
            };
            TransitionResult {
                outcome,
                risk_assessment: Some(RiskAssessment {
                    evidence,
                    decision,
                    reason_code,
                }),
            }
        }
    }
}
