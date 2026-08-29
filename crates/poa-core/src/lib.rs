pub mod audit;
pub mod descriptor;
pub mod kernel;
pub mod outcome;
pub mod risk;

pub use audit::AuditRecord;
pub use descriptor::TransitionDescriptor;
pub use kernel::{AacoHooks, RiskAwareAacoHooks, execute_transition, execute_transition_with_risk};
pub use outcome::{AbortReason, QuarantineReason, RejectReason, TransitionOutcome};
pub use risk::{
    BasisPoints, CorrelationId, EvidenceAggregation, EvidenceDecision, EvidenceSource,
    EvidenceThreshold, QuarantinePolicy, RiskAssessment, RiskCategory, RiskEvidence,
    RiskModelError, RiskReasonCode, TransitionFailure, TransitionResult, classify_failure,
    evaluate_evidence,
};
