use chrono::{TimeZone, Utc};
use poa_core::*;

fn bps(value: u16) -> BasisPoints {
    BasisPoints::new(value).unwrap()
}

fn evidence(occurrences: u32, severity: u16, confidence: u16) -> RiskEvidence {
    RiskEvidence::new(
        RiskCategory::ReplayAttack,
        bps(severity),
        bps(confidence),
        occurrences,
        EvidenceSource::ReplayWindow,
        1_751_234_567_890,
        CorrelationId::new("corr-001").unwrap(),
    )
    .unwrap()
}

fn policy(enabled: bool, mode: EvidenceAggregation) -> QuarantinePolicy {
    QuarantinePolicy::new(enabled, 3, bps(8_000), bps(8_000), mode).unwrap()
}

#[test]
fn re_mod_001_zero_bps_allowed() {
    assert_eq!(bps(0).value(), 0);
}

#[test]
fn re_mod_002_ten_thousand_bps_allowed() {
    assert_eq!(bps(10_000).value(), 10_000);
}

#[test]
fn re_mod_003_out_of_range_bps_rejected() {
    assert!(BasisPoints::new(10_001).is_err());
}

#[test]
fn re_mod_004_zero_occurrences_rejected() {
    let result = RiskEvidence::new(
        RiskCategory::FraudSignal,
        bps(1),
        bps(1),
        0,
        EvidenceSource::PatternDetector,
        0,
        CorrelationId::new("c").unwrap(),
    );
    assert!(matches!(
        result,
        Err(RiskModelError::OccurrencesMustBePositive)
    ));
}

#[test]
fn re_mod_005_empty_correlation_rejected() {
    assert!(CorrelationId::new("").is_err());
}

#[test]
fn re_mod_006_unknown_json_field_rejected() {
    let mut value = serde_json::to_value(evidence(1, 1, 1)).unwrap();
    value["unknown"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RiskEvidence>(value).is_err());
}

#[test]
fn re_mod_007_category_round_trip() {
    for value in [
        RiskCategory::ReplayAttack,
        RiskCategory::GeofenceViolation,
        RiskCategory::AuthenticationFailure,
        RiskCategory::PolicyEscalation,
        RiskCategory::FraudSignal,
        RiskCategory::AnomalySignal,
    ] {
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<RiskCategory>(&json).unwrap(), value);
    }
}

#[test]
fn re_mod_008_source_round_trip() {
    for value in [
        EvidenceSource::ReplayWindow,
        EvidenceSource::GeofenceEngine,
        EvidenceSource::AuthenticationVerifier,
        EvidenceSource::PolicyValidator,
        EvidenceSource::PatternDetector,
        EvidenceSource::ExternalOracle,
    ] {
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<EvidenceSource>(&json).unwrap(),
            value
        );
    }
}

#[test]
fn re_eval_001_to_008_all_threshold_truth_table() {
    for bits in 0u8..8 {
        let e = evidence(
            if bits & 1 != 0 { 3 } else { 2 },
            if bits & 2 != 0 { 8_000 } else { 7_999 },
            if bits & 4 != 0 { 8_000 } else { 7_999 },
        );
        let decision = evaluate_evidence(&e, &policy(true, EvidenceAggregation::AllThresholds));
        assert_eq!(
            matches!(decision, EvidenceDecision::Quarantine { .. }),
            bits == 7,
            "bits={bits}"
        );
    }
}

#[test]
fn re_eval_020_to_026_any_threshold_success_combinations() {
    for bits in 1u8..8 {
        let e = evidence(
            if bits & 1 != 0 { 3 } else { 2 },
            if bits & 2 != 0 { 8_000 } else { 7_999 },
            if bits & 4 != 0 { 8_000 } else { 7_999 },
        );
        assert!(
            matches!(
                evaluate_evidence(&e, &policy(true, EvidenceAggregation::AnyThreshold)),
                EvidenceDecision::Quarantine { .. }
            ),
            "bits={bits}"
        );
    }
    assert!(matches!(
        evaluate_evidence(
            &evidence(2, 7_999, 7_999),
            &policy(true, EvidenceAggregation::AnyThreshold)
        ),
        EvidenceDecision::Insufficient { .. }
    ));
}

#[test]
fn re_dis_001_risk_disabled_rejects_and_re_dis_002_preserves_audit_data() {
    let original = evidence(9, 9_000, 9_000);
    let result = classify_failure(
        TransitionFailure::Risk(original.clone()),
        Some(&policy(false, EvidenceAggregation::AllThresholds)),
    );
    assert!(matches!(
        result.outcome,
        TransitionOutcome::Reject(RejectReason::RiskEvidenceInsufficient)
    ));
    let assessment = result.risk_assessment.unwrap();
    assert_eq!(assessment.evidence, original);
    assert_eq!(assessment.reason_code, RiskReasonCode::ExtensionDisabled);
}

#[test]
fn re_dis_003_direct_quarantine_semantics_unchanged() {
    let outcome = TransitionOutcome::Quarantine(QuarantineReason::RepeatedPolicyViolation);
    assert_eq!(outcome.label(), "quarantine");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    None,
    Authorize,
    Validate,
    Mutate,
    Reconcile,
    Commit,
    Policy,
    Internal,
}

struct Hooks {
    stage: Stage,
    committed: Vec<u32>,
    candidates: u32,
}

impl RiskAwareAacoHooks<(), (), (), ()> for Hooks {
    type Candidate = u32;
    type State = Vec<u32>;
    fn authorize(&self, _: &TransitionDescriptor<(), (), (), ()>) -> Result<(), TransitionFailure> {
        match self.stage {
            Stage::Authorize => Err(TransitionFailure::Risk(evidence(3, 8_000, 8_000))),
            Stage::Policy => Err(TransitionFailure::Policy(RejectReason::DisallowedActor)),
            Stage::Internal => Err(TransitionFailure::Internal(AbortReason::InternalFailure(
                "x".into(),
            ))),
            _ => Ok(()),
        }
    }
    fn validate(&self, _: &TransitionDescriptor<(), (), (), ()>) -> Result<(), TransitionFailure> {
        if self.stage == Stage::Validate {
            Err(TransitionFailure::Risk(evidence(3, 8_000, 8_000)))
        } else {
            Ok(())
        }
    }
    fn mutate_candidate(
        &mut self,
        _: &TransitionDescriptor<(), (), (), ()>,
    ) -> Result<u32, TransitionFailure> {
        self.candidates += 1;
        if self.stage == Stage::Mutate {
            Err(TransitionFailure::Risk(evidence(3, 8_000, 8_000)))
        } else {
            Ok(self.candidates)
        }
    }
    fn reconcile(&self, _: &u32) -> Result<(), TransitionFailure> {
        if self.stage == Stage::Reconcile {
            Err(TransitionFailure::Risk(evidence(3, 8_000, 8_000)))
        } else {
            Ok(())
        }
    }
    fn commit(&mut self, candidate: u32) -> Result<(), TransitionFailure> {
        if self.stage == Stage::Commit {
            return Err(TransitionFailure::Risk(evidence(3, 8_000, 8_000)));
        }
        self.committed.push(candidate);
        Ok(())
    }
    fn state(&self) -> &Vec<u32> {
        &self.committed
    }
}

fn descriptor() -> TransitionDescriptor<(), (), (), ()> {
    TransitionDescriptor {
        actor: (),
        asset: (),
        context: (),
        operation: (),
    }
}

#[test]
fn re_ker_001_to_004_risk_at_every_precommit_stage_quarantines() {
    for stage in [
        Stage::Authorize,
        Stage::Validate,
        Stage::Mutate,
        Stage::Reconcile,
    ] {
        let mut hooks = Hooks {
            stage,
            committed: vec![],
            candidates: 0,
        };
        let result = execute_transition_with_risk(
            &mut hooks,
            &descriptor(),
            Some(&policy(true, EvidenceAggregation::AllThresholds)),
        );
        assert!(matches!(
            result.outcome,
            TransitionOutcome::Quarantine(QuarantineReason::RiskEvidenceThreshold)
        ));
        assert!(hooks.committed.is_empty());
    }
}

#[test]
fn re_ker_005_insufficient_risk_rejects() {
    let result = classify_failure(
        TransitionFailure::Risk(evidence(2, 9_000, 9_000)),
        Some(&policy(true, EvidenceAggregation::AllThresholds)),
    );
    assert!(matches!(
        result.outcome,
        TransitionOutcome::Reject(RejectReason::RiskEvidenceInsufficient)
    ));
}

#[test]
fn re_ker_006_policy_rejects_and_re_ker_007_internal_aborts() {
    for (stage, expected) in [(Stage::Policy, "reject"), (Stage::Internal, "abort")] {
        let mut hooks = Hooks {
            stage,
            committed: vec![],
            candidates: 0,
        };
        let result = execute_transition_with_risk(
            &mut hooks,
            &descriptor(),
            Some(&policy(true, EvidenceAggregation::AllThresholds)),
        );
        assert_eq!(result.outcome.label(), expected);
    }
}

#[test]
fn re_state_001_to_005_candidates_never_leak_before_commit_and_retry_is_clean() {
    for stage in [
        Stage::Authorize,
        Stage::Validate,
        Stage::Mutate,
        Stage::Reconcile,
    ] {
        let mut hooks = Hooks {
            stage,
            committed: vec![41],
            candidates: 0,
        };
        let _ = execute_transition_with_risk(
            &mut hooks,
            &descriptor(),
            Some(&policy(true, EvidenceAggregation::AllThresholds)),
        );
        assert_eq!(hooks.committed, vec![41]);
        let _audit_only = serde_json::to_vec(&hooks.committed).unwrap();
        assert_eq!(hooks.committed, vec![41]);
        hooks.stage = Stage::None;
        let retry = execute_transition_with_risk(
            &mut hooks,
            &descriptor(),
            Some(&policy(true, EvidenceAggregation::AllThresholds)),
        );
        assert!(matches!(retry.outcome, TransitionOutcome::Commit));
        assert_eq!(hooks.committed.len(), 2);
    }
}

#[test]
fn re_aud_001_to_006_structured_minimal_round_trip() {
    let result = classify_failure(
        TransitionFailure::Risk(evidence(3, 9_000, 8_500)),
        Some(&policy(true, EvidenceAggregation::AllThresholds)),
    );
    let audit = AuditRecord {
        transition_id: "t".into(),
        protocol_id: "p".into(),
        protocol_version: "1.0.0".into(),
        policy_digest: "sha256:abc".into(),
        actor: "a".into(),
        operation: "o".into(),
        outcome: result.outcome.label().into(),
        timestamp: Utc.timestamp_millis_opt(1_751_234_567_890).unwrap(),
        payload_hash: None,
        risk_evidence: result.risk_assessment,
    };
    let bytes = serde_json::to_vec(&audit).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(
        text.contains("corr-001") && text.contains("sha256:abc") && text.contains("risk_evidence")
    );
    assert!(!text.contains("committed_assets") && !text.contains("candidate"));
    let restored: AuditRecord = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        restored
            .risk_evidence
            .unwrap()
            .evidence
            .correlation_id()
            .as_str(),
        "corr-001"
    );
}

#[test]
fn re_prop_001_to_006_deterministic_monotone_bounded_and_timestamp_independent() {
    let p = policy(true, EvidenceAggregation::AllThresholds);
    for occurrences in 1..=6 {
        for severity in (0..=10_000).step_by(500) {
            for confidence in (0..=10_000).step_by(500) {
                let low = evidence(occurrences, severity, confidence);
                let first = evaluate_evidence(&low, &p);
                assert_eq!(first, evaluate_evidence(&low, &p));
                let high = evidence(
                    occurrences.saturating_add(1),
                    severity.saturating_add(1).min(10_000),
                    confidence.saturating_add(1).min(10_000),
                );
                if matches!(first, EvidenceDecision::Quarantine { .. }) {
                    assert!(matches!(
                        evaluate_evidence(&high, &p),
                        EvidenceDecision::Quarantine { .. }
                    ));
                }
                let mut value = serde_json::to_value(&low).unwrap();
                value["observed_at_ms"] = serde_json::json!(9_999_999_u64);
                let changed: RiskEvidence = serde_json::from_value(value).unwrap();
                assert_eq!(first, evaluate_evidence(&changed, &p));
            }
        }
    }
    assert!(serde_json::from_str::<BasisPoints>("10001").is_err());
    assert!(CorrelationId::new(" x ").is_err());
    let mut invalid_timestamp = serde_json::to_value(evidence(1, 1, 1)).unwrap();
    invalid_timestamp["observed_at_ms"] = serde_json::json!(-1);
    assert!(serde_json::from_value::<RiskEvidence>(invalid_timestamp).is_err());
}
