use poa_core::TransitionOutcome;
use poa_protocol::{PolicyRepository, validate_value};
use poa_verifier_example::Verifier;
use serde_json::{Value, json};

fn verifier() -> Verifier {
    let schema: Value = serde_json::from_str(include_str!(
        "../../../protocol/schema/poa-protocol-v1.schema.json"
    ))
    .unwrap();
    let base = validate_value(
        &serde_json::from_str(include_str!(
            "../../../protocol/base/hete.base.verifier.json"
        ))
        .unwrap(),
        &schema,
    )
    .unwrap();
    let child = validate_value(
        &serde_json::from_str(include_str!(
            "../../../protocol/examples/hete.verifier.payment.json"
        ))
        .unwrap(),
        &schema,
    )
    .unwrap();
    let policy = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap()
        .policy;
    let request_schema = serde_json::from_str(include_str!(
        "../../../protocol/schemas/transition-request.json"
    ))
    .unwrap();
    Verifier::new(policy, request_schema).unwrap()
}

fn request(verifier: &Verifier) -> Value {
    json!({"actor":"ubuntu-ledger-gateway","asset":"payment-transition-001","context":{"request_id":"req-1","expiry":1784553000_i64,"policy_digest":verifier.policy_digest()},"operation":"verify_transition","payload":{"amount":1000,"currency":"KRW"}})
}

#[test]
fn out_001_valid_commit_and_digest_audit() {
    let mut v = verifier();
    let bytes = serde_json::to_vec(&request(&v)).unwrap();
    let result = v.process_bytes(&bytes);
    assert_eq!(result.outcome, TransitionOutcome::Commit);
    assert_eq!(result.audit.policy_digest, v.policy_digest());
    assert_eq!(
        v.domain_state
            .committed_assets
            .get("payment-transition-001"),
        Some(&1000)
    );
}

#[test]
fn out_002_reject_disallowed_operation_state_unchanged() {
    let mut v = verifier();
    let before = v.domain_state.clone();
    let mut r = request(&v);
    r["operation"] = json!("delete_everything");
    assert!(matches!(
        v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome,
        TransitionOutcome::Reject(_)
    ));
    assert_eq!(v.domain_state, before);
}

#[test]
fn out_003_missing_context_rejected() {
    let mut v = verifier();
    let mut r = request(&v);
    r["context"].as_object_mut().unwrap().remove("expiry");
    assert!(matches!(
        v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome,
        TransitionOutcome::Reject(_)
    ));
}

#[test]
fn out_004_repeated_violation_quarantines_without_domain_change() {
    let mut v = verifier();
    let before = v.domain_state.clone();
    let mut r = request(&v);
    r["operation"] = json!("bad");
    let bytes = serde_json::to_vec(&r).unwrap();
    assert!(matches!(
        v.process_bytes(&bytes).outcome,
        TransitionOutcome::Reject(_)
    ));
    assert!(matches!(
        v.process_bytes(&bytes).outcome,
        TransitionOutcome::Reject(_)
    ));
    assert!(matches!(
        v.process_bytes(&bytes).outcome,
        TransitionOutcome::Quarantine(_)
    ));
    assert_eq!(v.domain_state, before);
    assert!(
        v.trust_state
            .quarantined_actors
            .contains("ubuntu-ledger-gateway")
    );
}

#[test]
fn out_005_internal_failure_aborts_without_state_change() {
    let mut v = verifier();
    let before = v.domain_state.clone();
    let mut r = request(&v);
    r["payload"]["inject_internal_error"] = json!(true);
    assert!(matches!(
        v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome,
        TransitionOutcome::Abort(_)
    ));
    assert_eq!(v.domain_state, before);
}

#[test]
fn e2e_008_wrong_digest_rejected() {
    let mut v = verifier();
    let mut r = request(&v);
    r["context"]["policy_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    assert!(matches!(
        v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome,
        TransitionOutcome::Reject(_)
    ));
}

#[test]
fn p1_input_unknown_field_and_size_rejected() {
    let mut v = verifier();
    let mut r = request(&v);
    r["unknown"] = json!(1);
    assert!(matches!(
        v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome,
        TransitionOutcome::Reject(_)
    ));
    let oversized = vec![b' '; 65537];
    assert!(matches!(
        v.process_bytes(&oversized).outcome,
        TransitionOutcome::Reject(_)
    ));
}

#[test]
fn p1_network_allowlist_enforced() {
    let v = verifier();
    assert!(v.authorize_inbound("127.0.0.1".parse().unwrap(), 7878, "tcp"));
    assert!(v.authorize_inbound("192.168.1.25".parse().unwrap(), 7878, "tcp"));
    assert!(!v.authorize_inbound("192.0.2.1".parse().unwrap(), 7878, "tcp"));
    assert!(!v.authorize_outbound("127.0.0.1".parse().unwrap(), 443, "tcp"));
}
