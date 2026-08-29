use poa_protocol::{PolicyError, PolicyRepository, canonicalize, policy_digest, validate_value};
use serde_json::{Value, json};

fn risk_policy(
    enabled: bool,
    occurrences: u32,
    severity: u16,
    confidence: u16,
    mode: &str,
) -> Value {
    json!({
        "enabled": enabled,
        "minimum_occurrences": occurrences,
        "minimum_severity_bps": severity,
        "minimum_confidence_bps": confidence,
        "aggregation": mode
    })
}

fn schema() -> Value {
    serde_json::from_str(include_str!(
        "../../../protocol/schema/poa-protocol-v1.schema.json"
    ))
    .unwrap()
}
fn base_value() -> Value {
    serde_json::from_str(include_str!(
        "../../../protocol/base/hete.base.verifier.json"
    ))
    .unwrap()
}
fn child_value() -> Value {
    serde_json::from_str(include_str!(
        "../../../protocol/examples/hete.verifier.payment.json"
    ))
    .unwrap()
}
fn empty_unveil_value() -> Value {
    serde_json::from_str(include_str!(
        "../../../protocol/fixtures/valid/empty-unveil.json"
    ))
    .unwrap()
}

#[test]
fn spec_001_valid_specification() {
    validate_value(&base_value(), &schema()).unwrap();
}

#[test]
fn sbox_empty_001_empty_unveil_is_valid_deny_all_policy() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let child = validate_value(&empty_unveil_value(), &schema()).unwrap();
    let effective = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap()
        .policy;
    assert!(effective.process_constraints.unveil_paths.is_empty());
}

#[test]
fn spec_002_missing_required_field() {
    let mut v = base_value();
    v.as_object_mut().unwrap().remove("failure_policy");
    assert!(matches!(
        validate_value(&v, &schema()),
        Err(PolicyError::Validation(_))
    ));
}

#[test]
fn spec_003_unknown_field() {
    let mut v = base_value();
    v["surprise"] = json!(true);
    assert!(matches!(
        validate_value(&v, &schema()),
        Err(PolicyError::Validation(_))
    ));
}

#[test]
fn spec_004_invalid_pledge() {
    let mut v = base_value();
    v["process_constraints"]["pledge_promises"] = json!(["stdio", "everything"]);
    let PolicyError::Validation(issues) = validate_value(&v, &schema()).unwrap_err() else {
        panic!()
    };
    assert!(issues.iter().any(|i| i.code == "unsupported_pledge"));
}

#[test]
fn spec_005_invalid_unveil_permission() {
    let mut v = base_value();
    v["process_constraints"]["unveil_paths"][0]["permissions"] = json!("rz");
    assert!(validate_value(&v, &schema()).is_err());
}

#[test]
fn spec_006_path_traversal() {
    let mut v = base_value();
    v["process_constraints"]["unveil_paths"][0]["path"] = json!("/var/hete/../etc");
    assert!(validate_value(&v, &schema()).is_err());
}

#[test]
fn spec_007_invalid_message_size() {
    let mut v = base_value();
    v["data_constraints"]["maximum_message_bytes"] = json!(0);
    assert!(validate_value(&v, &schema()).is_err());
}

#[test]
fn spec_008_production_noop() {
    let mut v = base_value();
    v["process_constraints"]["os_backend"] = json!("noop");
    let PolicyError::Validation(issues) = validate_value(&v, &schema()).unwrap_err() else {
        panic!()
    };
    assert!(issues.iter().any(|i| i.code == "noop_in_production"));
}

#[test]
fn inh_001_and_006_valid_narrowing() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let child = validate_value(&child_value(), &schema()).unwrap();
    let result = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap();
    assert_eq!(
        result.policy.process_constraints.pledge_promises,
        vec!["inet", "rpath", "stdio", "wpath"]
    );
    assert!(result.policy.extends.is_none());
}

#[test]
fn inh_003_missing_parent() {
    let child = validate_value(&child_value(), &schema()).unwrap();
    assert!(matches!(
        PolicyRepository::new([child]).resolve("hete.verifier.payment"),
        Err(PolicyError::MissingParent(_))
    ));
}

#[test]
fn inh_004_cycle_includes_chain() {
    let mut a = validate_value(&base_value(), &schema()).unwrap();
    a.protocol_id = "a".into();
    a.extends = Some("b".into());
    let mut b = a.clone();
    b.protocol_id = "b".into();
    b.extends = Some("a".into());
    let Err(PolicyError::Cycle(chain)) = PolicyRepository::new([a, b]).resolve("a") else {
        panic!()
    };
    assert_eq!(chain, "a -> b -> a");
}

#[test]
fn inh_007_expanding_pledge_rejected() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let mut child = validate_value(&child_value(), &schema()).unwrap();
    child
        .process_constraints
        .pledge_promises
        .push("exec".into());
    assert!(matches!(
        PolicyRepository::new([base, child]).resolve("hete.verifier.payment"),
        Err(PolicyError::PrivilegeExpansion { .. })
    ));
}

#[test]
fn p1_approved_expansion_is_accepted_and_audited() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let mut child = validate_value(&child_value(), &schema()).unwrap();
    child
        .process_constraints
        .pledge_promises
        .push("exec".into());
    child.privilege_expansion = Some(poa_protocol::PrivilegeExpansion {
        approved: true,
        approval_id: "change-2026-071".into(),
        reason: "evaluated exception".into(),
    });
    let result = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap();
    assert!(
        result
            .policy
            .process_constraints
            .pledge_promises
            .contains(&"exec".into())
    );
    assert!(
        result
            .expansion_audit
            .iter()
            .any(|entry| entry.contains("exec"))
    );
}

#[test]
fn p1_malformed_cidr_rejected() {
    let mut value = base_value();
    value["network_policy"]["inbound"][0]["address"] = json!("999.1.1.1/99");
    let PolicyError::Validation(issues) = validate_value(&value, &schema()).unwrap_err() else {
        panic!()
    };
    assert!(
        issues
            .iter()
            .any(|issue| issue.code == "invalid_network_address")
    );
}

#[test]
fn inh_009_context_weakening_rejected() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let mut child = validate_value(&child_value(), &schema()).unwrap();
    child.operations[0].required_context.pop();
    assert!(matches!(
        PolicyRepository::new([base, child]).resolve("hete.verifier.payment"),
        Err(PolicyError::PrivilegeExpansion { .. })
    ));
}

#[test]
fn dig_001_002_and_006_order_independent_and_repeatable() {
    let first = validate_value(&child_value(), &schema()).unwrap();
    let mut second = first.clone();
    second.operations[0].required_context.reverse();
    second.process_constraints.pledge_promises.reverse();
    assert_eq!(
        policy_digest(&first).unwrap(),
        policy_digest(&second).unwrap()
    );
    assert_eq!(
        canonicalize(&first).unwrap(),
        canonicalize(&second).unwrap()
    );
    assert_eq!(
        policy_digest(&first).unwrap(),
        policy_digest(&first).unwrap()
    );
}

#[test]
fn dig_003_004_005_material_changes_change_digest() {
    let original = validate_value(&child_value(), &schema()).unwrap();
    let digest = policy_digest(&original).unwrap();
    let mut operation = original.clone();
    operation.operations[0].name = "different".into();
    let mut pledge = original.clone();
    pledge.process_constraints.pledge_promises.pop();
    let mut unveil = original.clone();
    unveil.process_constraints.unveil_paths[0].path = "/different".into();
    assert_ne!(digest, policy_digest(&operation).unwrap());
    assert_ne!(digest, policy_digest(&pledge).unwrap());
    assert_ne!(digest, policy_digest(&unveil).unwrap());
}

#[test]
fn digest_golden_and_canonical_snapshot_match() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let child = validate_value(&child_value(), &schema()).unwrap();
    let effective = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap()
        .policy;
    assert_eq!(
        canonicalize(&effective).unwrap(),
        include_bytes!("../../../protocol/examples/hete.verifier.payment.effective.canonical.json")
            .strip_suffix(b"\n")
            .unwrap()
    );
    assert_eq!(
        policy_digest(&effective).unwrap(),
        include_str!("../../../protocol/examples/hete.verifier.payment.effective.sha256").trim()
    );
}

#[test]
fn re_protocol_optional_absence_preserves_legacy_golden_digest() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let child = validate_value(&child_value(), &schema()).unwrap();
    let effective = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap()
        .policy;
    assert!(effective.risk_evidence.is_none());
    assert_eq!(
        policy_digest(&effective).unwrap(),
        include_str!("../../../protocol/examples/hete.verifier.payment.effective.sha256").trim()
    );
}

#[test]
fn re_protocol_policy_is_strict_bounded_and_digest_bound() {
    let mut value = child_value();
    value["risk_evidence"] = risk_policy(true, 3, 8_000, 8_000, "all_thresholds");
    let spec = validate_value(&value, &schema()).unwrap();
    let legacy = validate_value(&child_value(), &schema()).unwrap();
    assert_ne!(
        policy_digest(&spec).unwrap(),
        policy_digest(&legacy).unwrap()
    );

    value["risk_evidence"]["minimum_confidence_bps"] = json!(10_001);
    assert!(validate_value(&value, &schema()).is_err());
    value["risk_evidence"]["minimum_confidence_bps"] = json!(8_000);
    value["risk_evidence"]["surprise"] = json!(true);
    assert!(validate_value(&value, &schema()).is_err());
}

#[test]
fn re_protocol_risk_policy_golden_digest() {
    let base = validate_value(&base_value(), &schema()).unwrap();
    let mut child_value = child_value();
    child_value["risk_evidence"] = risk_policy(true, 3, 8_000, 8_000, "all_thresholds");
    let child = validate_value(&child_value, &schema()).unwrap();
    let effective = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap()
        .policy;
    assert_eq!(
        policy_digest(&effective).unwrap(),
        "sha256:e70739ad11a746406e780800075b08f51c73dedd57892ee3a49a6eb4f847b778"
    );
}

#[test]
fn re_protocol_runtime_evidence_is_not_accepted_as_policy() {
    let mut value = child_value();
    value["risk_evidence"] = risk_policy(true, 3, 8_000, 8_000, "all_thresholds");
    value["risk_evidence"]["observed_at_ms"] = json!(123);
    assert!(validate_value(&value, &schema()).is_err());
}

#[test]
fn re_protocol_child_omission_inherits_parent_risk_policy() {
    let mut base = base_value();
    base["risk_evidence"] = risk_policy(true, 3, 8_000, 8_000, "all_thresholds");
    let base = validate_value(&base, &schema()).unwrap();
    let child = validate_value(&child_value(), &schema()).unwrap();
    let effective = PolicyRepository::new([base, child])
        .resolve("hete.verifier.payment")
        .unwrap()
        .policy;
    assert_eq!(effective.risk_evidence.unwrap().minimum_occurrences, 3);
}

#[test]
fn re_protocol_policy_weakening_requires_approved_expansion() {
    let mut base = base_value();
    base["risk_evidence"] = risk_policy(true, 3, 8_000, 8_000, "all_thresholds");
    let base = validate_value(&base, &schema()).unwrap();
    let mut child_value = child_value();
    child_value["risk_evidence"] = risk_policy(true, 2, 7_000, 7_000, "any_threshold");
    let child = validate_value(&child_value, &schema()).unwrap();
    assert!(matches!(
        PolicyRepository::new([base.clone(), child.clone()]).resolve("hete.verifier.payment"),
        Err(PolicyError::PrivilegeExpansion { .. })
    ));

    let mut approved = child;
    approved.privilege_expansion = Some(poa_protocol::PrivilegeExpansion {
        approved: true,
        approval_id: "risk-change-1".into(),
        reason: "reviewed exception".into(),
    });
    let result = PolicyRepository::new([base, approved])
        .resolve("hete.verifier.payment")
        .unwrap();
    assert!(
        result
            .expansion_audit
            .iter()
            .any(|entry| entry == "risk_evidence:weakened")
    );
}
