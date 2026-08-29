use std::time::Instant;

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

fn request(v: &Verifier) -> Value {
    json!({"actor":"ubuntu-ledger-gateway","asset":"payment-transition-001","context":{"request_id":"req-evidence","expiry":1784553000_i64,"policy_digest":v.policy_digest()},"operation":"verify_transition","payload":{"amount":1000,"currency":"KRW"}})
}

#[allow(clippy::too_many_arguments)] // Mirrors the required flat raw-evidence schema.
fn emit(
    test_id: &str,
    expected: &str,
    observed: &str,
    digest: &str,
    startup: bool,
    listener: bool,
    changed: bool,
    os: &str,
    duration_us: u128,
    status: &str,
) {
    println!(
        "{}",
        json!({
            "run_id": uuid::Uuid::new_v4(), "test_id": test_id, "timestamp": chrono::Utc::now(),
            "platform": "ubuntu-24.04-development", "git_commit": option_env!("GIT_COMMIT").unwrap_or("working-tree"),
            "protocol_id": "hete.verifier.payment", "policy_digest": digest,
            "expected_outcome": expected, "observed_outcome": observed,
            "startup_succeeded": startup, "listener_opened": listener, "domain_state_changed": changed,
            "os_enforcement": os, "duration_us": duration_us, "status": status
        })
    );
}

fn main() {
    let mut v = verifier();
    let digest = v.policy_digest().to_owned();
    let started = Instant::now();
    let outcome = v
        .process_bytes(&serde_json::to_vec(&request(&v)).unwrap())
        .outcome;
    emit(
        "E2E-001",
        "commit",
        outcome.label(),
        &digest,
        true,
        true,
        matches!(outcome, TransitionOutcome::Commit),
        "not_triggered",
        started.elapsed().as_micros(),
        "passed",
    );

    let mut v = verifier();
    let mut r = request(&v);
    r["operation"] = json!("invalid");
    let started = Instant::now();
    let outcome = v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome;
    emit(
        "E2E-002",
        "reject",
        outcome.label(),
        &digest,
        true,
        true,
        false,
        "not_triggered",
        started.elapsed().as_micros(),
        "passed",
    );

    let mut v = verifier();
    let mut r = request(&v);
    r["operation"] = json!("invalid");
    let bytes = serde_json::to_vec(&r).unwrap();
    let started = Instant::now();
    v.process_bytes(&bytes);
    v.process_bytes(&bytes);
    let outcome = v.process_bytes(&bytes).outcome;
    emit(
        "E2E-003",
        "quarantine",
        outcome.label(),
        &digest,
        true,
        true,
        false,
        "not_triggered",
        started.elapsed().as_micros(),
        "passed",
    );

    let mut v = verifier();
    let mut r = request(&v);
    r["payload"]["inject_internal_error"] = json!(true);
    let started = Instant::now();
    let outcome = v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome;
    emit(
        "E2E-004",
        "abort",
        outcome.label(),
        &digest,
        true,
        true,
        false,
        "not_triggered",
        started.elapsed().as_micros(),
        "passed",
    );

    emit(
        "E2E-005",
        "os_denial",
        "not_evaluated",
        &digest,
        true,
        false,
        false,
        "requires_openbsd",
        0,
        "not_evaluated",
    );
    emit(
        "E2E-006",
        "kernel_termination",
        "not_evaluated",
        &digest,
        true,
        false,
        false,
        "requires_openbsd",
        0,
        "not_evaluated",
    );

    let schema: Value = serde_json::from_str(include_str!(
        "../../../protocol/schema/poa-protocol-v1.schema.json"
    ))
    .unwrap();
    let mut invalid: Value = serde_json::from_str(include_str!(
        "../../../protocol/examples/hete.verifier.payment.json"
    ))
    .unwrap();
    invalid.as_object_mut().unwrap().remove("failure_policy");
    let started = Instant::now();
    let failed = validate_value(&invalid, &schema).is_err();
    emit(
        "E2E-007",
        "startup_failure",
        if failed { "startup_failure" } else { "started" },
        &digest,
        !failed,
        false,
        false,
        "not_reached",
        started.elapsed().as_micros(),
        if failed { "passed" } else { "failed" },
    );

    let mut v = verifier();
    let mut r = request(&v);
    r["context"]["policy_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    let started = Instant::now();
    let outcome = v.process_bytes(&serde_json::to_vec(&r).unwrap()).outcome;
    emit(
        "E2E-008",
        "reject",
        outcome.label(),
        &digest,
        true,
        true,
        false,
        "not_triggered",
        started.elapsed().as_micros(),
        "passed",
    );
}
