use poa_protocol::{PolicyRepository, canonicalize, policy_digest, validate_value};
use serde_json::Value;

fn main() {
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
    println!(
        "{}",
        String::from_utf8(canonicalize(&policy).unwrap()).unwrap()
    );
    eprintln!("{}", policy_digest(&policy).unwrap());
}
