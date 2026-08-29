use std::net::TcpListener;
use std::time::Instant;

use poa_protocol::{
    DeploymentMode, OsBackend, PolicyRepository, canonicalize, policy_digest, validate_value,
};
use poa_sandbox::{NoOpDevelopmentBackend, StartupEnforcement};
use serde_json::{Value, json};

fn main() {
    for iteration in 0..20 {
        let total = Instant::now();
        let started = Instant::now();
        let schema: Value = serde_json::from_str(include_str!(
            "../../../protocol/schema/poa-protocol-v1.schema.json"
        ))
        .unwrap();
        let base_value: Value = serde_json::from_str(include_str!(
            "../../../protocol/base/hete.base.verifier.json"
        ))
        .unwrap();
        let child_value: Value = serde_json::from_str(include_str!(
            "../../../protocol/examples/hete.verifier.payment.json"
        ))
        .unwrap();
        let t_parse = started.elapsed().as_micros();

        let started = Instant::now();
        let mut base = validate_value(&base_value, &schema).unwrap();
        let mut child = validate_value(&child_value, &schema).unwrap();
        let t_schema = started.elapsed().as_micros();
        base.mode = DeploymentMode::Development;
        base.process_constraints.os_backend = OsBackend::Noop;
        child.mode = DeploymentMode::Development;
        child.process_constraints.os_backend = OsBackend::Noop;

        let started = Instant::now();
        let effective = PolicyRepository::new([base, child])
            .resolve("hete.verifier.payment")
            .unwrap()
            .policy;
        let t_inheritance = started.elapsed().as_micros();
        let started = Instant::now();
        let _canonical = canonicalize(&effective).unwrap();
        let t_canonicalize = started.elapsed().as_micros();
        let started = Instant::now();
        let digest = policy_digest(&effective).unwrap();
        let t_digest = started.elapsed().as_micros();

        let started = Instant::now();
        let mut enforcement = StartupEnforcement::default();
        enforcement
            .prepare(&NoOpDevelopmentBackend, &effective)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        enforcement.listener_initialized = true;
        enforcement
            .enforce_after_listener(&NoOpDevelopmentBackend, &effective)
            .unwrap();
        drop(listener);
        let t_sandbox = started.elapsed().as_micros();
        println!(
            "{}",
            json!({
                "iteration":iteration,"platform":"ubuntu-24.04-noop-development","cache":"warm_unspecified",
                "policy_digest":digest,"t_parse_us":t_parse,"t_schema_us":t_schema,"t_inheritance_us":t_inheritance,
                "t_canonicalize_us":t_canonicalize,"t_digest_us":t_digest,"t_sandbox_us":t_sandbox,
                "t_total_startup_us":total.elapsed().as_micros(),"security_evidence":false
            })
        );
    }
}
