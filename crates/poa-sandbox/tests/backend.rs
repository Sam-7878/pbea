use poa_protocol::{DeploymentMode, OsBackend, ProtocolSpec};
use poa_sandbox::{
    EnforcementError, NoOpDevelopmentBackend, ProcessConstraintBackend, StartupEnforcement,
};

fn policy(mode: DeploymentMode) -> ProtocolSpec {
    serde_json::from_value(serde_json::json!({
      "$schema":"https://schema.hete.io/poa/v1.json","protocol_id":"test","version":"1.0.0","mode": match mode { DeploymentMode::Development => "development", DeploymentMode::Production => "production" },
      "operations":[{"name":"op","allowed_actors":["a"],"required_context":[]}],
      "process_constraints":{"os_backend":"noop","pledge_promises":[],"unveil_paths":[],"lock_after_initialization":true},
      "data_constraints":{"input_schema":"schema.json","maximum_message_bytes":10,"canonical_encoding":"JCS"},
      "failure_policy":{"invalid_request":"reject","policy_violation":"reject","repeated_violation":"quarantine","internal_error":"abort"}
    })).unwrap()
}

#[test]
fn sbox_001_development_noop_is_explicit() {
    let mut state = StartupEnforcement::default();
    state
        .prepare(
            &NoOpDevelopmentBackend,
            &policy(DeploymentMode::Development),
        )
        .unwrap();
    state.listener_initialized = true;
    state
        .enforce_after_listener(
            &NoOpDevelopmentBackend,
            &policy(DeploymentMode::Development),
        )
        .unwrap();
    assert!(state.business_loop_entered);
}

#[test]
fn sbox_007_requires_listener_first() {
    let mut state = StartupEnforcement::default();
    state
        .prepare(
            &NoOpDevelopmentBackend,
            &policy(DeploymentMode::Development),
        )
        .unwrap();
    assert!(
        state
            .enforce_after_listener(
                &NoOpDevelopmentBackend,
                &policy(DeploymentMode::Development)
            )
            .is_err()
    );
    assert!(!state.business_loop_entered);
}

#[test]
fn production_noop_fails_before_business_loop() {
    let mut state = StartupEnforcement::default();
    assert!(matches!(
        state.prepare(&NoOpDevelopmentBackend, &policy(DeploymentMode::Production)),
        Err(EnforcementError::InvalidPolicy(_))
    ));
    assert!(!state.business_loop_entered);
}

#[test]
fn resources_must_be_prepared_before_listener_enforcement() {
    let mut state = StartupEnforcement {
        listener_initialized: true,
        ..Default::default()
    };
    assert!(
        state
            .enforce_after_listener(
                &NoOpDevelopmentBackend,
                &policy(DeploymentMode::Development)
            )
            .is_err()
    );
    assert!(!state.business_loop_entered);
}

#[test]
fn linux_skeleton_compiles_and_refuses_enforcement() {
    let p = policy(DeploymentMode::Development);
    let mut p = p;
    p.process_constraints.os_backend = OsBackend::Linux;
    assert!(poa_sandbox::LinuxBackend.validate_policy(&p).is_err());
}

#[test]
fn policy_cannot_change_between_prepare_and_install() {
    let mut startup = StartupEnforcement::default();
    let first = policy(DeploymentMode::Development);
    startup.prepare(&NoOpDevelopmentBackend, &first).unwrap();
    startup.listener_initialized = true;
    let mut second = first.clone();
    second.version = "2.0.0".into();
    assert!(
        startup
            .enforce_after_listener(&NoOpDevelopmentBackend, &second)
            .is_err()
    );
    assert!(!startup.business_loop_entered);
    assert!(!startup.filesystem_applied);
}
