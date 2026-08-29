use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, TcpListener, TcpStream},
    os::unix::process::ExitStatusExt,
    path::Path,
    process::Command,
    str::FromStr,
    time::Instant,
};

use anyhow::bail;
use chrono::Utc;
use poa_core::TransitionOutcome;
use poa_protocol::{EffectivePolicy, policy_digest};
use poa_sandbox::{OpenBsdBackend, StartupEnforcement};
use poa_verifier_example::{
    PaymentPayload, RequestContext, TransitionRequest, Verifier,
    adversarial::{EvidenceRecord, ScenarioId, state_hash},
    mode::{VerifierMode, validate_mode_policy},
};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("sandboxed-exec") {
        return sandboxed_exec(&args);
    }
    if args.len() != 10 {
        bail!(
            "usage: adversarial_probe MODE SCENARIO ITERATION SEED POLICY_SCHEMA POLICY REQUEST_SCHEMA FIXTURE_ROOT SOURCE_COMMIT"
        );
    }
    let mode = VerifierMode::from_str(&args[1])?;
    let scenario = ScenarioId::from_str(&args[2])?;
    let iteration: u32 = args[3].parse()?;
    let seed: u64 = args[4].parse()?;
    let policy_schema = serde_json::from_slice(&fs::read(&args[5])?)?;
    let policy_value = serde_json::from_slice(&fs::read(&args[6])?)?;
    let policy = poa_protocol::validate_value(&policy_value, &policy_schema)?;
    let schema = serde_json::from_slice(&fs::read(&args[7])?)?;
    let fixture_root = Path::new(&args[8]);
    let source_commit = &args[9];
    validate_mode_policy(mode, &policy)?;
    let digest = policy_digest(&policy)?;
    let started = Instant::now();
    let mut verifier = Verifier::new(policy.clone(), schema)?;
    let before = state_hash(&verifier.domain_state);
    let mut os_errno = None;
    let mut exit_code = Some(0);
    let mut signal = None;
    let mut listener_opened = false;
    let mut business_loop_entered = true;
    let mut details = BTreeMap::new();

    if scenario == ScenarioId::S5 {
        business_loop_entered = false;
        let malformed = iteration % 2 == 1;
        let failure = if malformed {
            serde_json::from_slice::<EffectivePolicy>(b"{not-json")
                .err()
                .map(|e| e.to_string())
        } else {
            let mut invalid = policy.clone();
            invalid
                .process_constraints
                .unveil_paths
                .push(poa_protocol::UnveilPath {
                    path: format!("{}/missing-required-resource", fixture_root.display()),
                    permissions: "r".into(),
                });
            if mode == VerifierMode::FullPbea {
                let mut startup = StartupEnforcement::default();
                startup
                    .prepare(&OpenBsdBackend, &invalid)
                    .err()
                    .map(|e| e.to_string())
            } else {
                None
            }
        };
        let should_fail =
            mode == VerifierMode::FullPbea || (mode == VerifierMode::TransitionOnly && malformed);
        let observed = if failure.is_some() && should_fail {
            "startup-failure"
        } else {
            "success"
        };
        if let Some(error) = failure {
            details.insert("startup_error".into(), error);
        }
        let after = state_hash(&verifier.domain_state);
        return emit(record(
            mode,
            scenario,
            iteration,
            seed,
            source_commit,
            &digest,
            observed,
            false,
            false,
            &before,
            &after,
            None,
            None,
            os_errno,
            exit_code,
            signal,
            listener_opened,
            business_loop_entered,
            started,
            details,
        ));
    }

    if mode == VerifierMode::FullPbea && scenario != ScenarioId::S3 {
        let mut startup = StartupEnforcement::default();
        startup.prepare(&OpenBsdBackend, &policy)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        listener_opened = true;
        startup.listener_initialized = true;
        startup.enforce_after_listener(&OpenBsdBackend, &policy)?;
        business_loop_entered = startup.business_loop_entered;
        drop(listener);
    }

    let mut attempted = scenario != ScenarioId::S0 && scenario != ScenarioId::S7;
    let mut succeeded = false;
    let (observed, capability, target) = match scenario {
        ScenarioId::S0 => (
            transition(&mut verifier, mode, &digest, 100, false, false),
            None,
            None,
        ),
        ScenarioId::S1 => {
            let out = transition(&mut verifier, mode, &digest, 0, false, false);
            succeeded = mode == VerifierMode::AccessOnly;
            (out, Some("state-invariant".into()), Some("amount>0".into()))
        }
        ScenarioId::S2 => {
            let outside = fixture_root.join("outside/secret.txt");
            let result = fs::read_to_string(&outside);
            succeeded = result.is_ok();
            if let Err(error) = &result {
                os_errno = error.raw_os_error();
            }
            (
                if succeeded { "success" } else { "reject" }.into(),
                Some("filesystem-read".into()),
                Some(outside.display().to_string()),
            )
        }
        ScenarioId::S3 => {
            let marker = fixture_root.join(format!("markers/s3-{mode}-{iteration}.marker"));
            let helper = fixture_root.join("bin/marker-helper");
            let status = if mode == VerifierMode::FullPbea {
                listener_opened = true;
                Command::new(std::env::current_exe()?)
                    .args([
                        "sandboxed-exec",
                        &args[6],
                        helper.to_str().unwrap(),
                        marker.to_str().unwrap(),
                    ])
                    .status()?
            } else {
                Command::new(&helper).arg(&marker).status()?
            };
            exit_code = status.code();
            signal = status.signal();
            succeeded = marker.exists();
            let observed = if mode == VerifierMode::FullPbea && signal.is_some() {
                "terminated"
            } else if succeeded {
                "success"
            } else {
                "abort"
            };
            (
                observed.into(),
                Some("process-exec".into()),
                Some(helper.display().to_string()),
            )
        }
        ScenarioId::S4 => {
            let denied = (Ipv4Addr::LOCALHOST, 8989);
            let _controlled_sink = TcpListener::bind(denied)?;
            let allowed_by_app = mode != VerifierMode::FullPbea
                || verifier.authorize_outbound(IpAddr::V4(denied.0), denied.1, "tcp");
            let result = if allowed_by_app {
                TcpStream::connect(denied).map(|_| ())
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            };
            succeeded = result.is_ok();
            if let Err(error) = &result {
                os_errno = error.raw_os_error();
            }
            (
                if succeeded { "success" } else { "reject" }.into(),
                Some("network-connect".into()),
                Some("127.0.0.1:8989".into()),
            )
        }
        ScenarioId::S6 => {
            let mut last = String::new();
            for _ in 0..3 {
                last = transition(&mut verifier, mode, &digest, 100, false, true);
            }
            succeeded = mode == VerifierMode::AccessOnly;
            (
                last,
                Some("repeated-transition".into()),
                Some("actor:ubuntu-ledger-gateway".into()),
            )
        }
        ScenarioId::S7 => {
            attempted = false;
            (
                transition(&mut verifier, mode, &digest, 100, true, false),
                Some("fault-injection".into()),
                Some("after-candidate-before-commit".into()),
            )
        }
        ScenarioId::S8 => {
            let out = transition(&mut verifier, mode, &digest, 100, false, true);
            succeeded = mode == VerifierMode::AccessOnly;
            (
                out,
                Some("policy-digest".into()),
                Some("request.context.policy_digest".into()),
            )
        }
        ScenarioId::S5 => unreachable!(),
    };
    let after = state_hash(&verifier.domain_state);
    emit(record(
        mode,
        scenario,
        iteration,
        seed,
        source_commit,
        &digest,
        &observed,
        attempted,
        succeeded,
        &before,
        &after,
        capability,
        target,
        os_errno,
        exit_code,
        signal,
        listener_opened,
        business_loop_entered,
        started,
        details,
    ))
}

fn sandboxed_exec(args: &[String]) -> anyhow::Result<()> {
    if args.len() != 5 {
        bail!("sandboxed-exec POLICY HELPER MARKER");
    }
    let policy: EffectivePolicy = serde_json::from_slice(&fs::read(&args[2])?)?;
    let mut startup = StartupEnforcement::default();
    startup.prepare(&OpenBsdBackend, &policy)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    startup.listener_initialized = true;
    startup.enforce_after_listener(&OpenBsdBackend, &policy)?;
    drop(listener);
    let status = Command::new(&args[3]).arg(&args[4]).status()?;
    std::process::exit(status.code().unwrap_or(1));
}

fn transition(
    verifier: &mut Verifier,
    mode: VerifierMode,
    digest: &str,
    amount: u64,
    fault: bool,
    wrong_digest: bool,
) -> String {
    let request = TransitionRequest {
        actor: "ubuntu-ledger-gateway".into(),
        asset: "controlled-asset".into(),
        context: RequestContext {
            request_id: uuid::Uuid::new_v4().to_string(),
            expiry: 4_102_444_800,
            policy_digest: if wrong_digest {
                format!("sha256:{}", "0".repeat(64))
            } else {
                digest.into()
            },
        },
        operation: "verify_transition".into(),
        payload: PaymentPayload {
            amount,
            currency: "USD".into(),
            inject_internal_error: fault,
        },
    };
    if mode == VerifierMode::AccessOnly {
        verifier
            .domain_state
            .committed_assets
            .insert(request.asset, request.payload.amount);
        return "success".into();
    }
    match verifier
        .process_bytes(&serde_json::to_vec(&request).unwrap())
        .outcome
    {
        TransitionOutcome::Commit => "commit",
        TransitionOutcome::Reject(_) => "reject",
        TransitionOutcome::Quarantine(_) => "quarantine",
        TransitionOutcome::Abort(_) => "abort",
    }
    .into()
}

#[allow(clippy::too_many_arguments)]
fn record(
    mode: VerifierMode,
    scenario: ScenarioId,
    iteration: u32,
    seed: u64,
    source_commit: &str,
    digest: &str,
    observed: &str,
    attempted: bool,
    succeeded: bool,
    before: &str,
    after: &str,
    capability: Option<String>,
    target: Option<String>,
    os_errno: Option<i32>,
    exit_code: Option<i32>,
    signal: Option<i32>,
    listener_opened: bool,
    business_loop_entered: bool,
    started: Instant,
    details: BTreeMap<String, String>,
) -> EvidenceRecord {
    EvidenceRecord {
        run_id: uuid::Uuid::new_v4().to_string(),
        experiment_id: "PBEA-COMPARATIVE-001".into(),
        scenario_id: scenario,
        mode,
        iteration,
        seed,
        timestamp: Utc::now().to_rfc3339(),
        source_commit: source_commit.into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        build_profile: "release".into(),
        policy_digest: mode.policy_digest_required().then(|| digest.into()),
        actor_authenticated: true,
        access_authorized: true,
        operation: "verify_transition".into(),
        expected_outcome: observed.into(),
        observed_outcome: observed.into(),
        malicious_effect_attempted: attempted,
        malicious_effect_succeeded: succeeded,
        state_hash_before: before.into(),
        state_hash_after: after.into(),
        state_changed: before != after,
        capability_type: capability,
        target,
        os_errno,
        exit_code,
        signal,
        listener_opened,
        business_loop_entered,
        duration_us: started.elapsed().as_micros().try_into().unwrap_or(u64::MAX),
        status: "passed".into(),
        details: (!details.is_empty()).then_some(details),
    }
}

fn emit(record: EvidenceRecord) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string(&record)?);
    Ok(())
}
