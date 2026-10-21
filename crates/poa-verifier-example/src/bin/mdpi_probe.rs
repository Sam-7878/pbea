//! Additive MDPI corpus. Original four-mode records remain immutable.
use anyhow::{Context, bail};
use poa_protocol::{EffectivePolicy, policy_digest};
use poa_sandbox::{OpenBsdBackend, StartupEnforcement};
use poa_verifier_example::{
    Verifier,
    binding::{RuntimePlan, check_identity_contract},
    inventory::Inventory,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    process::Command,
    time::Instant,
};

fn load() -> anyhow::Result<EffectivePolicy> {
    let schema = poa_protocol::load_schema("protocol/schema/poa-protocol-v1.schema.json")?;
    Ok(poa_protocol::load_and_validate(
        "protocol/examples/hete.verifier.pbea-eval.json",
        &schema,
    )?)
}
fn install(policy: &EffectivePolicy) -> anyhow::Result<()> {
    let mut startup = StartupEnforcement::default();
    startup.prepare(&OpenBsdBackend, policy)?;
    let _listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    startup.listener_initialized = true;
    startup.enforce_after_listener(&OpenBsdBackend, policy)?;
    Ok(())
}
fn child(case: &str, mode: &str) -> anyhow::Result<Value> {
    let policy = load()?;
    let digest = policy_digest(&policy)?;
    let mut runtime_policy = policy.clone();
    let mut runtime_id = digest.clone();
    let mut evidence_id = digest.clone();
    let mut request_id = digest.clone();
    if case == "BIND-runtime-epoch" || case == "BIND-inheritance-drift" {
        runtime_policy.version = "2.0.0".into();
        runtime_id = policy_digest(&runtime_policy)?;
    }
    if case == "BIND-stale-evidence" {
        evidence_id = "sha256:stale".into();
    }
    if case == "BIND-request-version" {
        request_id = "sha256:stale".into();
    }
    let bound = mode == "full-pbea";
    let identity_ok =
        check_identity_contract(&request_id, &digest, &runtime_id, &evidence_id).is_ok();
    let plan = RuntimePlan::from_policy(&runtime_policy)?;
    if bound && !identity_ok {
        return Ok(
            json!({"application_outcome":"reject","native_status":"not_installed","identity_consistent":false,"business_entered":false,"domain_changed":false,"runtime_plan":plan}),
        );
    }
    // Explicit TCB counterexample: matching claimed IDs do not attest actual calls.
    if case == "BIND-equal-id-wrong-install" {
        runtime_policy
            .process_constraints
            .unveil_paths
            .push(poa_protocol::UnveilPath {
                path: "/tmp/pbea-eval/outside".into(),
                permissions: "r".into(),
            });
    }
    let mut preopened = if case == "BOUND-preopened-fd" {
        Some(fs::File::open("/tmp/pbea-eval/outside/secret.txt")?)
    } else {
        None
    };
    let listener = if case == "BOUND-send-before-abort" {
        Some(TcpListener::bind((Ipv4Addr::LOCALHOST, 7878))?)
    } else {
        None
    };
    install(&runtime_policy)?;
    let mut state = Inventory::new(10);
    let before = serde_json::to_value(&state)?;
    let mut out = "commit";
    let mut effect = false;
    let mut observer = Value::Null;
    match case {
        "BOUND-send-before-abort" => {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, 7878))?;
            client.write_all(b"synthetic-authorized-effect")?;
            client.shutdown(std::net::Shutdown::Write)?;
            let (mut receiver, _) = listener.unwrap().accept()?;
            let mut received = Vec::new();
            receiver.read_to_end(&mut received)?;
            effect = received == b"synthetic-authorized-effect";
            observer = json!({"receiver_bytes":received.len()});
            out = state.reserve("a", 2, true);
        }
        "BOUND-preopened-fd" => {
            let mut s = String::new();
            preopened.as_mut().unwrap().read_to_string(&mut s)?;
            effect = !s.is_empty();
            observer = json!({"preopened_read":effect,"pathname_read_succeeded":fs::read("/tmp/pbea-eval/outside/secret.txt").is_ok()});
        }
        "BIND-equal-id-wrong-install" => {
            effect = fs::read("/tmp/pbea-eval/outside/secret.txt").is_ok();
        }
        "SERVICE-sequence" => {
            let outcomes = vec![
                state.reserve("a", 6, false),
                state.reserve("b", 5, false),
                state.reserve("a", 1, false),
                state.reserve("b", 2, true),
                state.cancel("a"),
                state.cancel("a"),
            ];
            observer =
                json!({"outcomes":outcomes,"final_state":state,"invariant_holds":state.valid()});
        }
        _ => {
            out = state.reserve("a", 2, false);
        }
    }
    Ok(
        json!({"application_outcome":out,"native_status":"completed","identity_consistent":identity_ok,"business_entered":true,"domain_before":before,"domain_after":state,"domain_changed":before!=serde_json::to_value(&state)?,"effect_succeeded":effect,"effect_observer":observer,"runtime_plan":plan}),
    )
}
fn bench(mode: &str, workload: &str) -> anyhow::Result<Value> {
    let policy = load()?;
    let schema = serde_json::from_slice(&fs::read(
        "protocol/schemas/pbea-eval-transition-request.json",
    )?)?;
    let mut verifier = Verifier::new(policy.clone(), schema)?;
    let size = if workload == "state128" { 128 } else { 1 };
    for i in 0..size {
        verifier
            .domain_state
            .committed_assets
            .insert(format!("asset-{i}"), 100);
    }
    let request = json!({"actor":"ubuntu-ledger-gateway","asset":"asset-0","context":{"request_id":"mdpi-bench","expiry":4102444800_i64,"policy_digest":verifier.policy_digest()},"operation":"verify_transition","payload":{"amount":100,"currency":"USD"}});
    let bytes = serde_json::to_vec(&request)?;
    if mode == "runtime-only" || mode == "full-pbea" || mode == "unbound-composition" {
        install(&policy)?;
    }
    let guarded = mode != "access-only" && mode != "runtime-only";
    let mut samples = Vec::new();
    let mut timer = Vec::new();
    for _ in 0..100 {
        let t = Instant::now();
        std::hint::black_box(());
        timer.push(t.elapsed().as_nanos() as u64);
    }
    for i in 0..600 {
        let t = Instant::now();
        if guarded {
            let result = verifier.process_bytes(&bytes);
            anyhow::ensure!(
                result.outcome.label() == "commit",
                "benign operation failed"
            );
            std::hint::black_box(result);
        } else {
            verifier
                .domain_state
                .committed_assets
                .insert("asset-0".into(), 100);
        }
        if workload == "allowed-io" {
            std::hint::black_box(fs::read("/tmp/pbea-eval/allowed/input.json")?);
        }
        let ns = t.elapsed().as_nanos() as u64;
        if i >= 100 {
            samples.push(ns);
        }
    }
    Ok(
        json!({"mode":mode,"workload":workload,"state_assets":size,"warmup":100,"samples_ns":samples,"timer_empty_ns":timer,"final_state_hash":poa_verifier_example::adversarial::state_hash(&verifier.domain_state),"application_result":"success","functional_amount":verifier.domain_state.committed_assets["asset-0"]}),
    )
}
fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--case") => println!("{}", child(&args[2], &args[3])?),
        Some("--bench") => println!("{}", bench(&args[2], &args[3])?),
        Some("campaign") => {
            let output = args.get(2).context("output directory required")?;
            let source = args.get(3).context("source commit required")?;
            fs::create_dir_all(output)?;
            fs::create_dir_all("/tmp/pbea-eval/allowed")?;
            fs::create_dir_all("/tmp/pbea-eval/outside")?;
            fs::create_dir_all("/tmp/pbea-eval/bin")?;
            fs::create_dir_all("/tmp/pbea-eval/markers")?;
            fs::create_dir_all("/tmp/pbea-eval/logs")?;
            fs::write("/tmp/pbea-eval/allowed/input.json", b"{\"synthetic\":true}")?;
            fs::write("/tmp/pbea-eval/outside/secret.txt", b"synthetic-secret")?;
            let mut raw = fs::File::create(format!("{output}/security.jsonl"))?;
            let exe = std::env::current_exe()?;
            for iteration in 1..=30 {
                for case in [
                    "BIND-aligned",
                    "BIND-runtime-epoch",
                    "BIND-stale-evidence",
                    "BIND-inheritance-drift",
                    "BIND-request-version",
                    "BIND-equal-id-wrong-install",
                    "BOUND-send-before-abort",
                    "BOUND-preopened-fd",
                    "SERVICE-sequence",
                ] {
                    for mode in ["unbound-composition", "full-pbea"] {
                        let result = Command::new(&exe).args(["--case", case, mode]).output()?;
                        let observation: Value = if result.status.success() {
                            serde_json::from_slice(&result.stdout)?
                        } else {
                            json!({"application_outcome":null,"native_status":"child_failed","stderr":String::from_utf8_lossy(&result.stderr),"exit_code":result.status.code()})
                        };
                        let row = json!({"run_id":uuid::Uuid::new_v4(),"source_commit":source,"platform":std::env::consts::OS,"case":case,"mode":mode,"iteration":iteration,"observation":observation,"evidence_origin":"supervisor-child-pipe","scope":"controlled single-worker fixtures"});
                        writeln!(raw, "{row}")?;
                    }
                }
            }
            let mut raw = fs::File::create(format!("{output}/benchmark.jsonl"))?;
            let modes = [
                "access-only",
                "transition-only",
                "runtime-only",
                "full-pbea",
                "unbound-composition",
            ];
            for block in 0..20 {
                for offset in 0..5 {
                    let mode = modes[(offset + block) % 5];
                    for workload in ["state1", "state128", "allowed-io"] {
                        let result = Command::new(&exe)
                            .args(["--bench", mode, workload])
                            .output()?;
                        anyhow::ensure!(
                            result.status.success(),
                            "benchmark child failed: {}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        let observation: Value = serde_json::from_slice(&result.stdout)?;
                        writeln!(
                            raw,
                            "{}",
                            json!({"source_commit":source,"block":block,"observation":observation})
                        )?;
                    }
                }
            }
        }
        _ => bail!("usage: mdpi_probe campaign OUTPUT_DIR SOURCE_COMMIT"),
    }
    Ok(())
}
