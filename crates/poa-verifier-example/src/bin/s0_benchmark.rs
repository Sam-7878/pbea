use std::{
    collections::BTreeMap,
    fs,
    net::{Ipv4Addr, TcpListener},
    path::Path,
    process::Command,
    str::FromStr,
    time::Instant,
};

use anyhow::bail;
use poa_protocol::policy_digest;
use poa_sandbox::{OpenBsdBackend, StartupEnforcement};
use poa_verifier_example::{
    PaymentPayload, RequestContext, TransitionRequest, Verifier,
    mode::{VerifierMode, validate_mode_policy},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub count: usize,
    pub min_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub mean_ns: f64,
    pub stddev_ns: f64,
    pub min_us: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub max_us: f64,
    pub mean_us: f64,
    pub stddev_us: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StartupMeasurement {
    pub mode: String,
    pub policy_parse_ns: u64,
    pub policy_validate_ns: u64,
    pub digest_computation_ns: u64,
    pub sandbox_startup_ns: u64,
    pub total_startup_ns: u64,
    pub total_startup_us: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildBenchResult {
    pub startup: StartupMeasurement,
    pub steady_state: LatencyStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub experiment_id: String,
    pub source_commit: String,
    pub platform: String,
    pub warmup_iterations: usize,
    pub measured_iterations: usize,
    pub batches: usize,
    pub startup: Vec<StartupMeasurement>,
    pub steady_state: BTreeMap<String, LatencyStats>,
    pub overhead_vs_b0: BTreeMap<String, OverheadStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverheadStats {
    pub p50_overhead_pct: f64,
    pub p95_overhead_pct: f64,
    pub p99_overhead_pct: f64,
    pub mean_overhead_pct: f64,
}

fn compute_stats(mut samples: Vec<u64>) -> LatencyStats {
    if samples.is_empty() {
        return LatencyStats {
            count: 0,
            min_ns: 0,
            p50_ns: 0,
            p95_ns: 0,
            p99_ns: 0,
            max_ns: 0,
            mean_ns: 0.0,
            stddev_ns: 0.0,
            min_us: 0.0,
            p50_us: 0.0,
            p95_us: 0.0,
            p99_us: 0.0,
            max_us: 0.0,
            mean_us: 0.0,
            stddev_us: 0.0,
        };
    }
    samples.sort_unstable();
    let count = samples.len();
    let min_ns = samples[0];
    let max_ns = samples[count - 1];
    let p50_ns = samples[count * 50 / 100];
    let p95_ns = samples[count * 95 / 100];
    let p99_ns = samples[count * 99 / 100];
    let sum: u64 = samples.iter().sum();
    let mean_ns = sum as f64 / count as f64;
    let variance = samples
        .iter()
        .map(|&v| {
            let diff = v as f64 - mean_ns;
            diff * diff
        })
        .sum::<f64>()
        / count as f64;
    let stddev_ns = variance.sqrt();

    LatencyStats {
        count,
        min_ns,
        p50_ns,
        p95_ns,
        p99_ns,
        max_ns,
        mean_ns,
        stddev_ns,
        min_us: min_ns as f64 / 1000.0,
        p50_us: p50_ns as f64 / 1000.0,
        p95_us: p95_ns as f64 / 1000.0,
        p99_us: p99_ns as f64 / 1000.0,
        max_us: max_ns as f64 / 1000.0,
        mean_us: mean_ns / 1000.0,
        stddev_us: stddev_ns / 1000.0,
    }
}

fn run_child_bench(args: &[String]) -> anyhow::Result<()> {
    if args.len() < 9 {
        bail!(
            "usage: --bench-child MODE POLICY_SCHEMA POLICY REQUEST_SCHEMA SOURCE_COMMIT WARMUP MEASURED BATCHES"
        );
    }
    let mode = VerifierMode::from_str(&args[2])?;
    let policy_schema_bytes = fs::read(&args[3])?;
    let policy_bytes = fs::read(&args[4])?;
    let request_schema_bytes = fs::read(&args[5])?;
    let warmup_count: usize = args[7].parse()?;
    let measured_count: usize = args[8].parse()?;
    let batches: usize = args[9].parse()?;

    let policy_schema: serde_json::Value = serde_json::from_slice(&policy_schema_bytes)?;
    let request_schema: serde_json::Value = serde_json::from_slice(&request_schema_bytes)?;

    // 1. Startup measurement
    let t0 = Instant::now();
    let policy_value: serde_json::Value = serde_json::from_slice(&policy_bytes)?;
    let t1 = Instant::now();
    let policy = poa_protocol::validate_value(&policy_value, &policy_schema)?;
    let t2 = Instant::now();
    let digest = policy_digest(&policy)?;
    let t3 = Instant::now();

    validate_mode_policy(mode, &policy)?;

    let mut sandbox_startup_ns = 0;
    if mode.runtime_constraints_enabled() {
        let sb_start = Instant::now();
        let mut startup = StartupEnforcement::default();
        startup.prepare(&OpenBsdBackend, &policy)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        startup.listener_initialized = true;
        startup.enforce_after_listener(&OpenBsdBackend, &policy)?;
        drop(listener);
        sandbox_startup_ns = sb_start.elapsed().as_nanos() as u64;
    }
    let total_startup_ns = t0.elapsed().as_nanos() as u64;

    let startup = StartupMeasurement {
        mode: mode.to_string(),
        policy_parse_ns: (t1 - t0).as_nanos() as u64,
        policy_validate_ns: (t2 - t1).as_nanos() as u64,
        digest_computation_ns: (t3 - t2).as_nanos() as u64,
        sandbox_startup_ns,
        total_startup_ns,
        total_startup_us: total_startup_ns as f64 / 1000.0,
    };

    // 2. Steady-State S0 Execution
    let mut verifier = Verifier::new(policy.clone(), request_schema.clone())?;
    let sample_request = TransitionRequest {
        actor: "ubuntu-ledger-gateway".into(),
        asset: "benchmark-asset".into(),
        context: RequestContext {
            request_id: "bench-req-001".into(),
            expiry: 4_102_444_800,
            policy_digest: digest.clone(),
        },
        operation: "verify_transition".into(),
        payload: PaymentPayload {
            amount: 100,
            currency: "USD".into(),
            inject_internal_error: false,
        },
    };
    let request_bytes = serde_json::to_vec(&sample_request)?;

    // Warmup phase
    for _ in 0..warmup_count {
        if mode.transition_guards_enabled() {
            let _ = verifier.process_bytes(&request_bytes);
        } else {
            verifier
                .domain_state
                .committed_assets
                .insert(sample_request.asset.clone(), 100);
        }
    }

    // Measured phase
    let mut all_latencies = Vec::with_capacity(batches * measured_count);
    for _ in 0..batches {
        for _ in 0..measured_count {
            let op_start = Instant::now();
            if mode.transition_guards_enabled() {
                let _ = verifier.process_bytes(&request_bytes);
            } else {
                verifier
                    .domain_state
                    .committed_assets
                    .insert(sample_request.asset.clone(), 100);
            }
            all_latencies.push(op_start.elapsed().as_nanos() as u64);
        }
    }

    let steady_state = compute_stats(all_latencies);
    let child_res = ChildBenchResult {
        startup,
        steady_state,
    };
    println!("{}", serde_json::to_string(&child_res)?);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--bench-child") {
        return run_child_bench(&args);
    }
    if args.len() < 7 {
        bail!(
            "usage: s0_benchmark POLICY_SCHEMA POLICY REQUEST_SCHEMA FIXTURE_ROOT SOURCE_COMMIT OUTPUT_JSON [WARMUP] [MEASURED] [BATCHES]"
        );
    }
    let policy_schema = &args[1];
    let policy = &args[2];
    let request_schema = &args[3];
    let _fixture_root = Path::new(&args[4]);
    let source_commit = &args[5];
    let output_path = Path::new(&args[6]);
    let warmup_count: usize = args.get(7).and_then(|s| s.parse().ok()).unwrap_or(100);
    let measured_count: usize = args.get(8).and_then(|s| s.parse().ok()).unwrap_or(1000);
    let batches: usize = args.get(9).and_then(|s| s.parse().ok()).unwrap_or(5);

    let current_exe = std::env::current_exe()?;
    let mut startup_measurements = Vec::new();
    let mut steady_state_results = BTreeMap::new();

    for &mode in &VerifierMode::ALL {
        let child_output = Command::new(&current_exe)
            .args([
                "--bench-child",
                &mode.to_string(),
                policy_schema,
                policy,
                request_schema,
                source_commit,
                &warmup_count.to_string(),
                &measured_count.to_string(),
                &batches.to_string(),
            ])
            .output()?;

        if !child_output.status.success() {
            let stderr = String::from_utf8_lossy(&child_output.stderr);
            bail!("Child bench failed for mode {mode}: {stderr}");
        }

        let stdout_str = String::from_utf8_lossy(&child_output.stdout);
        let child_res: ChildBenchResult = serde_json::from_str(stdout_str.trim())?;
        startup_measurements.push(child_res.startup);
        steady_state_results.insert(mode.to_string(), child_res.steady_state);
    }

    // Compute overhead vs B0
    let b0_stats = steady_state_results
        .get("access-only")
        .cloned()
        .unwrap_or_else(|| compute_stats(vec![1]));

    let mut overhead_map = BTreeMap::new();
    for (mode_name, stats) in &steady_state_results {
        let p50_oh = if b0_stats.p50_ns > 0 {
            (stats.p50_ns as f64 - b0_stats.p50_ns as f64) / b0_stats.p50_ns as f64 * 100.0
        } else {
            0.0
        };
        let p95_oh = if b0_stats.p95_ns > 0 {
            (stats.p95_ns as f64 - b0_stats.p95_ns as f64) / b0_stats.p95_ns as f64 * 100.0
        } else {
            0.0
        };
        let p99_oh = if b0_stats.p99_ns > 0 {
            (stats.p99_ns as f64 - b0_stats.p99_ns as f64) / b0_stats.p99_ns as f64 * 100.0
        } else {
            0.0
        };
        let mean_oh = if b0_stats.mean_ns > 0.0 {
            (stats.mean_ns - b0_stats.mean_ns) / b0_stats.mean_ns * 100.0
        } else {
            0.0
        };
        overhead_map.insert(
            mode_name.clone(),
            OverheadStats {
                p50_overhead_pct: p50_oh,
                p95_overhead_pct: p95_oh,
                p99_overhead_pct: p99_oh,
                mean_overhead_pct: mean_oh,
            },
        );
    }

    let report = BenchmarkReport {
        experiment_id: "PBEA-BENCHMARK-S0-001".into(),
        source_commit: source_commit.into(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        warmup_iterations: warmup_count,
        measured_iterations: measured_count * batches,
        batches,
        startup: startup_measurements,
        steady_state: steady_state_results,
        overhead_vs_b0: overhead_map,
    };

    let serialized = serde_json::to_string_pretty(&report)?;
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output_path, &serialized)?;
    println!("{serialized}");
    Ok(())
}
