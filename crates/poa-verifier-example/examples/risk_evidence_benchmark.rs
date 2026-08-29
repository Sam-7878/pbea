use std::hint::black_box;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use poa_core::{
    BasisPoints, CorrelationId, EvidenceAggregation, EvidenceDecision, EvidenceSource,
    QuarantinePolicy, RiskCategory, RiskEvidence, evaluate_evidence,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const RUNS: u32 = 30;
const INNER_ITERATIONS: u32 = 100_000;
const WARMUP_ITERATIONS: u32 = 20_000;

#[derive(Clone, Copy)]
struct LabelledEvidence {
    occurrences: u32,
    severity: u16,
    confidence: u16,
    should_quarantine: bool,
}

const CORPUS: [LabelledEvidence; 16] = [
    LabelledEvidence {
        occurrences: 1,
        severity: 4_000,
        confidence: 4_000,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 1,
        severity: 9_500,
        confidence: 4_500,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 2,
        severity: 6_000,
        confidence: 6_000,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 3,
        severity: 6_500,
        confidence: 8_500,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 5,
        severity: 4_500,
        confidence: 9_000,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 2,
        severity: 7_500,
        confidence: 7_500,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 3,
        severity: 7_900,
        confidence: 7_900,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 5,
        severity: 8_500,
        confidence: 5_500,
        should_quarantine: false,
    },
    LabelledEvidence {
        occurrences: 2,
        severity: 8_500,
        confidence: 8_500,
        should_quarantine: true,
    },
    LabelledEvidence {
        occurrences: 3,
        severity: 8_000,
        confidence: 8_000,
        should_quarantine: true,
    },
    LabelledEvidence {
        occurrences: 3,
        severity: 9_000,
        confidence: 8_500,
        should_quarantine: true,
    },
    LabelledEvidence {
        occurrences: 5,
        severity: 7_500,
        confidence: 9_000,
        should_quarantine: true,
    },
    LabelledEvidence {
        occurrences: 5,
        severity: 9_000,
        confidence: 7_500,
        should_quarantine: true,
    },
    LabelledEvidence {
        occurrences: 5,
        severity: 9_500,
        confidence: 9_500,
        should_quarantine: true,
    },
    LabelledEvidence {
        occurrences: 2,
        severity: 9_500,
        confidence: 9_500,
        should_quarantine: true,
    },
    LabelledEvidence {
        occurrences: 3,
        severity: 8_500,
        confidence: 9_500,
        should_quarantine: true,
    },
];

fn bps(value: u16) -> BasisPoints {
    BasisPoints::new(value).expect("bounded benchmark input")
}

fn evidence(item: LabelledEvidence, correlation: &str) -> RiskEvidence {
    RiskEvidence::new(
        RiskCategory::AnomalySignal,
        bps(item.severity),
        bps(item.confidence),
        item.occurrences,
        EvidenceSource::PatternDetector,
        1_751_234_567_890,
        CorrelationId::new(correlation).expect("valid benchmark correlation"),
    )
    .expect("valid benchmark evidence")
}

fn policy(enabled: bool, occurrences: u32, severity: u16, confidence: u16) -> QuarantinePolicy {
    QuarantinePolicy::new(
        enabled,
        occurrences,
        bps(severity),
        bps(confidence),
        EvidenceAggregation::AllThresholds,
    )
    .expect("valid benchmark policy")
}

fn timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_millis()
}

fn digest(policy: &QuarantinePolicy) -> String {
    let bytes = serde_json::to_vec(policy).expect("serializable policy");
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn base(experiment_id: &str, test_id: &str, policy: &QuarantinePolicy) -> Value {
    json!({
        "experiment_id": experiment_id,
        "test_id": test_id,
        "git_commit": option_env!("GIT_COMMIT").unwrap_or("uncommitted"),
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        "rust_version": option_env!("RUST_VERSION").unwrap_or("recorded-in-environment-manifest"),
        "build_profile": "release",
        "policy_id": "risk-evidence-benchmark-v1",
        "policy_digest": digest(policy),
        "category": "anomaly_signal",
        "source": "pattern_detector",
        "timestamp": timestamp_ms(),
    })
}

fn print_json(mut base: Value, fields: Value) {
    base.as_object_mut()
        .expect("object")
        .extend(fields.as_object().expect("object").clone());
    println!("{}", serde_json::to_string(&base).expect("JSON output"));
}

fn overhead() {
    let cases = [
        (
            "disabled",
            policy(false, 3, 8_000, 8_000),
            evidence(CORPUS[13], "bench-disabled"),
        ),
        (
            "insufficient",
            policy(true, 3, 8_000, 8_000),
            evidence(CORPUS[2], "bench-insufficient"),
        ),
        (
            "quarantine",
            policy(true, 3, 8_000, 8_000),
            evidence(CORPUS[13], "bench-quarantine"),
        ),
    ];
    for (_, policy, evidence) in &cases {
        for _ in 0..WARMUP_ITERATIONS {
            black_box(evaluate_evidence(black_box(evidence), black_box(policy)));
        }
    }
    for (case, policy, evidence) in &cases {
        for run_id in 1..=RUNS {
            let started = Instant::now();
            for _ in 0..INNER_ITERATIONS {
                black_box(evaluate_evidence(black_box(evidence), black_box(policy)));
            }
            let latency = started.elapsed().as_nanos() as f64 / f64::from(INNER_ITERATIONS);
            print_json(
                base("B-RE1", &format!("B-RE1-{case}"), policy),
                json!({
                    "run_id": run_id, "case": case, "warmup_iterations": WARMUP_ITERATIONS,
                    "inner_iterations": INNER_ITERATIONS, "occurrences": evidence.occurrences(),
                    "severity_bps": evidence.severity().value(), "confidence_bps": evidence.confidence().value(),
                    "decision": match evaluate_evidence(evidence, policy) {
                        EvidenceDecision::ExtensionDisabled => "extension_disabled",
                        EvidenceDecision::Insufficient { .. } => "insufficient",
                        EvidenceDecision::Quarantine { .. } => "quarantine",
                    },
                    "latency_ns": latency
                }),
            );
        }
    }
    let fixed = policy(true, 3, 8_000, 8_000);
    print_json(
        base("B-RE3", "B-RE3-fixed-comparisons", &fixed),
        json!({
            "run_id": 1, "occurrences": 3, "severity_bps": 8000, "confidence_bps": 8000,
            "decision": "three_scalar_comparisons", "latency_ns": null,
            "statement": "The evaluator performs a fixed number of scalar threshold comparisons for a single RiskEvidence record."
        }),
    );
}

fn ratio(numerator: u32, denominator: u32) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        f64::from(numerator) / f64::from(denominator)
    }
}

fn sensitivity() {
    let mut run_id = 0;
    for occurrences in [1, 2, 3, 5] {
        for severity in [5_000, 7_000, 8_000, 9_000] {
            for confidence in [5_000, 7_000, 8_000, 9_000] {
                run_id += 1;
                let policy = policy(true, occurrences, severity, confidence);
                let (mut tp, mut fp, mut tn, mut fn_count) = (0, 0, 0, 0);
                for (index, item) in CORPUS.iter().copied().enumerate() {
                    let predicted = matches!(
                        evaluate_evidence(&evidence(item, &format!("corpus-{index:02}")), &policy),
                        EvidenceDecision::Quarantine { .. }
                    );
                    match (item.should_quarantine, predicted) {
                        (true, true) => tp += 1,
                        (false, true) => fp += 1,
                        (false, false) => tn += 1,
                        (true, false) => fn_count += 1,
                    }
                }
                let precision = ratio(tp, tp + fp);
                let recall = ratio(tp, tp + fn_count);
                let f1 = if precision + recall == 0.0 {
                    0.0
                } else {
                    2.0 * precision * recall / (precision + recall)
                };
                print_json(
                    base("B-RE2", "B-RE2-synthetic-grid", &policy),
                    json!({
                        "run_id": run_id, "occurrences": occurrences, "severity_bps": severity,
                        "confidence_bps": confidence, "decision": "aggregate", "latency_ns": null,
                        "dataset_id": "synthetic-risk-corpus-v1", "dataset_count": CORPUS.len(),
                        "true_positive": tp, "false_positive": fp, "true_negative": tn, "false_negative": fn_count,
                        "true_quarantine_rate": ratio(tp, tp + fn_count), "false_quarantine_rate": ratio(fp, fp + tn),
                        "missed_containment_rate": ratio(fn_count, tp + fn_count), "precision": precision,
                        "recall": recall, "f1": f1, "quarantine_count": tp + fp, "reject_count": tn + fn_count
                    }),
                );
            }
        }
    }
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("overhead") => overhead(),
        Some("sensitivity") => sensitivity(),
        _ => {
            eprintln!("usage: risk_evidence_benchmark <overhead|sensitivity>");
            std::process::exit(2);
        }
    }
}
