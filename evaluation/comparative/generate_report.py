#!/usr/bin/env python3
"""Generate human-readable Markdown evaluation report for 4-mode PBEA evaluation."""
import argparse, json, pathlib

MODES = ("access-only", "transition-only", "runtime-only", "full-pbea")
LABEL = {
    "access-only": "Access-only (B0)",
    "transition-only": "Transition-only (B1)",
    "runtime-only": "Runtime-only (B2)",
    "full-pbea": "Full-PBEA (P)",
}

def percent(value):
    return "N/A" if value is None else f"{100*value:.2f}%"

def interval(metric):
    if metric.get("wilson_95_low") is None:
        return "N/A"
    return f"{100*metric['wilson_95_low']:.2f}%–{100*metric['wilson_95_high']:.2f}%"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("metrics", type=pathlib.Path)
    p.add_argument("output", type=pathlib.Path)
    p.add_argument("--benchmark", type=pathlib.Path)
    p.add_argument("--boundary", type=pathlib.Path)
    a = p.parse_args()

    d = json.loads(a.metrics.read_text())
    lines = [
        "# Comparative Evaluation Report (4-Mode Evaluation)",
        "",
        "All values below are generated from the validated 1080-record JSONL corpus (4 modes × 9 scenarios × 30 iterations).",
        "",
        "## 1. Effect Family Security Metrics Breakdown",
        "",
        "| Effect Family | Metric | Access-only (B0) | Transition-only (B1) | Runtime-only (B2) | Full-PBEA (P) |",
        "|---|---|---:|---:|---:|---:|",
    ]

    fams = [
        ("State Integrity", "S1 Invalid State Rate", "state_integrity", "S1_invalid_state_propagation_rate"),
        ("State Integrity", "S7 Rollback Failure Rate", "state_integrity", "S7_rollback_failure_rate"),
        ("Runtime Confinement", "S2 Filesystem Containment", "runtime_capability_containment", "S2_filesystem_containment"),
        ("Runtime Confinement", "S3 Process Exec Containment", "runtime_capability_containment", "S3_child_execution_containment"),
        ("Runtime Confinement", "S4 Network Containment", "runtime_capability_containment", "S4_network_containment"),
        ("Runtime Confinement", "Aggregate CCR", "runtime_capability_containment", "aggregate_CCR"),
        ("Policy Binding", "S8 Digest Mismatch Accept Rate", "policy_binding", "S8_digest_mismatch_acceptance_rate"),
        ("Fail-Closed Startup", "S5 Malformed Policy FCR", "fail_closed_startup", "S5_malformed_policy_FCR"),
        ("Fail-Closed Startup", "S5 Missing Resource FCR", "fail_closed_startup", "S5_missing_resource_FCR"),
        ("Fail-Closed Startup", "S5 Aggregate FCR", "fail_closed_startup", "S5_aggregate_FCR"),
        ("Outcome Semantics", "S6 Quarantine Rate", "outcome_quarantine_semantics", "S6_quarantine_rate"),
        ("Outcome Semantics", "S7 Abort Rate", "outcome_quarantine_semantics", "S7_abort_rate"),
        ("Benign Preservation", "S0 BRSR", "benign_preservation", "S0_BRSR"),
    ]

    for cat, name, f_key, m_key in fams:
        row_vals = [
            percent(d[m]["effect_families"][f_key][m_key]["rate"])
            for m in MODES
        ]
        lines.append(f"| {cat} | {name} | " + " | ".join(row_vals) + " |")

    lines += [
        "",
        "## 2. Mode-by-Mode Detailed Metrics",
        "",
    ]

    for mode in MODES:
        row = d[mode]
        lines += [
            f"### {LABEL[mode]}",
            "",
            "| Metric | Numerator | Denominator | Rate | Wilson 95% CI |",
            "|---|---:|---:|---:|---:|",
        ]
        for name, m in row["metrics"].items():
            lines.append(f"| {name} | {m['numerator']} | {m['denominator']} | {percent(m['rate'])} | {interval(m)} |")
        x = row["latency_us"]
        lines += [
            "",
            f"**Harness Timing (µs)**: n={x['count']}, min={x['min']}, P50={x['p50']}, P95={x['p95']}, max={x['max']}, mean={x['mean']:.2f}, population σ={x['population_stddev']:.2f}.",
            "",
        ]

    # S0 Steady-state benchmark section if available
    if a.benchmark and a.benchmark.exists():
        bdata = json.loads(a.benchmark.read_text())
        ss = bdata.get("steady_state", {})
        oh = bdata.get("overhead_vs_b0", {})
        lines += [
            "## 3. S0 Steady-State Performance Benchmark",
            "",
            "| Mode | Operations | Min (µs) | P50 (µs) | P95 (µs) | P99 (µs) | P50 Overhead vs B0 | P95 Overhead vs B0 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for mode in MODES:
            s = ss.get(mode, {})
            o = oh.get(mode, {})
            p50_oh = f"{o.get('p50_overhead_pct', 0.0):+.1f}%" if mode != "access-only" else "Baseline"
            p95_oh = f"{o.get('p95_overhead_pct', 0.0):+.1f}%" if mode != "access-only" else "Baseline"
            lines.append(
                f"| {LABEL[mode]} | {s.get('count', 0)} | {s.get('min_us', 0):.2f} | {s.get('p50_us', 0):.2f} | "
                f"{s.get('p95_us', 0):.2f} | {s.get('p99_us', 0):.2f} | {p50_oh} | {p95_oh} |"
            )
        lines.append("")

    # Boundary tests section if available
    if a.boundary and a.boundary.exists():
        bound_data = json.loads(a.boundary.read_text())
        lines += [
            "## 4. Claim-Boundary / Adaptive-Adversary Experiment Results",
            "",
            "| Test ID | Test Name | Mode | Policy Allowed | Succeeded | Observed Outcome | Claim Verification Interpretation |",
            "|---|---|---|:---:|:---:|---|---|",
        ]
        for t in bound_data.get("tests", []):
            lines.append(
                f"| {t['test_id']} | {t['test_name']} | {LABEL.get(t['mode'], t['mode'])} | "
                f"{'Yes' if t['policy_allowed'] else 'No'} | {'Yes' if t['operation_succeeded'] else 'No'} | "
                f"`{t['outcome']}` | {t['claim_verification_interpretation']} |"
            )
        lines.append("")

    a.output.write_text("\n".join(lines).rstrip() + "\n")

if __name__ == "__main__":
    main()
