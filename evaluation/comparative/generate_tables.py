#!/usr/bin/env python3
"""Generate LaTeX tables and CSV summaries for 4-mode PBEA evaluation."""
import argparse, json, pathlib

LABEL = {
    "access-only": "Access-only (B0)",
    "transition-only": "Transition-only (B1)",
    "runtime-only": "Runtime-only (B2)",
    "full-pbea": "Full-PBEA (P)",
}
MODES = ("access-only", "transition-only", "runtime-only", "full-pbea")

def pct(x):
    return "--" if x is None else f"{100*x:.1f}\\%"

def pct_csv(x):
    return "" if x is None else f"{100*x:.1f}%"

def ci(m):
    if m.get("wilson_95_low") is None or m.get("wilson_95_high") is None:
        return "--"
    return f"[{100*m['wilson_95_low']:.1f}, {100*m['wilson_95_high']:.1f}]"

def main():
    p = argparse.ArgumentParser()
    p.add_argument("metrics", type=pathlib.Path)
    p.add_argument("output", type=pathlib.Path)
    p.add_argument("--benchmark", type=pathlib.Path, help="Optional s0_benchmark.json")
    p.add_argument("--boundary", type=pathlib.Path, help="Optional boundary_results.json")
    a = p.parse_args()

    data = json.loads(a.metrics.read_text())
    a.output.mkdir(parents=True, exist_ok=True)

    # 1. Comparative Security Aggregate Table (LaTeX & CSV)
    lines = [
        r"\begin{tabular}{lrrrrrr}",
        r"\toprule",
        r"Mode & MESR & BRSR & SIVR & CER & FCR & OCA \\",
        r"\midrule",
    ]
    csv_rows = [["Mode", "MESR", "BRSR", "SIVR", "CER", "FCR", "OCA"]]
    for mode in MODES:
        row = data[mode]
        m = row["metrics"]
        lines.append(
            LABEL[mode]
            + " & "
            + " & ".join(pct(m[k]["rate"]) for k in ("MESR", "BRSR", "SIVR", "CER", "FCR", "OCA"))
            + r" \\"
        )
        csv_rows.append([LABEL[mode]] + [pct_csv(m[k]["rate"]) for k in ("MESR", "BRSR", "SIVR", "CER", "FCR", "OCA")])
    lines += [r"\bottomrule", r"\end{tabular}"]
    (a.output / "comparative_security.tex").write_text("\n".join(lines) + "\n")
    (a.output / "aggregate_metrics.csv").write_text("\n".join(",".join(r) for r in csv_rows) + "\n")

    # 2. Detailed Security Metrics with Wilson CI (LaTeX)
    lines = [
        r"\begin{tabular}{llrrl}",
        r"\toprule",
        r"Mode & Metric & Numerator & Denominator & Wilson 95\% CI (\%) \\",
        r"\midrule",
    ]
    for mode in MODES:
        row = data[mode]
        for name, m in row["metrics"].items():
            lines.append(
                f"{LABEL[mode]} & {name} & {m['numerator']} & {m['denominator']} & {ci(m)} \\\\"
            )
    lines += [r"\bottomrule", r"\end{tabular}"]
    (a.output / "security_metrics.tex").write_text("\n".join(lines) + "\n")

    # 3. Effect Family Metrics (LaTeX & CSV)
    lines = [
        r"\begin{tabular}{lcccc}",
        r"\toprule",
        r"Effect Family & Access-only (B0) & Transition-only (B1) & Runtime-only (B2) & Full-PBEA (P) \\",
        r"\midrule",
    ]
    fam_csv = [["Effect Family", "Metric", "B0 Access-only", "B1 Transition-only", "B2 Runtime-only", "P Full-PBEA"]]

    # F1: State Integrity
    s1_vals = [pct(data[m]["effect_families"]["state_integrity"]["S1_invalid_state_propagation_rate"]["rate"]) for m in MODES]
    lines.append(r"\textbf{State Integrity} (S1 Invalid State Rate) & " + " & ".join(s1_vals) + r" \\")
    fam_csv.append(["State Integrity", "S1 Invalid State Rate"] + [pct_csv(data[m]["effect_families"]["state_integrity"]["S1_invalid_state_propagation_rate"]["rate"]) for m in MODES])

    # F2: Capability Containment
    s2_vals = [pct(data[m]["effect_families"]["runtime_capability_containment"]["S2_filesystem_containment"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Runtime Confinement} (S2 Filesystem Containment) & " + " & ".join(s2_vals) + r" \\")
    fam_csv.append(["Runtime Confinement", "S2 Filesystem Containment"] + [pct_csv(data[m]["effect_families"]["runtime_capability_containment"]["S2_filesystem_containment"]["rate"]) for m in MODES])

    s3_vals = [pct(data[m]["effect_families"]["runtime_capability_containment"]["S3_child_execution_containment"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Runtime Confinement} (S3 Process Exec Containment) & " + " & ".join(s3_vals) + r" \\")
    fam_csv.append(["Runtime Confinement", "S3 Process Exec Containment"] + [pct_csv(data[m]["effect_families"]["runtime_capability_containment"]["S3_child_execution_containment"]["rate"]) for m in MODES])

    s4_vals = [pct(data[m]["effect_families"]["runtime_capability_containment"]["S4_network_containment"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Runtime Confinement} (S4 Egress Containment) & " + " & ".join(s4_vals) + r" \\")
    fam_csv.append(["Runtime Confinement", "S4 Egress Containment"] + [pct_csv(data[m]["effect_families"]["runtime_capability_containment"]["S4_network_containment"]["rate"]) for m in MODES])

    ccr_vals = [pct(data[m]["effect_families"]["runtime_capability_containment"]["aggregate_CCR"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Runtime Confinement} (Aggregate CCR S2--S4) & " + " & ".join(ccr_vals) + r" \\")
    fam_csv.append(["Runtime Confinement", "Aggregate CCR S2-S4"] + [pct_csv(data[m]["effect_families"]["runtime_capability_containment"]["aggregate_CCR"]["rate"]) for m in MODES])

    # F3: Policy Binding
    s8_vals = [pct(data[m]["effect_families"]["policy_binding"]["S8_digest_mismatch_acceptance_rate"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Policy Binding} (S8 Digest Mismatch Accept Rate) & " + " & ".join(s8_vals) + r" \\")
    fam_csv.append(["Policy Binding", "S8 Digest Mismatch Accept Rate"] + [pct_csv(data[m]["effect_families"]["policy_binding"]["S8_digest_mismatch_acceptance_rate"]["rate"]) for m in MODES])

    # F4: Fail-closed Startup
    fcr_vals = [pct(data[m]["effect_families"]["fail_closed_startup"]["S5_aggregate_FCR"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Fail-Closed Startup} (S5 Aggregate FCR) & " + " & ".join(fcr_vals) + r" \\")
    fam_csv.append(["Fail-Closed Startup", "S5 Aggregate FCR"] + [pct_csv(data[m]["effect_families"]["fail_closed_startup"]["S5_aggregate_FCR"]["rate"]) for m in MODES])

    # F5: Outcome Quarantine
    s6_vals = [pct(data[m]["effect_families"]["outcome_quarantine_semantics"]["S6_quarantine_rate"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Outcome Semantics} (S6 Quarantine Rate) & " + " & ".join(s6_vals) + r" \\")
    fam_csv.append(["Outcome Semantics", "S6 Quarantine Rate"] + [pct_csv(data[m]["effect_families"]["outcome_quarantine_semantics"]["S6_quarantine_rate"]["rate"]) for m in MODES])

    # F6: Benign Preservation
    s0_vals = [pct(data[m]["effect_families"]["benign_preservation"]["S0_BRSR"]["rate"]) for m in MODES]
    lines.append(r"\textbf{Benign Preservation} (S0 BRSR) & " + " & ".join(s0_vals) + r" \\")
    fam_csv.append(["Benign Preservation", "S0 BRSR"] + [pct_csv(data[m]["effect_families"]["benign_preservation"]["S0_BRSR"]["rate"]) for m in MODES])

    lines += [r"\bottomrule", r"\end{tabular}"]
    (a.output / "family_metrics.tex").write_text("\n".join(lines) + "\n")
    (a.output / "family_metrics.csv").write_text("\n".join(",".join(r) for r in fam_csv) + "\n")

    # 4. Scenario Matrix (LaTeX & CSV)
    scen_csv = [["Scenario", "Description", "B0 Access-only", "B1 Transition-only", "B2 Runtime-only", "P Full-PBEA"]]
    scen_lines = [
        r"\begin{tabular}{llcccc}",
        r"\toprule",
        r"ID & Scenario Description & B0 & B1 & B2 & P \\",
        r"\midrule",
    ]
    scen_desc = {
        "S0": "Benign authorized operation",
        "S1": "Post-authorization invariant violation",
        "S2": "File read outside unveiled path",
        "S3": "Undeclared helper execution",
        "S4": "Disallowed loopback connect",
        "S5": "Invalid startup / missing resource",
        "S6": "Repeated policy violation",
        "S7": "Failure after candidate creation",
        "S8": "Mismatched effective policy digest",
    }
    for s_id, desc in scen_desc.items():
        row_tex = []
        row_c = [s_id, desc]
        for m in MODES:
            bd = data[m].get("scenario_breakdown", {}).get(s_id, {})
            succ = bd.get("malicious_succeeded", 0)
            tot = bd.get("total", 30)
            outs = bd.get("observed_outcomes", {})
            main_out = max(outs.items(), key=lambda x: x[1])[0] if outs else "?"
            row_tex.append(f"{main_out} ({succ}/{tot})")
            row_c.append(f"{main_out} ({succ}/{tot})")
        scen_lines.append(f"{s_id} & {desc} & " + " & ".join(row_tex) + r" \\")
        scen_csv.append(row_c)
    scen_lines += [r"\bottomrule", r"\end{tabular}"]
    (a.output / "scenario_matrix.tex").write_text("\n".join(scen_lines) + "\n")
    (a.output / "scenario_matrix.csv").write_text("\n".join(",".join(r) for r in scen_csv) + "\n")

    # 5. Harness/Mixed Diagnostic Latency Table (LaTeX)
    lines = [
        r"\begin{tabular}{lrrrrrrr}",
        r"\toprule",
        r"Mode & n & Min & P50 & P95 & Max & Mean & $\sigma$ \\",
        r"\midrule",
    ]
    for mode in MODES:
        row = data[mode]
        x = row["latency_us"]
        lines.append(
            f"{LABEL[mode]} & {x['count']} & {x['min']} & {x['p50']} & {x['p95']} & {x['max']} & {x['mean']:.1f} & {x['population_stddev']:.1f} \\\\"
        )
    lines += [r"\bottomrule", r"\end{tabular}"]
    (a.output / "overhead.tex").write_text("\n".join(lines) + "\n")

    # 6. Attack Mechanisms Table
    (a.output / "attack_mechanisms.tex").write_text(
        r"""\begin{tabular}{lll}
\toprule
Scenario & Full-PBEA Control Layer & Observable Evidence \\
\midrule
S1, S6, S8 & Transition Policy (AACO Kernel) & Reject/Quarantine with deterministic audit hash \\
S2 & OpenBSD unveil(2) & Filesystem read denied with native OS errno (ENOENT) \\
S3 & OpenBSD pledge(2) & Child execution killed via termination signal (SIGABRT/SIGKILL) \\
S4 & Application Endpoint Allowlist & Socket connection denied before network dispatch \\
S5 & Fail-Closed Startup Enforcement & Protected business loop not entered on malformed policy/resource \\
S7 & Candidate/Commit Isolation & Abort with unchanged domain state hash \\
\bottomrule
\end{tabular}
"""
    )

    # 7. S0 Steady-State Benchmark Tables (if benchmark json provided)
    if a.benchmark and a.benchmark.exists():
        bdata = json.loads(a.benchmark.read_text())
        ss = bdata["steady_state"]
        oh = bdata.get("overhead_vs_b0", {})

        s0_lines = [
            r"\begin{tabular}{lrrrrrcc}",
            r"\toprule",
            r"Mode & n & Min ($\mu$s) & P50 ($\mu$s) & P95 ($\mu$s) & P99 ($\mu$s) & P50 Overhead & P95 Overhead \\",
            r"\midrule",
        ]
        s0_csv = [["Mode", "n", "Min_us", "P50_us", "P95_us", "P99_us", "P50_Overhead_pct", "P95_Overhead_pct"]]
        for mode in MODES:
            s = ss.get(mode, {})
            o = oh.get(mode, {})
            p50_oh_str = f"{o.get('p50_overhead_pct', 0.0):+.1f}\\%" if mode != "access-only" else "Baseline"
            p95_oh_str = f"{o.get('p95_overhead_pct', 0.0):+.1f}\\%" if mode != "access-only" else "Baseline"
            s0_lines.append(
                f"{LABEL[mode]} & {s.get('count',0)} & {s.get('min_us',0):.2f} & {s.get('p50_us',0):.2f} & "
                f"{s.get('p95_us',0):.2f} & {s.get('p99_us',0):.2f} & {p50_oh_str} & {p95_oh_str} \\\\"
            )
            s0_csv.append([
                LABEL[mode],
                str(s.get("count", 0)),
                f"{s.get('min_us', 0):.2f}",
                f"{s.get('p50_us', 0):.2f}",
                f"{s.get('p95_us', 0):.2f}",
                f"{s.get('p99_us', 0):.2f}",
                f"{o.get('p50_overhead_pct', 0.0):+.1f}%" if mode != "access-only" else "Baseline",
                f"{o.get('p95_overhead_pct', 0.0):+.1f}%" if mode != "access-only" else "Baseline",
            ])
        s0_lines += [r"\bottomrule", r"\end{tabular}"]
        (a.output / "s0_latency.tex").write_text("\n".join(s0_lines) + "\n")
        (a.output / "s0_latency.csv").write_text("\n".join(",".join(r) for r in s0_csv) + "\n")

        # Startup Latency
        su_csv = [["Mode", "Policy_Parse_us", "Policy_Validate_us", "Digest_us", "Sandbox_Startup_us", "Total_Startup_us"]]
        for item in bdata.get("startup", []):
            su_csv.append([
                item["mode"],
                f"{item['policy_parse_ns']/1000.0:.2f}",
                f"{item['policy_validate_ns']/1000.0:.2f}",
                f"{item['digest_computation_ns']/1000.0:.2f}",
                f"{item['sandbox_startup_ns']/1000.0:.2f}",
                f"{item['total_startup_us']:.2f}",
            ])
        (a.output / "startup_latency.csv").write_text("\n".join(",".join(r) for r in su_csv) + "\n")

    # 8. Boundary Results Table (if boundary json provided)
    if a.boundary and a.boundary.exists():
        bound_data = json.loads(a.boundary.read_text())
        b_csv = [["Test ID", "Test Name", "Mode", "Target", "Policy Allowed", "Attempted", "Succeeded", "Outcome", "Interpretation"]]
        b_lines = [
            r"\begin{tabular}{lllccc}",
            r"\toprule",
            r"Test ID & Mode & Target & Allowed by Policy & Succeeded & Observed Outcome \\",
            r"\midrule",
        ]
        for t in bound_data.get("tests", []):
            b_csv.append([
                t["test_id"],
                t["test_name"],
                t["mode"],
                t["target"],
                str(t["policy_allowed"]),
                str(t["operation_attempted"]),
                str(t["operation_succeeded"]),
                t["outcome"],
                f"\"{t['claim_verification_interpretation']}\"",
            ])
            b_lines.append(
                f"{t['test_id']} & {LABEL.get(t['mode'], t['mode'])} & {t['target']} & "
                f"{'Yes' if t['policy_allowed'] else 'No'} & "
                f"{'Yes' if t['operation_succeeded'] else 'No'} & {t['outcome']} \\\\"
            )
        b_lines += [r"\bottomrule", r"\end{tabular}"]
        (a.output / "boundary_results.tex").write_text("\n".join(b_lines) + "\n")
        (a.output / "boundary_results.csv").write_text("\n".join(",".join(r) for r in b_csv) + "\n")

if __name__ == "__main__":
    main()
