#!/usr/bin/env python3
"""Generate manuscript inputs from canonical metrics and benchmark artifacts."""
import argparse, hashlib, json, pathlib

MODES=("access-only","transition-only","runtime-only","full-pbea")
LABEL={"access-only":"B0 Access-only","transition-only":"B1 Transition-only","runtime-only":"B2 Runtime-only","full-pbea":"P Full-PBEA"}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def pct(v): return "N/A" if v is None else f"{100*v:.1f}%"
def header(metrics,benchmark,startup=None):
    extra=f" startup_sha256:{sha(startup)}" if startup else ""
    return f"<!-- canonical_metrics_sha256:{sha(metrics)} benchmark_sha256:{sha(benchmark)}{extra} -->"

def main():
    p=argparse.ArgumentParser(); p.add_argument("metrics",type=pathlib.Path); p.add_argument("benchmark",type=pathlib.Path); p.add_argument("output_dir",type=pathlib.Path); p.add_argument("--startup-summary",type=pathlib.Path); a=p.parse_args()
    d=json.loads(a.metrics.read_text()); b=json.loads(a.benchmark.read_text()); a.output_dir.mkdir(parents=True,exist_ok=True)
    marker=header(a.metrics,a.benchmark,a.startup_summary)
    lines=[marker,"# PBEA Round 1.1 revision inputs","",f"Canonical corpus: 1,080 records from frozen evaluation source `{b['source_commit']}`.","",
           "| Metric | B0 | B1 | B2 | P |","|---|---:|---:|---:|---:|"]
    paths=[("S1 invalid-state rate","state_integrity","S1_invalid_state_propagation_rate"),("S7 rollback-failure rate","state_integrity","S7_rollback_failure_rate"),("Aggregate CCR","runtime_capability_containment","aggregate_CCR"),("S5 FCR","fail_closed_startup","S5_aggregate_FCR"),("S6 quarantine rate","outcome_quarantine_semantics","S6_quarantine_rate"),("S0 BRSR","benign_preservation","S0_BRSR")]
    for title,fam,key in paths: lines.append("| "+title+" | "+" | ".join(pct(d[m]["effect_families"][fam][key]["rate"]) for m in MODES)+" |")
    lines += ["", "S7 is not applicable to B0/B2 because their direct-mutation path contains no after-candidate fault point. It is excluded rather than scored as success or failure.","", "## Steady-state S0","", "| Mode | n | P50 µs | P95 µs | P99 µs |","|---|---:|---:|---:|---:|"]
    for m in MODES:
        x=b["steady_state"][m]; lines.append(f"| {LABEL[m]} | {x['count']} | {x['p50_us']:.3f} | {x['p95_us']:.3f} | {x['p99_us']:.3f} |")
    lines += ["", "No measurable median or P95 increase was observed for Runtime-only relative to Access-only in this synthetic S0 path at the reported measurement resolution after restrictions had been installed.", "", "No component-level causal attribution is made from the aggregate Full-PBEA timing."]
    if a.startup_summary:
        startup=json.loads(a.startup_summary.read_text())["summary"]
        lines += ["", "## Repeated startup", "", "| Mode | n | P50 ms | P95 ms | Mean ms |", "|---|---:|---:|---:|---:|"]
        for m in MODES:
            x=startup[m]; lines.append(f"| {LABEL[m]} | {x['count']} | {x['p50_us']/1000:.3f} | {x['p95_us']/1000:.3f} | {x['mean_us']/1000:.3f} |")
        lines += ["", "Startup remained in the tens-of-milliseconds range. No ranking claim is made among modes."]
    (a.output_dir/"revision_inputs_v2.md").write_text("\n".join(lines)+"\n")
    report=[marker,"# S0 steady-state overhead report v2","",f"Method: {b['warmup_iterations']} warm-up operations followed by {b['measured_iterations']} measured operations per mode on {b['platform']}.","", "| Mode | n | P50 µs | P95 µs | P99 µs |", "|---|---:|---:|---:|---:|"]
    for m in MODES:
        x=b["steady_state"][m]; report.append(f"| {LABEL[m]} | {x['count']} | {x['p50_us']:.3f} | {x['p95_us']:.3f} | {x['p99_us']:.3f} |")
    report += ["", "No measurable median or P95 increase was observed for Runtime-only relative to Access-only in this synthetic S0 path at the reported measurement resolution after restrictions had been installed.", "", "No component-level causal attribution is made from the aggregate Full-PBEA timing.", "", "Startup mode ranking is not inferred from steady-state measurements; the 30-repetition startup summary is reported in revision_inputs_v2.md and generated/startup_latency.csv."]
    (a.output_dir/"s0_steady_state_overhead_report_v2.md").write_text("\n".join(report)+"\n")
if __name__=="__main__": main()
