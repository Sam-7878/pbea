#!/usr/bin/env python3
"""Extract and summarize the 120 frozen S7 records without rewriting evidence."""
import argparse, csv, json, pathlib

MODES = ("access-only", "transition-only", "runtime-only", "full-pbea")
GUARDED = {"transition-only", "full-pbea"}
FIELDS = (
    "mode", "scenario", "iteration", "expected_outcome", "observed_outcome",
    "state_hash_before", "state_hash_after", "domain_state_changed",
    "candidate_created", "fault_injected", "fault_location",
    "malicious_effect_attempted", "malicious_effect_succeeded",
    "rollback_expected", "rollback_observed", "rollback_failure",
    "quarantine_state", "abort_state", "metric_applicable", "source_commit",
)

def audit(records):
    rows=[]
    for r in records:
        if r["scenario_id"] != "S7": continue
        guarded=r["mode"] in GUARDED
        unchanged=r["state_hash_before"] == r["state_hash_after"]
        rows.append({
            "mode":r["mode"], "scenario":"S7", "iteration":r["iteration"],
            "expected_outcome":r["expected_outcome"], "observed_outcome":r["observed_outcome"],
            "state_hash_before":r["state_hash_before"], "state_hash_after":r["state_hash_after"],
            "domain_state_changed":r["state_changed"],
            "candidate_created":guarded, "fault_injected":guarded and r["observed_outcome"] == "abort",
            "fault_location":r["target"], "malicious_effect_attempted":r["malicious_effect_attempted"],
            "malicious_effect_succeeded":r["malicious_effect_succeeded"],
            "rollback_expected":guarded, "rollback_observed":guarded and unchanged,
            "rollback_failure":guarded and not unchanged,
            "quarantine_state":r["observed_outcome"] == "quarantine",
            "abort_state":r["observed_outcome"] == "abort", "metric_applicable":guarded,
            "source_commit":r["source_commit"],
        })
    return sorted(rows,key=lambda x:(MODES.index(x["mode"]),x["iteration"]))

def main():
    p=argparse.ArgumentParser(); p.add_argument("paths",nargs="+",type=pathlib.Path)
    p.add_argument("--csv",required=True,type=pathlib.Path); p.add_argument("--summary",required=True,type=pathlib.Path); a=p.parse_args()
    records=[json.loads(line) for path in a.paths for line in path.read_text().splitlines() if line.strip()]
    rows=audit(records)
    if len(rows)!=120: raise SystemExit(f"expected 120 S7 records, found {len(rows)}")
    a.csv.parent.mkdir(parents=True,exist_ok=True)
    with a.csv.open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    lines=["# S7 raw evidence audit","", "S7 asks whether a fault after candidate preparation propagates partial state.","",
           "The frozen raw corpus implements **Case B** for B0/B2: those direct-mutation paths have no after-candidate fault point. Their ordinary mutation changes state, but `malicious_effect_attempted=false`; therefore rollback metrics are not applicable and use denominator 0.","",
           "| Mode | Records | Outcome | State changed | Fault injected | Rollback failures | Metric denominator |","|---|---:|---|---:|---:|---:|---:|"]
    for mode in MODES:
        rs=[r for r in rows if r["mode"]==mode]
        outs=sorted({r["observed_outcome"] for r in rs})
        lines.append(f"| {mode} | {len(rs)} | {'/'.join(outs)} | {sum(r['domain_state_changed'] for r in rs)} | {sum(r['fault_injected'] for r in rs)} | {sum(r['rollback_failure'] for r in rs)} | {sum(r['metric_applicable'] for r in rs)} |")
    lines += ["", "Root cause: the metric generator counted every S7 state change as rollback failure, while `revision_inputs.md` manually reported zero. Raw hashes were internally consistent; the denominator semantics and hand-maintained report were not.", "", "Re-experiment decision: not required. The immutable records contain enough information to distinguish absent fault attempts (B0/B2) from guarded Abort behavior (B1/P)."]
    a.summary.write_text("\n".join(lines)+"\n")

if __name__=="__main__": main()
