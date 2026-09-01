#!/usr/bin/env python3
"""Verify application-visible S0 equivalence from the frozen four-mode corpus."""
import argparse, json, pathlib

MODES=("access-only","transition-only","runtime-only","full-pbea")
def main():
    p=argparse.ArgumentParser(); p.add_argument("paths",nargs="+",type=pathlib.Path); p.add_argument("--output",required=True,type=pathlib.Path); a=p.parse_args()
    records=[json.loads(line) for path in a.paths for line in path.read_text().splitlines() if line.strip()]
    s0=[r for r in records if r["scenario_id"]=="S0"]
    by={m:[r for r in s0 if r["mode"]==m] for m in MODES}
    result={
        "source_commit":sorted({r["source_commit"] for r in s0}),
        "records_per_mode":{m:len(by[m]) for m in MODES},
        "same_operation":len({r["operation"] for r in s0})==1,
        "same_input":"The frozen probe constructs one amount=100 USD request shape for every mode before mode branching.",
        "same_domain_result":len({r["state_hash_after"] for r in s0})==1 and all(r["state_changed"] for r in s0),
        "same_application_result":all(r["observed_outcome"] in ("success","commit") for r in s0),
        "normalized_application_result":"success",
        "security_specific_differences_allowed":["policy_digest","candidate isolation","reconciliation","runtime sandbox","security evidence"],
    }
    result["status"]="valid" if all(result[k] is True for k in ("same_operation","same_domain_result","same_application_result")) and all(v==30 for v in result["records_per_mode"].values()) else "invalid"
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    if result["status"]!="valid": raise SystemExit(1)
if __name__=="__main__": main()
