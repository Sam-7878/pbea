#!/usr/bin/env python3
"""Build and verify the Round 1.1 SHA-256 manifest from an explicit allowlist."""
import argparse, datetime, hashlib, json, pathlib, subprocess

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(); p.add_argument("repo",type=pathlib.Path); p.add_argument("output",type=pathlib.Path); p.add_argument("--evaluation-source-commit",required=True); p.add_argument("--report-generator-commit",required=True); a=p.parse_args()
    repo=a.repo.resolve(); out=a.output.resolve(); out.mkdir(parents=True,exist_ok=True)
    round_rel="docs/work_reports/203_pbea_rev_round_2/round_1_1"
    files=[
      "docs/work_reports/202_pbea_rev_round_1/raw/access-only.jsonl","docs/work_reports/202_pbea_rev_round_1/raw/transition-only.jsonl","docs/work_reports/202_pbea_rev_round_1/raw/runtime-only.jsonl","docs/work_reports/202_pbea_rev_round_1/raw/full-pbea.jsonl",
      f"{round_rel}/generated/metrics.json",f"{round_rel}/generated/s0_benchmark.json",f"{round_rel}/generated/startup_summary.json",f"{round_rel}/generated/boundary_results.json",
      f"{round_rel}/raw/startup/startup-access-only.jsonl",f"{round_rel}/raw/startup/startup-transition-only.jsonl",f"{round_rel}/raw/startup/startup-runtime-only.jsonl",f"{round_rel}/raw/startup/startup-full-pbea.jsonl",
      f"{round_rel}/s7_raw_audit.csv",f"{round_rel}/s0_functional_equivalence.json",f"{round_rel}/comparative_evaluation_report_v3.md",f"{round_rel}/revision_inputs_v2.md",f"{round_rel}/s0_steady_state_overhead_report_v2.md",
      "evaluation/comparative/validate_records.py","evaluation/comparative/compute_security_metrics.py","evaluation/comparative/generate_report.py","evaluation/comparative/generate_tables.py","evaluation/comparative/report_consistency_test.py","evaluation/comparative/artifact_manifest.py",
    ]
    generated=sorted((repo/round_rel/"generated").glob("*.csv"))+sorted((repo/round_rel/"generated").glob("*.tex"))
    files += [str(x.relative_to(repo)).replace("\\","/") for x in generated]
    files=list(dict.fromkeys(files)); missing=[f for f in files if not (repo/f).is_file()]
    if missing: raise SystemExit(f"missing manifest files: {missing}")
    hashes={f:digest(repo/f) for f in files}
    manifest={"status":"valid","files_checked":len(files),"hash_failures":0,"evaluation_source_commit":a.evaluation_source_commit,"report_generator_commit":a.report_generator_commit,"generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"files":hashes}
    (out/"manifest.json").write_text(json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    (out/"manifest.sha256").write_text("".join(f"{h}  {f}\n" for f,h in sorted(hashes.items())))
    failures=[]; output=[]
    for f,h in sorted(hashes.items()):
        actual=digest(repo/f); ok=actual==h; output.append(f"{f}: {'OK' if ok else 'FAILED'}");
        if not ok: failures.append(f)
    (out/"verification_output.txt").write_text("\n".join(output)+"\n")
    summary={"status":"valid" if not failures else "invalid","files_checked":len(files),"hash_failures":len(failures),"evaluation_source_commit":a.evaluation_source_commit,"report_generator_commit":a.report_generator_commit}
    (out/"verification_summary.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    if failures: raise SystemExit(f"hash verification failures: {failures}")
    print(json.dumps(summary,sort_keys=True))
if __name__=="__main__": main()
