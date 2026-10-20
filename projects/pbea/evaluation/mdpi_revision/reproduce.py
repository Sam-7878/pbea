#!/usr/bin/env python3
"""Regenerate historical manuscript tables with explicit provenance and missing-data status."""
import argparse, hashlib, importlib.util, json, pathlib, subprocess, sys, tarfile

MODES=("access-only","transition-only","runtime-only","full-pbea")
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def module(path):
    sys.path.insert(0,str(path.parent));s=importlib.util.spec_from_file_location(path.stem,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
    p=argparse.ArgumentParser();p.add_argument("repo",type=pathlib.Path);p.add_argument("--output",type=pathlib.Path,help="optional separate analysis output; does not modify retained evidence");a=p.parse_args();repo=a.repo.resolve()
    retained_report=repo/"projects/pbea/results/204_Astra_review"
    report=a.output.resolve() if a.output else retained_report;report.mkdir(parents=True,exist_ok=True)
    generated=report/"generated";generated.mkdir(exist_ok=True)
    historical=repo/"docs/work_reports/pbea/202_pbea_rev_round_1";round11=repo/"docs/work_reports/pbea/203_pbea_rev_round_2/round_1_1"
    paths=[historical/"raw"/f"{m}.jsonl" for m in MODES]
    records=[json.loads(x) for f in paths for x in f.read_text().splitlines() if x.strip()]
    validator=module(repo/"evaluation/comparative/validate_records.py");errors=validator.validate(records)
    if errors:raise SystemExit(errors)
    metrics=module(repo/"evaluation/comparative/compute_security_metrics.py").compute(records)
    (generated/"historical_metrics.json").write_text(json.dumps(metrics,indent=2,sort_keys=True)+"\n")
    archived=json.loads((round11/"generated/metrics.json").read_text())
    if metrics!=archived:raise SystemExit("archived metrics differ from recomputed metrics")
    checks=[]
    old=json.loads((round11/"manifests/manifest.json").read_text())
    for path,h in old["files"].items():
        mapped=path.replace("docs/work_reports/","docs/work_reports/pbea/",1) if path.startswith("docs/work_reports/") else path
        f=repo/mapped; checks.append({"original_path":path,"mapped_path":mapped,"exists":f.is_file(),"hash_matches":f.is_file() and sha(f)==h})
    (generated/"historical_manifest_verification.json").write_text(json.dumps({"files_checked":len(checks),"matching":sum(x["hash_matches"] for x in checks),"checks":checks},indent=2)+"\n")
    views=[]
    for r in records:
        native=r["observed_outcome"]=="terminated"
        views.append({"run_id":r["run_id"],"original_source_commit":r["source_commit"],"scenario":r["scenario_id"],"mode":r["mode"],"application_outcome":None if native else r["observed_outcome"],"native_status":"terminated" if native else "completed-or-denied","signal":r["signal"],"errno":r["os_errno"],"evidence_origin":"supervisor" if native else "probe","evidence_complete":not native,"child_state_after":None if native else "not_separately_observed","parent_domain_hash_before":r["state_hash_before"],"parent_domain_hash_after":r["state_hash_after"]})
    (generated/"historical_observation_view.jsonl").write_text("".join(json.dumps(v,sort_keys=True)+"\n" for v in views))
    table=[r"\begin{tabular}{lrrrr}",r"\toprule",r"Metric & B0 & B1 & B2 & P \\",r"\midrule"]
    for title,fam,key in [("S1 invalid state","state_integrity","S1_invalid_state_propagation_rate"),("S7 rollback failure","state_integrity","S7_rollback_failure_rate"),("S2--S4 containment","runtime_capability_containment","aggregate_CCR"),("S8 mismatch accepted","policy_binding","S8_digest_mismatch_acceptance_rate"),("S5 malformed failure","fail_closed_startup","S5_malformed_policy_FCR"),("S5 missing-resource failure","fail_closed_startup","S5_missing_resource_FCR"),("S6 quarantine","outcome_quarantine_semantics","S6_quarantine_rate"),("S0 benign success","benign_preservation","S0_BRSR")]:
        values=[]
        for m in MODES:
            x=metrics[m]["effect_families"][fam][key];values.append("N/A" if not x["denominator"] else f"{x['numerator']}/{x['denominator']}")
        table.append(title+" & "+" & ".join(values)+r" \\")
    table += [r"\bottomrule",r"\end{tabular}"]
    (generated/"historical_security.tex").write_text("\n".join(table)+"\n")
    bench=json.loads((round11/"generated/s0_benchmark.json").read_text());b0=bench["steady_state"]["access-only"]["p50_us"]
    table=[r"\begin{tabular}{lrrrrr}",r"\toprule",r"Mode & P50 ($\mu$s) & P95 & P99 & $\Delta$ B0 & Ratio B0 \\",r"\midrule"]
    for m,label in zip(MODES,("B0","B1","B2","P")):
        x=bench["steady_state"][m];table.append(f"{label} & {x['p50_us']:.3f} & {x['p95_us']:.3f} & {x['p99_us']:.3f} & {x['p50_us']-b0:.3f} & {x['p50_us']/b0:.2f} \\\\")
    table += [r"\bottomrule",r"\end{tabular}"]
    (generated/"historical_performance.tex").write_text("\n".join(table)+"\n")
    manuscripts=repo/"docs/papers/_46_01_PBEA";inputs=[manuscripts/f for f in ("_46_PBEA.tex","references.bib","PBEA_Architecture_TikZ.tex")]
    if not (report/"original_manuscript.tar.gz").exists():
        with tarfile.open(report/"original_manuscript.tar.gz","w:gz") as archive:
            for f in inputs:archive.add(f,arcname=f.name)
    retained=json.loads((retained_report/"source_provenance.json").read_text()) if (retained_report/"source_provenance.json").exists() else {}
    def full(rev):
        if (repo/".git").exists():return subprocess.check_output(["git","-c",f"safe.directory={repo}","-C",str(repo),"rev-parse",rev],text=True).strip()
        return next((value for key,value in retained.items() if key.endswith("commit") and isinstance(value,str) and value.startswith(rev)),rev)
    provenance={"original_manuscripts":{f.name:sha(f) for f in inputs},"historical_evaluation_commit":full("62229cd"),"historical_reporting_commit":full("f2be0bf"),"new_source_commit":full("afe94eb"),"raw_hashes":{str(f.relative_to(repo)):sha(f) for f in paths},"historical_record_count":len(records),"historical_raw_timing_samples_available":False,"new_native_campaign":"completed" if (retained_report/"raw/security.jsonl").exists() else "not_run","historical_manifest_matching":sum(x["hash_matches"] for x in checks)}
    (report/"source_provenance.json").write_text(json.dumps(provenance,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"historical_records_validated":len(records),"canonical_metrics_match":True,"historical_manifest_matches":sum(x["hash_matches"] for x in checks),"files_checked":len(checks)}))
if __name__=="__main__":main()
