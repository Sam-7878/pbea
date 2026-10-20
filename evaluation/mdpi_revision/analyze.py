#!/usr/bin/env python3
"""Outcome-independent evidence validation and canonical MDPI table generation."""
import argparse, collections, hashlib, json, pathlib, statistics

CASES=("BIND-aligned","BIND-runtime-epoch","BIND-stale-evidence","BIND-inheritance-drift","BIND-request-version","BIND-equal-id-wrong-install","BOUND-send-before-abort","BOUND-preopened-fd","SERVICE-sequence")

def validate(records):
    errors=[]; ids=set(); cells=set()
    for r in records:
        required={"run_id","source_commit","platform","case","mode","iteration","observation","evidence_origin","scope"}
        if not isinstance(r,dict) or set(r)!=required:
            errors.append("record schema mismatch");continue
        if not isinstance(r["observation"],dict) or not isinstance(r["iteration"],int) or not 1<=r["iteration"]<=30:
            errors.append("observation/iteration schema mismatch");continue
        if r["run_id"] in ids: errors.append("duplicate run id")
        ids.add(r["run_id"])
        cell=(r["case"],r["mode"],r["iteration"])
        if cell in cells: errors.append("duplicate cell")
        cells.add(cell)
        o=r["observation"]
        if o.get("native_status")=="child_failed": continue  # Preserve genuine system failures.
        if "domain_before" in o and ("domain_after" not in o or o.get("domain_changed") != (o["domain_before"]!=o.get("domain_after"))): errors.append("inconsistent state observation")
        if o.get("native_status")=="not_installed" and o.get("business_entered"): errors.append("business entered before install")
        # Do NOT reject a well-formed security failure merely because P failed.
    target={(c,m,i) for c in CASES for m in ("unbound-composition","full-pbea") for i in range(1,31)}
    if len(records)!=540 or cells!=target: errors.append("incomplete 9x2x30 corpus")
    if len({r.get("source_commit") for r in records if isinstance(r,dict)})!=1: errors.append("mixed source revisions")
    return errors

def validate_benchmark(records, source):
    """Check measurement structure, not whether a security claim succeeded."""
    errors=[];cells=set()
    modes=("access-only","transition-only","runtime-only","full-pbea","unbound-composition")
    workloads=("state1","state128","allowed-io")
    target={(b,m,w) for b in range(20) for m in modes for w in workloads}
    for r in records:
        if not isinstance(r,dict) or set(r)!={"block","source_commit","observation"} or not isinstance(r.get("observation"),dict):
            errors.append("benchmark schema mismatch");continue
        o=r["observation"]
        cell=(r["block"],o.get("mode"),o.get("workload"))
        if cell in cells: errors.append("duplicate benchmark cell")
        cells.add(cell)
        if r["source_commit"]!=source: errors.append("benchmark source mismatch")
        for key,n in (("samples_ns",500),("timer_empty_ns",100)):
            values=o.get(key)
            if not isinstance(values,list) or len(values)!=n or any(type(x) is not int or x<0 for x in values):errors.append("invalid timing samples")
        if o.get("warmup")!=100: errors.append("warmup mismatch")
    if len(records)!=300 or cells!=target:errors.append("incomplete benchmark cells")
    return errors

def stats(values):
    v=sorted(values)
    return {"n":len(v),"min":v[0],"p50":statistics.median(v),"p95":v[round((len(v)-1)*.95)],"p99":v[round((len(v)-1)*.99)],"max":v[-1],"mean":statistics.fmean(v),"population_stddev":statistics.pstdev(v)}

def main():
    p=argparse.ArgumentParser();p.add_argument("raw",type=pathlib.Path);p.add_argument("output",type=pathlib.Path);a=p.parse_args();a.output.mkdir(parents=True,exist_ok=True)
    records=[json.loads(x) for x in (a.raw/"security.jsonl").read_text().splitlines()]
    errors=validate(records)
    if errors: raise SystemExit(errors)
    cases={}
    for case in sorted({r["case"] for r in records}):
        cases[case]={}
        for mode in ("unbound-composition","full-pbea"):
            rs=[r["observation"] for r in records if r["case"]==case and r["mode"]==mode]
            cases[case][mode]={"n":len(rs),"outcomes":dict(collections.Counter(str(r.get("application_outcome")) for r in rs)),"native_status":dict(collections.Counter(r["native_status"] for r in rs)),"effects_succeeded":sum(r.get("effect_succeeded",False) for r in rs),"domain_changed":sum(r.get("domain_changed",False) for r in rs)}
    bench=[json.loads(x) for x in (a.raw/"benchmark.jsonl").read_text().splitlines()]
    errors=validate_benchmark(bench,records[0]["source_commit"])
    if errors:raise SystemExit(errors)
    timing={}
    for workload in ("state1","state128","allowed-io"):
        timing[workload]={}
        baseline=None
        for mode in ("access-only","transition-only","runtime-only","full-pbea","unbound-composition"):
            rows=[r["observation"] for r in bench if r["observation"]["mode"]==mode and r["observation"]["workload"]==workload]
            if len(rows)!=20 or any(len(r["samples_ns"])!=500 for r in rows):raise SystemExit("incomplete benchmark")
            if any(r["functional_amount"]!=100 or r["application_result"]!="success" for r in rows):raise SystemExit("functional mismatch")
            hashes={r["observation"]["final_state_hash"] for r in bench if r["observation"]["workload"]==workload}
            if len(hashes)!=1:raise SystemExit("cross-mode domain-result mismatch")
            samples=[n/1000 for r in rows for n in r["samples_ns"]]
            x=stats(samples);x["independent_blocks"]=20;x["block_medians_us"]=stats([statistics.median(r["samples_ns"])/1000 for r in rows]);x["empty_timer_ns"]=stats([n for r in rows for n in r["timer_empty_ns"]]);
            if mode=="access-only":baseline=x["p50"]
            x["p50_delta_vs_b0_us"]=x["p50"]-baseline;x["p50_ratio_vs_b0"]=x["p50"]/baseline if baseline else None
            timing[workload][mode]=x
    result={"security_records":len(records),"benchmark_blocks":len(bench),"source_commit":records[0]["source_commit"],"cases":cases,"timing_us":timing,"validation":"valid","experiment_unit":"process block, not individual sequential operation"}
    (a.output/"metrics.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    lines=["# Additional native evidence", "", f"Source: `{result['source_commit']}`. Security records: {len(records)}. Process benchmark blocks: {len(bench)}.","", "| Case | B3 outcomes | P outcomes | B3/P external successes |", "|---|---|---|---|"]
    for case,modes in cases.items():
        b=modes["unbound-composition"];f=modes["full-pbea"];lines.append(f"| {case} | {b['outcomes']} | {f['outcomes']} | {b['effects_succeeded']}/{f['effects_succeeded']} |")
    lines += ["", "The equal-ID/wrong-install case is an intentional trusted-mapper defect. A matching metadata identity does not attest kernel configuration. B3 and P both permit that effect; the claim is identity consistency only.","", "Allowed send before Abort succeeds at the receiver while candidate state remains uninstalled. This is not external-I/O atomic rollback.","", "## Benign cost (pooled quantiles; uncertainty unit is process block)","", "| Workload | Mode | P50 µs | P95 µs | P99 µs | Δ B0 µs | Ratio B0 | Block-median min–max µs |", "|---|---|---:|---:|---:|---:|---:|---|"]
    for w,modes in timing.items():
        for m,x in modes.items():
            b=x["block_medians_us"];lines.append(f"| {w} | {m} | {x['p50']:.3f} | {x['p95']:.3f} | {x['p99']:.3f} | {x['p50_delta_vs_b0_us']:.3f} | {x['p50_ratio_vs_b0']:.2f} | {b['min']:.3f}–{b['max']:.3f} |")
    (a.output/"results.md").write_text("\n".join(lines)+"\n")
    tex=[r"\begin{tabular}{lrr}",r"\toprule",r"Configuration & Runtime-ID skew accepted & Equal-ID mapper defect effect \\",r"\midrule"]
    for m,label in (("unbound-composition","B3"),("full-pbea","P")):
        accepted=cases["BIND-runtime-epoch"][m]["outcomes"].get("commit",0)
        effects=cases["BIND-equal-id-wrong-install"][m]["effects_succeeded"]
        tex.append(f"{label} & {accepted}/30 & {effects}/30 \\\\")
    tex += [r"\bottomrule",r"\end{tabular}"]
    (a.output/"binding_results.tex").write_text("\n".join(tex)+"\n")
    table=[r"\begin{tabular}{llrrrrr}",r"\toprule",r"Workload & Mode & P50 & P95 & P99 & $\Delta$ B0 & Ratio B0 \\",r"\midrule"]
    labels={"access-only":"B0","transition-only":"B1","runtime-only":"B2","full-pbea":"P","unbound-composition":"B3"}
    for workload,modes in timing.items():
        for mode,x in modes.items():
            table.append(f"{workload} & {labels[mode]} & {x['p50']:.3f} & {x['p95']:.3f} & {x['p99']:.3f} & {x['p50_delta_vs_b0_us']:.3f} & {x['p50_ratio_vs_b0']:.2f} \\\\")
    table += [r"\bottomrule",r"\end{tabular}"]
    (a.output/"native_performance.tex").write_text("\n".join(table)+"\n")
    functional={"status":"valid","modes":list(labels),"workloads":list(timing),"same_requested_operation":True,"same_input_shape":True,"same_business_mutation":True,"same_result_state_per_workload":True,"same_normalized_application_result":True,"sample_count":sum(len(r["observation"]["samples_ns"]) for r in bench),"unit":"500 sequential operations per independent process block","raw_source":"benchmark.jsonl"}
    (a.output/"functional_equivalence.json").write_text(json.dumps(functional,indent=2,sort_keys=True)+"\n")
    manifest={str(path.relative_to(a.raw.parent)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(a.raw.glob("*.jsonl"))}
    (a.output/"raw_hashes.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(json.dumps({"security_records":len(records),"benchmark_blocks":len(bench),"status":"valid"}))
if __name__=="__main__":main()
