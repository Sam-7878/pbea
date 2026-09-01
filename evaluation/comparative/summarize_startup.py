#!/usr/bin/env python3
"""Summarize 30 independent startup observations per mode."""
import argparse, csv, json, pathlib, statistics

MODES=("access-only","transition-only","runtime-only","full-pbea")
def percentile(values,p):
    v=sorted(values); return v[round((len(v)-1)*p)]
def main():
    p=argparse.ArgumentParser(); p.add_argument("input_dir",type=pathlib.Path); p.add_argument("--csv",required=True,type=pathlib.Path); p.add_argument("--json",required=True,type=pathlib.Path); a=p.parse_args()
    summary={}
    for mode in MODES:
        records=[json.loads(x) for x in (a.input_dir/f"startup-{mode}.jsonl").read_text().splitlines() if x.strip()]
        if len(records)!=30: raise SystemExit(f"{mode}: expected 30, got {len(records)}")
        values=[r["startup"]["total_startup_us"] for r in records]
        summary[mode]={"count":30,"min_us":min(values),"p50_us":percentile(values,.5),"p95_us":percentile(values,.95),"max_us":max(values),"mean_us":statistics.fmean(values),"population_stddev_us":statistics.pstdev(values)}
    a.csv.parent.mkdir(parents=True,exist_ok=True)
    with a.csv.open("w",newline="") as f:
        w=csv.writer(f); w.writerow(["Mode","n","Min_us","P50_us","P95_us","Max_us","Mean_us","Population_StdDev_us"])
        for m in MODES:
            x=summary[m]; w.writerow([m,x["count"],*(f"{x[k]:.3f}" for k in ("min_us","p50_us","p95_us","max_us","mean_us","population_stddev_us"))])
    a.json.write_text(json.dumps({"method":"30 independent process startups per mode in round-robin order; one untimed benign operation followed each startup","source_commit":"62229cd","summary":summary},indent=2,sort_keys=True)+"\n")
if __name__=="__main__": main()
