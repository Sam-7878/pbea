#!/usr/bin/env python3
import argparse, json, pathlib, statistics, sys
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from compute_wilson_ci import wilson

MODES=("access-only","transition-only","full-pbea")
def ratio(name, numerator, denominator):
    ci=wilson(numerator,denominator)
    return {"metric":name,"numerator":numerator,"denominator":denominator,
            "rate":None if not denominator else numerator/denominator,
            "percent":None if not denominator else 100*numerator/denominator,
            "wilson_95_low":None if ci is None else ci[0],"wilson_95_high":None if ci is None else ci[1]}

def percentile(values,p):
    values=sorted(values); idx=max(0,min(len(values)-1,round((len(values)-1)*p))); return values[idx]

def compute(records):
    result={}
    for mode in MODES:
        rs=[r for r in records if r["mode"]==mode]
        attempts=[r for r in rs if r["malicious_effect_attempted"]]
        benign=[r for r in rs if r["scenario_id"]=="S0"]
        noncommit=[r for r in rs if r["observed_outcome"] in ("reject","quarantine","abort","terminated","startup-failure")]
        contained=[r for r in rs if r["scenario_id"] in ("S2","S3","S4")]
        faults=[r for r in rs if r["scenario_id"]=="S5"]
        lat=[r["duration_us"] for r in rs]
        result[mode]={"metrics":{
            "MESR":ratio("MESR",sum(r["malicious_effect_succeeded"] for r in attempts),len(attempts)),
            "BRSR":ratio("BRSR",sum(r["status"]=="passed" and r["observed_outcome"] in ("success","commit") for r in benign),len(benign)),
            "SIVR":ratio("SIVR",sum(r["state_changed"] for r in noncommit),len(noncommit)),
            "CER":ratio("CER",sum(not r["malicious_effect_succeeded"] for r in contained),len(contained)),
            "FCR":ratio("FCR",sum(r["observed_outcome"]=="startup-failure" for r in faults),len(faults)),
            "OCA":ratio("OCA",sum(r["status"]=="passed" and r["expected_outcome"]==r["observed_outcome"] for r in rs),len(rs)),
        },"latency_us":{"count":len(lat),"min":min(lat),"p50":percentile(lat,.50),"p95":percentile(lat,.95),"max":max(lat),"mean":statistics.fmean(lat),"population_stddev":statistics.pstdev(lat)}}
    return result

def main():
    p=argparse.ArgumentParser(); p.add_argument("paths",nargs="+",type=pathlib.Path); p.add_argument("--output",type=pathlib.Path); a=p.parse_args()
    records=[json.loads(line) for path in a.paths for line in path.read_text().splitlines()]
    out=json.dumps(compute(records),indent=2,sort_keys=True)+"\n"
    if a.output: a.output.write_text(out)
    else: print(out,end="")
if __name__=="__main__": main()
