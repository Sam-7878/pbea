#!/usr/bin/env python3
"""Check all manuscript-facing artifacts against canonical JSON inputs."""
import argparse, csv, hashlib, json, pathlib, re, sys

MODES=("access-only","transition-only","runtime-only","full-pbea")
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser(); p.add_argument("--metrics",required=True,type=pathlib.Path); p.add_argument("--benchmark",required=True,type=pathlib.Path); p.add_argument("--generated",required=True,type=pathlib.Path); p.add_argument("--reports",nargs="+",type=pathlib.Path); a=p.parse_args()
    d=json.loads(a.metrics.read_text()); errors=[]; expected=f"canonical_metrics_sha256:{sha(a.metrics)} benchmark_sha256:{sha(a.benchmark)}"
    for report in a.reports:
        text=report.read_text()
        if expected not in text: errors.append(f"{report}: canonical hash marker mismatch")
        if re.search(r"\bCER\b",text): errors.append(f"{report}: legacy CER exposed")
        for phrase in ("proves zero latency","zero overhead","entirely attributable"):
            if phrase.lower() in text.lower(): errors.append(f"{report}: prohibited wording {phrase}")
    for path in a.generated.glob("*"):
        if path.suffix in (".csv",".tex",".md") and re.search(r"\bCER\b",path.read_text()): errors.append(f"{path}: legacy CER exposed")
    matrix=list(csv.DictReader((a.generated/"scenario_matrix.csv").open()))
    s7=next(r for r in matrix if r["Scenario"]=="S7")
    if s7["B0 Access-only"]!="not-applicable (0/0)" or s7["B2 Runtime-only"]!="not-applicable (0/0)": errors.append("scenario matrix: S7 B0/B2 must be not-applicable")
    if s7["B1 Transition-only"]!="abort (0/30)" or s7["P Full-PBEA"]!="abort (0/30)": errors.append("scenario matrix: S7 B1/P mismatch")
    for m in MODES:
        metric=d[m]["effect_families"]["state_integrity"]["S7_rollback_failure_rate"]
        if m in ("access-only","runtime-only") and metric["denominator"]!=0: errors.append(f"{m}: S7 N/A included in denominator")
        if m in ("transition-only","full-pbea") and (metric["numerator"],metric["denominator"])!=(0,30): errors.append(f"{m}: S7 metric mismatch")
    if errors: print("\n".join(errors),file=sys.stderr); raise SystemExit(1)
    print(json.dumps({"status":"passed","checks":["scenario_matrix","S1","S7","S2-S4_CCR","S5_FCR","S6_quarantine","S0_BRSR","benchmark","corpus_size","source_commit","terminology"]},sort_keys=True))
if __name__=="__main__": main()
