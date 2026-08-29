#!/usr/bin/env python3
import argparse, json, pathlib

LABEL={"access-only":"Access-only (B0)","transition-only":"Transition-only (B1)","full-pbea":"Full-PBEA (P)"}
MODES=("access-only","transition-only","full-pbea")
def pct(x): return "--" if x is None else f"{100*x:.1f}\\%"
def ci(m): return f"[{100*m['wilson_95_low']:.1f}, {100*m['wilson_95_high']:.1f}]" if m["wilson_95_low"] is not None else "--"
def main():
    p=argparse.ArgumentParser(); p.add_argument("metrics",type=pathlib.Path); p.add_argument("output",type=pathlib.Path); a=p.parse_args()
    data=json.loads(a.metrics.read_text()); a.output.mkdir(parents=True,exist_ok=True)
    lines=[r"\begin{tabular}{lrrrrrr}",r"\toprule",r"Mode & MESR & BRSR & SIVR & CER & FCR & OCA \\",r"\midrule"]
    for mode in MODES:
        row=data[mode]; lines.append(LABEL[mode]+" & "+" & ".join(pct(row["metrics"][m]["rate"]) for m in ("MESR","BRSR","SIVR","CER","FCR","OCA"))+r" \\")
    lines += [r"\bottomrule",r"\end{tabular}"]
    (a.output/"comparative_security.tex").write_text("\n".join(lines)+"\n")
    lines=[r"\begin{tabular}{llrrl}",r"\toprule",r"Mode & Metric & Numerator & Denominator & Wilson 95\% CI (\%) \\",r"\midrule"]
    for mode in MODES:
        row=data[mode]
        for name,m in row["metrics"].items(): lines.append(f"{LABEL[mode]} & {name} & {m['numerator']} & {m['denominator']} & {ci(m)} \\\\")
    lines += [r"\bottomrule",r"\end{tabular}"]
    (a.output/"security_metrics.tex").write_text("\n".join(lines)+"\n")
    lines=[r"\begin{tabular}{lrrrrrrr}",r"\toprule",r"Mode & n & Min & P50 & P95 & Max & Mean & $\sigma$ \\",r"\midrule"]
    for mode in MODES:
        row=data[mode]
        x=row["latency_us"]; lines.append(f"{LABEL[mode]} & {x['count']} & {x['min']} & {x['p50']} & {x['p95']} & {x['max']} & {x['mean']:.1f} & {x['population_stddev']:.1f} \\\\")
    lines += [r"\bottomrule",r"\end{tabular}"]
    (a.output/"overhead.tex").write_text("\n".join(lines)+"\n")
    (a.output/"attack_mechanisms.tex").write_text("""\\begin{tabular}{lll}\n\\toprule\nScenario & Full-PBEA control & Evidence \\\\\n+\\midrule\nS1/S6/S8 & Transition policy & Reject/quarantine and state hash \\\\\n+S2 & OpenBSD unveil & Read denied with OS errno \\\\\n+S3 & OpenBSD pledge & Child termination signal \\\\\n+S4 & Application endpoint allowlist & Blocked before connect \\\\\n+S5 & Fail-closed startup & Business loop not entered \\\\\n+S7 & Candidate/commit separation & Abort and unchanged state hash \\\\\n+\\bottomrule\n\\end{tabular}\n""")
if __name__=="__main__": main()
