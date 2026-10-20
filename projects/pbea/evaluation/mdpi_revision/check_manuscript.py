#!/usr/bin/env python3
"""Static manuscript checks complement (not replace) full PDF visual review."""
import argparse,json,pathlib,re

def main():
    p=argparse.ArgumentParser();p.add_argument("paper",type=pathlib.Path);p.add_argument("--output",type=pathlib.Path);a=p.parse_args()
    main=(a.paper/"main.tex").read_text(); texts=main+(a.paper/"architecture_fragment.tex").read_text()
    labels=re.findall(r"\\label\{([^}]+)\}",texts);refs=re.findall(r"\\(?:ref|eqref)\{([^}]+)\}",texts)
    citations={key for group in re.findall(r"\\cite\{([^}]+)\}",texts) for key in group.split(",")}
    bib=(a.paper.parent/"references.bib").read_text()+(a.paper/"revision_references.bib").read_text();keys=set(re.findall(r"@\w+\{([^,]+),",bib))
    abstract=re.search(r"\\abstract\{(.*?)\}\n\\keyword",main,re.S).group(1)
    words=len(re.findall(r"\b[\w.-]+\b",abstract))
    errors=[]
    if len(labels)!=len(set(labels)):errors.append("duplicate labels")
    if set(refs)-set(labels):errors.append(f"undefined references: {set(refs)-set(labels)}")
    if citations-keys:errors.append(f"undefined citation keys: {citations-keys}")
    if words>200:errors.append(f"abstract length {words}>200 words")
    if "\\section{Results}" not in main:errors.append("missing Results section")
    if re.search(r"Section~[IVX]+\b|Eq\.\s*\([0-9]+\)",main):errors.append("manual numbering")
    if "IEEEtran" in main or "ANONYMIZED-OR-VENUE" in main:errors.append("legacy class/placeholder")
    result={"status":"valid" if not errors else "invalid","abstract_words":words,"citation_keys":len(citations),"labels":len(labels),"errors":errors}
    if a.output:a.output.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))
    if errors:raise SystemExit(1)
if __name__=="__main__":main()
