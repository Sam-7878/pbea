#!/usr/bin/env python3
"""Create/verify a local, secret-excluding reviewer artifact; never publish it."""
import argparse, hashlib, json, pathlib, subprocess, tarfile

REPORT=pathlib.Path('docs/work_reports/pbea/204_Astra_review/revision')
ROOTS=('crates','protocol','evaluation/comparative','evaluation/mdpi_revision',
       'docs/work_reports/pbea/202_pbea_rev_round_1',
       'docs/work_reports/pbea/203_pbea_rev_round_2/round_1_1',str(REPORT),
       'docs/papers/_46_01_PBEA/mdpi_revision')
FILES=('Cargo.toml','Cargo.lock','LICENSE','docs/papers/_46_01_PBEA/_46_PBEA.tex',
       'docs/papers/_46_01_PBEA/references.bib','docs/papers/_46_01_PBEA/PBEA_Architecture_TikZ.tex')
EXCLUDE={'__pycache__','packages','.git','target','local_security'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('repo',type=pathlib.Path);p.add_argument('--verify',action='store_true');a=p.parse_args();repo=a.repo.resolve()
    report=repo/REPORT;manifest=report/'manifests/manifest.json'
    if a.verify:
        data=json.loads(manifest.read_text());bad=[s for s,h in data['files'].items() if not (repo/s).is_file() or sha(repo/s)!=h]
        print(json.dumps({'status':'invalid' if bad else 'valid','files_checked':len(data['files']),'mismatches':bad}))
        if bad:raise SystemExit(1)
        return
    paths=set(repo/f for f in FILES)
    for root in ROOTS:
        for f in (repo/root).rglob('*'):
            rel=f.relative_to(repo)
            if not f.is_file() or f.is_symlink() or set(rel.parts)&EXCLUDE:continue
            if rel.is_relative_to(REPORT/'manifests'):continue
            if f.suffix in {'.aux','.out','.toc','.blg','.fls','.fdb_latexmk','.pyc'}:continue
            # All compiled manuscripts/build logs live in the report, not source.
            if 'mdpi_revision' in rel.parts and 'papers' in rel.parts and f.suffix in {'.log','.pdf','.bbl'} and 'Definitions' not in rel.parts:continue
            paths.add(f)
    missing=[str(f) for f in paths if not f.is_file()]
    if missing:raise SystemExit(missing)
    rev=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    hashes={str(f.relative_to(repo)):sha(f) for f in sorted(paths)}
    manifest.parent.mkdir(exist_ok=True)
    manifest.write_text(json.dumps({'reporting_revision':rev,'excluded':'self-manifests and package outputs; secrets; build caches','files':hashes},indent=2,sort_keys=True)+'\n')
    (manifest.parent/'manifest.sha256').write_text(''.join(f'{h}  {s}\n' for s,h in hashes.items()))
    package=report/'packages';package.mkdir(exist_ok=True)
    with tarfile.open(package/'pbea-mdpi-reviewer-artifact.tar.gz','w:gz') as out:
        for s in hashes:out.add(repo/s,arcname=s,recursive=False)
        out.add(manifest,arcname=str(manifest.relative_to(repo)))
        sums=manifest.parent/'manifest.sha256';out.add(sums,arcname=str(sums.relative_to(repo)))
    archive=package/'pbea-mdpi-reviewer-artifact.tar.gz'
    (package/'archive.sha256').write_text(f'{sha(archive)}  {archive.name}\n')
    print(json.dumps({'files':len(hashes),'reporting_revision':rev,'archive':str(archive),'sha256':sha(archive)}))
if __name__=='__main__':main()
