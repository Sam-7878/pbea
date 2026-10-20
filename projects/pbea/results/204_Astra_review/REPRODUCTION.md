# Reproduction and build guide

## Reanalysis of retained evidence (no OpenBSD required)

Run from the repository root with Python 3 and `jsonschema` installed:

```sh
python3 -m pip install -r projects/pbea/evaluation/mdpi_revision/requirements.txt
python3 projects/pbea/evaluation/mdpi_revision/reproduce.py .
python3 projects/pbea/evaluation/mdpi_revision/analyze.py projects/pbea/results/204_Astra_review/raw projects/pbea/results/204_Astra_review/generated
python3 -m unittest discover -s projects/pbea/evaluation/mdpi_revision -v
```

The tool maps relocated report paths, validates the 1,080 historical records, compares recomputed canonical metrics with the retained report, verifies 37 historical manifest files, and generates manuscript tables. It does not invent individual historical latency samples.

## New native campaign (OpenBSD 7.9)

Checkout evaluation source `afe94eb` (resolve full hash through Git). In a separate directory:

```sh
cargo test --workspace --locked
cargo build --release --locked -p poa-verifier-example --bin mdpi_probe
target/release/mdpi_probe campaign /home/sam/pbea-mdpi-results ACTUAL_FULL_SOURCE_COMMIT
```

The campaign intentionally creates/replaces only synthetic fixtures under `/tmp/pbea-eval`, and uses loopback. Ensure no other campaign is running against the same fixtures/ports. The output directory must be a new campaign path. Substitute the actual frozen full commit rather than the command's descriptive token.

Copy `security.jsonl` and `benchmark.jsonl` into this revision's `raw/` directory. Then:

```sh
python3 projects/pbea/evaluation/mdpi_revision/analyze.py \
  projects/pbea/results/204_Astra_review/raw \
  projects/pbea/results/204_Astra_review/generated
```

The analysis preserves observed failures. The 540 security records and 300 independent benchmark-process records do not replace the old corpus. Every block stores 500 post-warm-up nanosecond samples and 100 empty-timer observations.

## MDPI manuscript

The original `_46_PBEA.tex` is unchanged. The revised main source is `projects/pbea/paper/mdpi_revision/main.tex`. It uses the unmodified official MDPI class in `Definitions/`, with Electronics as a provisional working target. The same TikZ fragment serves main and standalone output.

```sh
cd projects/pbea/paper/mdpi_revision
pdflatex -interaction=nonstopmode -halt-on-error main.tex
bibtex main
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error main.tex
pdflatex -interaction=nonstopmode -halt-on-error architecture_standalone.tex
```

A full TeX Live installation needs the packages in the publisher class, including `soul`, `enotez`, and the usual LaTeX-extra collection. This task extracted official Ubuntu `texlive-latex-extra`/`texlive-plain-generic` packages under `/tmp/mdpi-tex-tree`; no publisher class or system configuration was modified. The temporary environment is not a required artifact runtime.

After a successful build, render and visually review **every** page. A build with no undefined citations is not by itself a layout QA result. Author declarations, publication permissions, final venue/APC/indexing checks, and reviewer-accessible archival release remain distinct submission gates.

## Local reviewer package

The original `packages/pbea-mdpi-reviewer-artifact.tar.gz` and top-level manifests are historical 2026-10-20 snapshots: their internal paths and hashes must not be edited to resemble a new experiment. The current-layout package is `packages/layout_2026_10_21/pbea-mdpi-reviewer-artifact.tar.gz`, with a separate manifest under `manifests/layout_2026_10_21/`. It contains the selected source, license, lockfile, policy fixtures, historical/new raw data, analysis tools, manuscript and review outputs, and excludes private settings, keys and caches. Extract the current-layout package into a fresh directory; run the commands above there. Current-layout hash verification is:

```sh
python3 projects/pbea/evaluation/mdpi_revision/package_revision.py . --verify
```

The package's lack of `.git` is intentional. Full source revisions are retained in `source_provenance.json` and `manifests/manifest.json`. Reanalysis without Git does not establish a fresh checkout of those revisions; it checks retained evidence. `reproduce.py` preserves the archived full provenance when Git is absent. Historical archive regeneration changes archive metadata only, so run the manifest check before regeneration. A local archive is not a public reviewer-access URL.

For non-mutating reanalysis of retained task outputs, use `reproduce.py . --output /tmp/pbea-history-check` and pass a new `/tmp/` output directory to `analyze.py`. Reproduction never needs to alter the retained `raw/` directory. The Windows/WSL workspace had preexisting CRLF-only changes before the 2026-10-21 move; migration did not normalize raw bytes or reinterpret old file hashes. The layout audit records byte-for-byte transfer checks. New `.gitattributes` rules prevent further automatic newline conversion of evidence and publisher sources.
