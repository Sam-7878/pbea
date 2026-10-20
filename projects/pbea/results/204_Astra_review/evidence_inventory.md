# W01 evidence inventory

Assessment date: 2026-10-20. Original manuscript files match all three hashes in the work order. `original_manuscript.tar.gz` preserves those inputs without editing them.

| Material | Actual location | Evidence level | Limitation |
|---|---|---|---|
| Original manuscript/BibTeX/TikZ | `docs/papers/_46_01_PBEA/` | files present; SHA-256 matches review | Original source preserved; not overwritten |
| Historical evaluation source | Git `62229cd31ad1915cdd850fe3cfd670cddf208d0c` | revision resolved | Not silently conflated with new source |
| Historical reporting source | Git `f2be0bfbcbf2aad093018d69e513cc61b169e5e3` | revision resolved | Reporting corrections separate from native evaluation |
| Rust workspace, lockfile, fixtures | repository `crates/`, `protocol/`, Cargo.lock | locally executable | Current local host is Ubuntu 26.04, not the historical 24.04 |
| Four historical raw JSONL files | `docs/work_reports/pbea/202_pbea_rev_round_1/raw/` | 1,080 records revalidated; canonical metrics reproduce | Nine deterministic fixtures, not 1,080 attack types |
| Historical 120 startup observations | `docs/work_reports/pbea/203_pbea_rev_round_2/round_1_1/raw/startup/` | files present; original manifest verified | Original hardware/session metadata retained as historical |
| Historical steady-state benchmark | same report's `generated/s0_benchmark.json` | aggregate statistics present | Individual 5,000-operation timing samples absent; cannot reconstruct uncertainty |
| BT1/BT2 | same report's `generated/boundary_results.json` | eight raw boundary records present | One controlled boundary action per mode; no population claim |
| Original 37-file manifest | same report's `manifests/manifest.json` | 37/37 hashes match after relocation mapping | Old path names are mapped explicitly, not rewritten in originals |
| New source | Git `afe94eb` | local tests, Clippy and OpenBSD workspace tests passed | Frozen separately from reporting tools |
| New native corpus | `revision/raw/` | 540 security records, 300 independent process blocks, 150,000 timings | Controlled OpenBSD 7.9 fixtures; no population inference |
| Public revision archive | no verified archival release | not available | No fabricated URL/DOI; author publication/access approval is a submission gate |

The existing worktree has tracked deletions at the old report paths. They predate this task and were not staged, restored, or committed by this revision. Data under the new `docs/work_reports/pbea/` paths were read without altering the original records.

The new implementation is additive. Its B3/native-boundary and independent-block performance corpus must never be merged into the historical 1,080-record corpus or attributed to `62229cd`.
