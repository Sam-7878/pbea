# Main integration and project-layout migration

Date: 2026-10-21 (Asia/Seoul). Requested repository: `/mnt/d/_Work/goat_bank/pbea`.

## Scope and decisions

`main` is the single integration branch. Its original tip `61d5f3cd165585934ac78c6fa49ed56f2d7128a7` was an ancestor of `revision/mdpi-2026-10-20` at `3a0a88e4beace7eaeae58682cdc6d88c375b8f4d`, so integration preserved the published six-commit history by fast-forward, including the user's `3a0a88e` cleanup. No rebase, reset, force-push of main, source rollback or deletion of research evidence was used.

The user additionally approved updating `origin/main` and deleting the integrated remote revision branch. Remote update/deletion and the final branch state are checked in the completion log; no journal submission is involved.

| Original active path | New canonical path | Role |
|---|---|---|
| `docs/work_reports/pbea/204_Astra_review/revision/` | `projects/pbea/results/204_Astra_review/` | One milestone/task's raw data, reports, pictures, PDFs and archives |
| `evaluation/mdpi_revision/` | `projects/pbea/evaluation/mdpi_revision/` | PBEA-specific tools reused across milestones |
| `docs/papers/_46_01_PBEA/mdpi_revision/` | `projects/pbea/paper/mdpi_revision/` | PBEA-wide working manuscript, not a duplicate task-output tree |

The original bibliography was copied byte-for-byte to `projects/pbea/paper/references.bib` for the working draft; the original source remains preserved in its old manuscript archive. This is an explicitly identified working snapshot, not two competing sources maintained silently. Earlier reports/original manuscripts were not wholesale moved. The old task folder contains only an index to the new active results in addition to its retained review/work-order inputs; it has no second `revision/` data tree.

## Project ownership

Repository-wide `crates/`, `protocol/` and reusable components remain shared. `projects/pbea/` owns PBEA-wide tools/manuscript/resources. New `open_banking` and `swarm_drones` READMEs reserve derivative namespaces without pretending implementations exist. Every future task stores its own data, reports and pictures in `projects/<project>/results/<task>/`. Rules are documented in `projects/README.md`; no permanent branch per project is required.

## Preservation and validation

At start, 70 tracked files had preexisting CRLF-only differences; `git diff --ignore-space-at-eol` showed no content changes. These were not silently discarded. The common Rust files retain their preexisting workspace bytes and are not staged as source changes by this migration.

All **60** files in the original revision directory were hashed before movement and verified byte-identical immediately after movement. `before_move.sha256` and `byte_preservation.log` record this check. Afterwards only the active reproduction guide was deliberately updated and a new index added; retained raw data, PDF, original logs, original archives and historical manifests were not rewritten. Original scientific source revisions remain unchanged and no native experiment was rerun or relabeled.

New `.gitattributes` entries disable automatic newline conversion for byte-sensitive PBEA result files and publisher sources, and define LF for PBEA analysis scripts. These rules prevent future Windows/WSL checkout differences; they do not pretend preexisting CRLF bytes had never changed.

The new current-layout archive/manifest use separate `layout_2026_10_21/` subdirectories. Old archives retain old internal paths and original hashes. Current packaging explicitly identifies a working-tree byte snapshot and records pending tracked changes, rather than claiming byte identity with a clean source checkout.

Validation includes 11 analyzer/layout tests; reanalysis of 540 security records and 300 benchmark blocks; reproduction of the historical 1,080 records and all 37 original manifest checks; canonical metrics comparison (allowing only line-ending differences); static manuscript-reference checks; and a complete PDF rebuild from the relocated project paths in a temporary directory. Validation logs are retained with this migration task. New package verification is run separately after creation, including extraction into a fresh directory. Any remaining submission/scientific limitations in the 204 handoff remain unchanged.

The old working branch is removed only after its commits are reachable from main and the requested remote update is confirmed. Its history remains recoverable through main; no unmerged branch work is intentionally discarded.
