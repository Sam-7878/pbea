# PBEA MDPI revision — implementation and evidence handoff

Date: 2026-10-20. Branch: `revision/mdpi-2026-10-20`.

## Outcome

The revision now has strict duplicate-key parsing, worker-policy prepare/install consistency, explicit runtime-plan identity, an additive reservation domain, a B3 comparison and native boundary campaign, independent-process raw benchmarks, reproducible tables, and a self-contained MDPI Article draft. Original manuscript inputs and historical raw evidence are unchanged. Source freeze: `afe94eb08acac168b2a6e5c6c3c5562df330e909`; reporting tools were developed separately. Exact report revisions are recorded by Git and the artifact manifest.

This is **not submission-ready approval**. External publication, author declarations, final venue checks, and the remaining measurement coverage below are not silently marked complete.

## Native results

OpenBSD 7.9 native workspace tests passed (72 tests across test binaries; no failed tests). The new campaign retained 540 security records and 300 independently started benchmark processes, containing 150,000 measured operations. The existing 1,080-record corpus reproduces the prior canonical metrics and all 37 historical manifest hashes match.

Four supplied component-ID mismatch cases: B3 accepted 120/120, P rejected 120/120. Equal-ID/wrong-install: both modes performed all 30 outside reads per mode. This intentionally broken trusted mapper is a counterexample to claiming that identity checks attest kernel configuration. Allowed transmissions remained visible after candidate Abort; preopened FDs retained read authority while new pathname reads were denied. The reservation sequence preserved its invariant in every recorded trial. Full details and costs are generated in `generated/results.md` and `generated/metrics.json`, not inferred from pass/fail expectations.

## Work-order disposition

| ID | Disposition | Material and remaining limits |
|---|---|---|
| W01 | Implemented | Evidence inventory, original archive, full source provenance, historical reanalysis and missing old sample series disclosed |
| W02 | Implemented | Immutable before snapshot in pseudocode; separate trust/domain state; successful effects; admissibility versus correctness; native regressions |
| W03 | Implemented within observed failure model | Derived supervisor-origin view, unknown child state, separate native/application outcomes; no crash-state guarantee |
| W04 | Implemented bounded contract | Strict parser, native call mapping, worker epoch/plan IDs, preparation guard, FD boundary; not universal JCS or attestation |
| W05 | Implemented | 9 × 2 × 30 additive native records; both layers active in B3; explicit same-ID counterexample and narrowed integration claim |
| W06 | Implemented bounded case study | Real reserve/cancel state transitions, six-operation sequence, multi-field conservation; parser/inheritance/startup regression families; no fuzz campaign claimed |
| W07 | Implemented for serial service | Receiver-observed send then Abort, no external rollback, serial/in-memory and failure-model limits |
| W08 | Substantial implementation; coverage limitation remains | 20 independent processes/cell, rotating modes, raw samples/timer, 1/128 assets and allowed filesystem I/O, quantiles/deltas/ratios/block ranges. Policy/invariant-count scaling and allowed-network-I/O timing are not measured. Hyper-V host scheduling/VM settings were not independently inventoried in this session; measured guest metadata retained |
| W09 | Implemented for retained corpora | Outcome-independent new validator, completeness/duplicate/provenance/timing checks, eight negative/acceptance tests, canonical generated tables; actual failures retained |
| W10 | Local package implemented; external gate open | Source/lockfile/license/schema/fixtures/raw/tools/README/manifests; isolated extracted-package reanalysis. Public/reviewer URL needs author-approved publication; no DOI invented |
| W11 | Revised; author literature gate open | UCON, TxBox, integrity/contracts, capabilities, IFC, RASP/AppSensor and BeeBox comparison. Targeted primary-source search, not an exhaustive 2024–2026 systematic review |
| W12 | Implemented working draft | Official unmodified publisher class/styles, separate manuscript directory, shared TikZ source, complete BibTeX build and all-page visual QA; author-confirmation text intentionally remains |
| W13 | Implemented bounded draft | Self-contained 12-page Article, 173-word abstract, separate Results and claim–evidence matrix; no unsupported general dominance claim |
| W14 | Explicitly deferred optional scope | No Linux native backend, distributed commit, LLM-agent or IoT claims added |
| W15 | Drafts ready; author/editor gates open | Scope-inquiry/cover drafts only. No sending, submitting, publication or APC action; latest APC/indexing and conflicting issue deadline unresolved |

The manuscript explicitly states its measured scope. The unmeasured W08 coverage should be expanded if authors want a broader performance/scalability claim; the present results must not be presented as that claim.

## Files and verification

- Revised source: `docs/papers/_46_01_PBEA/mdpi_revision/main.tex`.
- Review PDF and standalone diagram: this report's `output/`.
- Native original data: `raw/`; reanalysis: `generated/`; logs: `logs/`; rendered full-page QA: `qa/`.
- Reproduction: `REPRODUCTION.md`; local self-contained artifact and SHA-256: `packages/`; input manifest: `manifests/`.
- Submission facts/remaining approvals: `venue_and_author_gates.md` and `submission_drafts.md`.

The actual WSL environment is Ubuntu 26.04.1 after the user's reinstall; it was not misreported as the formerly requested 24.04. Native evaluation ran on the configured OpenBSD 7.9 host after restoring access via the user's SSH agent. Connection settings were read from `local_security/open_bsd_connection.json` before remote connections; private keys and connection JSON are excluded from the reviewer artifact.

Preexisting tracked deletions at old report locations belong to the user's shared worktree and remain unstaged. No reset/clean was used and no AntiGravity changes were restored over.
