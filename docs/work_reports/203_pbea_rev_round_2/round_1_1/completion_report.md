# PBEA Round 1.1 completion report

Status: **Completed**. Frozen evaluation source `62229cd31ad1915cdd850fe3cfd670cddf208d0c` was retained; hardened reporting/validation tools are revision `f2be0bf`.

## A. Root Cause of S7 Inconsistency

The 120 immutable S7 records are internally consistent at the state-hash level. The inconsistency came from two reporting paths:

1. `compute_security_metrics.py` counted every S7 state change as a rollback failure, including B0/B2 records where the after-candidate fault was never attempted.
2. The manually maintained revision input table reported zero for every mode without encoding applicability or a denominator.

The frozen probe takes the direct-mutation branch in B0/B2. That branch contains no candidate-isolation fault point, and its records explicitly say `malicious_effect_attempted=false`. The ordinary successful mutation changes the state hash, but it is not a failed rollback. This is work-order Case B, not Case A. B1/P take the guarded candidate path and record `abort` with identical before/after hashes.

## B. Correct S7 Result

| Mode | Outcome | State propagation | Rollback failure | Malicious effect | Metric treatment |
|---|---|---|---|---|---|
| B0 Access-only | success | normal direct mutation propagated | N/A | no fault attempted or succeeded | excluded, 0/0 |
| B1 Transition-only | abort | none | 0/30 | none succeeded | included, 0/30 |
| B2 Runtime-only | success | normal direct mutation propagated | N/A | no fault attempted or succeeded | excluded, 0/0 |
| P Full-PBEA | abort | none | 0/30 | none succeeded | included, 0/30 |

The validator now rejects guarded S7 Abort records with changed hashes, S7 effect contradictions, incorrect fault-location metadata, and attempts to treat B0/B2 as applicable fault effects. The canonical metrics generator is the only source for S7 rates.

## C. Re-experiment Decision

The 1,080-record security matrix was **not re-executed**. The frozen evidence already distinguishes the absent B0/B2 fault attempt from the B1/P guarded Abort through mode, outcome, state hashes, target metadata, and effect-attempt fields. No Rust probe or security semantics were changed. Re-running would add measurement variation without repairing missing evidence.

Only startup timing was newly collected: the existing frozen `s0_benchmark` binary was invoked in 120 independent processes (30 per mode, round-robin). This does not change the security corpus.

## D. Final 4-Mode Metrics

All values are generated from `generated/metrics.json` after validation of 1,080/1,080 records.

| Metric | B0 | B1 | B2 | P |
|---|---:|---:|---:|---:|
| S1 invalid-state propagation | 30/30 (100%) | 0/30 (0%) | 30/30 (100%) | 0/30 (0%) |
| S7 rollback failure | N/A (0/0) | 0/30 (0%) | N/A (0/0) | 0/30 (0%) |
| S2–S4 aggregate CCR | 0/90 (0%) | 0/90 (0%) | 90/90 (100%) | 90/90 (100%) |
| S8 digest-mismatch acceptance | 30/30 (100%) | 0/30 (0%) | 30/30 (100%) | 0/30 (0%) |
| S5 fail-closed startup | 0/30 (0%) | 15/30 (50%) | 30/30 (100%) | 30/30 (100%) |
| S6 quarantine | 0/30 (0%) | 30/30 (100%) | 0/30 (0%) | 30/30 (100%) |
| S0 benign success | 30/30 (100%) | 30/30 (100%) | 30/30 (100%) | 30/30 (100%) |

The symmetric result remains intact: B1 supplies transition integrity without runtime confinement; B2 supplies runtime confinement without transition integrity; P combines both.

## E. Benchmark Validity

### Functional equivalence

`s0_functional_equivalence.json` verifies 30 S0 records per mode with the same `verify_transition` operation, the same resulting domain-state hash, a state-changing normal operation, and the same normalized application-visible success. Security-specific work differs by design.

### Steady state

The retained S0 benchmark used 100 warm-up operations and 5,000 measured operations per mode. P50/P95 were B0 0.700/0.701 µs, B1 208.195/262.393 µs, B2 0.700/0.701 µs, and P 184.995/218.495 µs.

No measurable median or P95 increase was observed for B2 relative to B0 on this synthetic path at the reported resolution after OpenBSD restrictions had been installed. This is not a zero-cost claim. Component instrumentation was intentionally omitted because it would alter the measured code path; no causal attribution of P's aggregate time to individual phases is made.

### Repeated startup

| Mode | n | P50 ms | P95 ms | Mean ms | Population σ ms |
|---|---:|---:|---:|---:|---:|
| B0 | 30 | 43.973 | 47.705 | 44.403 | 1.379 |
| B1 | 30 | 44.523 | 47.403 | 44.822 | 1.468 |
| B2 | 30 | 44.653 | 48.104 | 44.995 | 1.674 |
| P | 30 | 44.115 | 46.671 | 44.513 | 1.413 |

Startup was in the tens-of-milliseconds range and dominated by schema initialization in this implementation. No mode ranking is claimed.

## F. Artifact Verification

- Security records validated: 1,080/1,080.
- Startup records collected: 120/120.
- Report consistency checks: passed for scenario matrix, S1, S7, S2–S4 CCR, S5, S6, S0, benchmark provenance, corpus size, source revision, and terminology.
- SHA-256 files checked: 37.
- Hash failures: 0.
- Frozen evaluation source: `62229cd31ad1915cdd850fe3cfd670cddf208d0c`.
- Reporting/validation tool revision: `f2be0bf`.

`manifests/verification_output.txt` contains one `OK` result per file, and `verification_summary.json` is the machine-readable verdict.

## G. Manuscript-Ready Claims

- In the evaluated 30-run cells, B1 and P admitted no S1 invalid state, while B0 and B2 admitted 30/30.
- S7 is applicable only to transition-guarded B1/P; both aborted 30/30 with no observed state propagation.
- No prohibited S2–S4 capability effect succeeded in the 90 evaluated B2 attempts or 90 evaluated Full-PBEA attempts.
- B1 did not substitute for runtime confinement, and B2 did not substitute for transition integrity in this symmetric ablation.
- P rejected all 30 evaluated digest-mismatch requests, while B0/B2 accepted all 30.
- All four modes preserved the 30/30 benign S0 outcome in the security corpus.
- Runtime-only and Access-only showed no measurable P50/P95 difference for the synthetic benign path at the reported resolution after restrictions were installed.
- BT1 shows that a policy-allowed endpoint operation is not blocked based on inferred malicious intent; BT2 shows that the tested symlink traversal outside unveiled paths is denied in B2/P.
- The observed startup distribution is approximately tens of milliseconds on this OpenBSD 7.9 VM; it does not establish a mode performance ranking.

These claims are bounded to the evaluated fixtures, source revision, OpenBSD platform, and sample sizes. They do not establish universal prevention of runtime attacks or universal superiority over other systems.
