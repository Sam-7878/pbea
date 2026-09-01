<!-- canonical_metrics_sha256:7eb58f10bab82a5610431c8da1c1e0109901a3b10a7d77f4ebfa3735b4289521 benchmark_sha256:82a5e2982a59fe185a9e00ba7cb1c66d8aa91a51e1e60fe9ebe1b75bf1536fac startup_sha256:0d03729c27fff748f225f83847e7d7120d38b5c89916ec4b418dda728dd623bb -->
# PBEA Round 1.1 revision inputs

Canonical corpus: 1,080 records from frozen evaluation source `62229cd`.

| Metric | B0 | B1 | B2 | P |
|---|---:|---:|---:|---:|
| S1 invalid-state rate | 100.0% | 0.0% | 100.0% | 0.0% |
| S7 rollback-failure rate | N/A | 0.0% | N/A | 0.0% |
| Aggregate CCR | 0.0% | 0.0% | 100.0% | 100.0% |
| S5 FCR | 0.0% | 50.0% | 100.0% | 100.0% |
| S6 quarantine rate | 0.0% | 100.0% | 0.0% | 100.0% |
| S0 BRSR | 100.0% | 100.0% | 100.0% | 100.0% |

S7 is not applicable to B0/B2 because their direct-mutation path contains no after-candidate fault point. It is excluded rather than scored as success or failure.

## Steady-state S0

| Mode | n | P50 µs | P95 µs | P99 µs |
|---|---:|---:|---:|---:|
| B0 Access-only | 5000 | 0.700 | 0.701 | 1.000 |
| B1 Transition-only | 5000 | 208.195 | 262.393 | 378.591 |
| B2 Runtime-only | 5000 | 0.700 | 0.701 | 0.800 |
| P Full-PBEA | 5000 | 184.995 | 218.495 | 320.293 |

No measurable median or P95 increase was observed for Runtime-only relative to Access-only in this synthetic S0 path at the reported measurement resolution after restrictions had been installed.

No component-level causal attribution is made from the aggregate Full-PBEA timing.

## Repeated startup

| Mode | n | P50 ms | P95 ms | Mean ms |
|---|---:|---:|---:|---:|
| B0 Access-only | 30 | 43.973 | 47.705 | 44.403 |
| B1 Transition-only | 30 | 44.523 | 47.403 | 44.822 |
| B2 Runtime-only | 30 | 44.653 | 48.104 | 44.995 |
| P Full-PBEA | 30 | 44.115 | 46.671 | 44.513 |

Startup remained in the tens-of-milliseconds range. No ranking claim is made among modes.
