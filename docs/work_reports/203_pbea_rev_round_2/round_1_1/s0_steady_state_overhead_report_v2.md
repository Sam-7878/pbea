<!-- canonical_metrics_sha256:7eb58f10bab82a5610431c8da1c1e0109901a3b10a7d77f4ebfa3735b4289521 benchmark_sha256:82a5e2982a59fe185a9e00ba7cb1c66d8aa91a51e1e60fe9ebe1b75bf1536fac startup_sha256:0d03729c27fff748f225f83847e7d7120d38b5c89916ec4b418dda728dd623bb -->
# S0 steady-state overhead report v2

Method: 100 warm-up operations followed by 5000 measured operations per mode on openbsd-x86_64.

| Mode | n | P50 µs | P95 µs | P99 µs |
|---|---:|---:|---:|---:|
| B0 Access-only | 5000 | 0.700 | 0.701 | 1.000 |
| B1 Transition-only | 5000 | 208.195 | 262.393 | 378.591 |
| B2 Runtime-only | 5000 | 0.700 | 0.701 | 0.800 |
| P Full-PBEA | 5000 | 184.995 | 218.495 | 320.293 |

No measurable median or P95 increase was observed for Runtime-only relative to Access-only in this synthetic S0 path at the reported measurement resolution after restrictions had been installed.

No component-level causal attribution is made from the aggregate Full-PBEA timing.

Startup mode ranking is not inferred from steady-state measurements; the 30-repetition startup summary is reported in revision_inputs_v2.md and generated/startup_latency.csv.
