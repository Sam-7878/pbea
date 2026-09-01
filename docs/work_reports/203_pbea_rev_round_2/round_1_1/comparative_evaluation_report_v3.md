<!-- canonical_metrics_sha256:7eb58f10bab82a5610431c8da1c1e0109901a3b10a7d77f4ebfa3735b4289521 benchmark_sha256:82a5e2982a59fe185a9e00ba7cb1c66d8aa91a51e1e60fe9ebe1b75bf1536fac -->
# Comparative Evaluation Report (4-Mode Evaluation)

All values below are generated from the validated 1080-record JSONL corpus (4 modes × 9 scenarios × 30 iterations).

## 1. Effect Family Security Metrics Breakdown

| Effect Family | Metric | Access-only (B0) | Transition-only (B1) | Runtime-only (B2) | Full-PBEA (P) |
|---|---|---:|---:|---:|---:|
| State Integrity | S1 Invalid State Rate | 100.00% | 0.00% | 100.00% | 0.00% |
| State Integrity | S7 Rollback Failure Rate | N/A | 0.00% | N/A | 0.00% |
| Runtime Confinement | S2 Filesystem Containment | 0.00% | 0.00% | 100.00% | 100.00% |
| Runtime Confinement | S3 Process Exec Containment | 0.00% | 0.00% | 100.00% | 100.00% |
| Runtime Confinement | S4 Network Containment | 0.00% | 0.00% | 100.00% | 100.00% |
| Runtime Confinement | Aggregate CCR | 0.00% | 0.00% | 100.00% | 100.00% |
| Policy Binding | S8 Digest Mismatch Accept Rate | 100.00% | 0.00% | 100.00% | 0.00% |
| Fail-Closed Startup | S5 Malformed Policy FCR | 0.00% | 100.00% | 100.00% | 100.00% |
| Fail-Closed Startup | S5 Missing Resource FCR | 0.00% | 0.00% | 100.00% | 100.00% |
| Fail-Closed Startup | S5 Aggregate FCR | 0.00% | 50.00% | 100.00% | 100.00% |
| Outcome Semantics | S6 Quarantine Rate | 0.00% | 100.00% | 0.00% | 100.00% |
| Outcome Semantics | S7 Abort Rate | N/A | 100.00% | N/A | 100.00% |
| Benign Preservation | S0 BRSR | 100.00% | 100.00% | 100.00% | 100.00% |

## 2. Mode-by-Mode Detailed Metrics

### Access-only (B0)

| Metric | Numerator | Denominator | Rate | Wilson 95% CI |
|---|---:|---:|---:|---:|
| BRSR | 30 | 30 | 100.00% | 88.65%–100.00% |
| CCR | 0 | 90 | 0.00% | 0.00%–4.09% |
| FCR | 0 | 30 | 0.00% | 0.00%–11.35% |
| MESR | 180 | 180 | 100.00% | 97.91%–100.00% |
| OCA | 270 | 270 | 100.00% | 98.60%–100.00% |
| SIVR | 0 | 0 | N/A | N/A |

**Harness Timing (µs)**: n=270, min=8382, P50=9012, P95=21944, max=26163, mean=10131.59, population σ=3378.93.

### Transition-only (B1)

| Metric | Numerator | Denominator | Rate | Wilson 95% CI |
|---|---:|---:|---:|---:|
| BRSR | 30 | 30 | 100.00% | 88.65%–100.00% |
| CCR | 0 | 90 | 0.00% | 0.00%–4.09% |
| FCR | 15 | 30 | 50.00% | 33.15%–66.85% |
| MESR | 90 | 180 | 50.00% | 42.77%–57.23% |
| OCA | 270 | 270 | 100.00% | 98.60%–100.00% |
| SIVR | 0 | 135 | 0.00% | 0.00%–2.77% |

**Harness Timing (µs)**: n=270, min=8382, P50=9195, P95=13419, max=15037, mean=9702.89, population σ=1444.18.

### Runtime-only (B2)

| Metric | Numerator | Denominator | Rate | Wilson 95% CI |
|---|---:|---:|---:|---:|
| BRSR | 30 | 30 | 100.00% | 88.65%–100.00% |
| CCR | 90 | 90 | 100.00% | 95.91%–100.00% |
| FCR | 30 | 30 | 100.00% | 88.65%–100.00% |
| MESR | 90 | 180 | 50.00% | 42.77%–57.23% |
| OCA | 270 | 270 | 100.00% | 98.60%–100.00% |
| SIVR | 0 | 120 | 0.00% | 0.00%–3.10% |

**Harness Timing (µs)**: n=270, min=8429, P50=9069, P95=165388, max=209624, mean=26679.19, population σ=50294.36.

### Full-PBEA (P)

| Metric | Numerator | Denominator | Rate | Wilson 95% CI |
|---|---:|---:|---:|---:|
| BRSR | 30 | 30 | 100.00% | 88.65%–100.00% |
| CCR | 90 | 90 | 100.00% | 95.91%–100.00% |
| FCR | 30 | 30 | 100.00% | 88.65%–100.00% |
| MESR | 0 | 180 | 0.00% | 0.00%–2.09% |
| OCA | 270 | 270 | 100.00% | 98.60%–100.00% |
| SIVR | 0 | 240 | 0.00% | 0.00%–1.58% |

**Harness Timing (µs)**: n=270, min=8443, P50=9251, P95=187534, max=220617, mean=27830.00, population σ=52973.56.

## 3. S0 Steady-State Performance Benchmark

| Mode | Operations | Min (µs) | P50 (µs) | P95 (µs) | P99 (µs) | P50 Overhead vs B0 | P95 Overhead vs B0 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Access-only (B0) | 5000 | 0.50 | 0.70 | 0.70 | 1.00 | Baseline | Baseline |
| Transition-only (B1) | 5000 | 178.00 | 208.19 | 262.39 | 378.59 | +29642.1% | +37331.2% |
| Runtime-only (B2) | 5000 | 0.60 | 0.70 | 0.70 | 0.80 | +0.0% | +0.0% |
| Full-PBEA (P) | 5000 | 166.30 | 185.00 | 218.50 | 320.29 | +26327.9% | +31069.0% |

Runtime-only and Access-only have identical reported P50 and P95 values. No measurable median or P95 increase was observed for Runtime-only relative to Access-only in this synthetic S0 path at the reported measurement resolution after the OpenBSD restrictions had been installed.

The benchmark does not isolate component costs, so the Full-PBEA latency is not causally attributed to individual validation, canonicalization, digest, transition, or evidence-generation phases.

## 4. Claim-Boundary / Adaptive-Adversary Experiment Results

| Test ID | Test Name | Mode | Policy Allowed | Succeeded | Observed Outcome | Claim Verification Interpretation |
|---|---|---|:---:|:---:|---|---|
| BT1-access-only | Allowed Endpoint Misuse | Access-only (B0) | Yes | Yes | `permitted` | PBEA permits data delivery through policy-declared endpoints as designed; it does not infer intent within allowed capabilities. |
| BT1-transition-only | Allowed Endpoint Misuse | Transition-only (B1) | Yes | Yes | `permitted` | PBEA permits data delivery through policy-declared endpoints as designed; it does not infer intent within allowed capabilities. |
| BT1-runtime-only | Allowed Endpoint Misuse | Runtime-only (B2) | Yes | Yes | `permitted` | PBEA permits data delivery through policy-declared endpoints as designed; it does not infer intent within allowed capabilities. |
| BT1-full-pbea | Allowed Endpoint Misuse | Full-PBEA (P) | Yes | Yes | `permitted` | PBEA permits data delivery through policy-declared endpoints as designed; it does not infer intent within allowed capabilities. |
| BT2-access-only | Symlink Traversal Across Unveil Boundary | Access-only (B0) | No | Yes | `read-succeeded` | Host filesystem permitted symlink traversal to outside path (unveil disabled or non-OpenBSD environment). |
| BT2-transition-only | Symlink Traversal Across Unveil Boundary | Transition-only (B1) | No | Yes | `read-succeeded` | Host filesystem permitted symlink traversal to outside path (unveil disabled or non-OpenBSD environment). |
| BT2-runtime-only | Symlink Traversal Across Unveil Boundary | Runtime-only (B2) | No | No | `traversal-denied` | OpenBSD unveil kernel enforcement prevented symlink resolution to un-unveiled path outside boundary. |
| BT2-full-pbea | Symlink Traversal Across Unveil Boundary | Full-PBEA (P) | No | No | `traversal-denied` | OpenBSD unveil kernel enforcement prevented symlink resolution to un-unveiled path outside boundary. |
