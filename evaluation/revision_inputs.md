# PBEA Manuscript Revision Inputs (Round 1 Revision Artifact)

**Generated Date**: 2026-09-01  
**Frozen Source Commit**: `62229cd31ad1915cdd850fe3cfd670cddf208d0c` (`62229cd`)  
**Target Platform**: OpenBSD 7.9 (GENERIC.MP#449 amd64 / Hyper-V VM `192.168.1.103`)  
**Corpus Size**: 1,080 records (4 modes × 9 scenarios × 30 iterations)  
**Corpus Validation Status**: 100% Validated (1,080/1,080 cells, zero schema or semantic anomalies)

---

## 1. Executive Summary of New Findings & Changes

1. **Orthogonal Security Boundaries Proven (Symmetric 4-Mode Ablation)**:
   - **B1 (Transition-only)**: Prevents S1 domain state invariant violations (0.0% invalid state rate) but completely fails against S2–S4 runtime capability escapes (0.0% containment rate).
   - **B2 (Runtime-only)**: Completely contains S2–S4 runtime capability escapes (100.0% containment via OpenBSD `pledge`/`unveil`/allowlist) but completely fails against S1 domain state invariant violations (100.0% invalid state propagation rate).
   - **P (Full-PBEA)**: Achieves 0.0% invalid state propagation (S1/S7), 100.0% capability containment (S2–S4), 100.0% digest mismatch rejection (S8), 100.0% fail-closed startup (S5), 100.0% quarantine on repeated violation (S6), while maintaining 100.0% benign request success (S0).

2. **Real S0 Steady-State Latency Benchmark (5,000 operations per mode)**:
   - **Access-only (B0)**: Median (P50) = 0.70 µs, P95 = 0.70 µs, P99 = 1.00 µs
   - **Runtime-only (B2)**: Median (P50) = 0.70 µs, P95 = 0.70 µs, P99 = 0.80 µs (0.0% overhead vs B0)
   - **Transition-only (B1)**: Median (P50) = 208.19 µs, P95 = 262.39 µs, P99 = 378.59 µs
   - **Full-PBEA (P)**: Median (P50) = 185.00 µs, P95 = 218.50 µs, P99 = 320.29 µs (~0.185 ms total latency)
   - *Key takeaway*: Full-PBEA steady-state latency is sub-millisecond (< 0.2 ms), dominated by JSON schema validation and JCS SHA-256 digest hashing. Once installed at process startup, OpenBSD kernel sandboxing (`pledge`/`unveil`) imposes **zero marginal latency** on benign operations.

3. **Claim-Boundary Verification (BT1 & BT2)**:
   - **BT1 (Allowed Endpoint)**: Permitted loopback endpoint delivered payload successfully (100%), confirming that PBEA constrains effects outside declared policy without arbitrarily blocking permitted operations.
   - **BT2 (Symlink Traversal Across Unveil Boundary)**: Symlink resolution pointing outside unveiled root was blocked by OpenBSD kernel (`ENOENT`, errno 2) under B2 and P, but succeeded under B0 and B1.

---

## 2. Effect-Family Decomposed Security Metrics Table

| Effect Family | Evaluated Metric | Access-only (B0) | Transition-only (B1) | Runtime-only (B2) | Full-PBEA (P) |
|---|---|:---:|:---:|:---:|:---:|
| **State Integrity** | S1 Invalid State Propagation Rate | 100.0% (30/30) | **0.0%** (0/30) | 100.0% (30/30) | **0.0%** (0/30) |
| **State Integrity** | S7 Rollback Failure Rate | 0.0% (0/30) | 0.0% (0/30) | 0.0% (0/30) | 0.0% (0/30) |
| **Runtime Confinement** | S2 Filesystem Read Containment | 0.0% (0/30) | 0.0% (0/30) | **100.0%** (30/30) | **100.0%** (30/30) |
| **Runtime Confinement** | S3 Child Execution Containment | 0.0% (0/30) | 0.0% (0/30) | **100.0%** (30/30) | **100.0%** (30/30) |
| **Runtime Confinement** | S4 Egress Network Containment | 0.0% (0/30) | 0.0% (0/30) | **100.0%** (30/30) | **100.0%** (30/30) |
| **Runtime Confinement** | Aggregate CCR (S2–S4) | 0.0% (0/90) | 0.0% (0/90) | **100.0%** (90/90) | **100.0%** (90/90) |
| **Policy Binding** | S8 Digest Mismatch Accept Rate | 100.0% (30/30) | **0.0%** (0/30) | 100.0% (30/30) | **0.0%** (0/30) |
| **Fail-Closed Startup** | S5 Aggregate FCR | 0.0% (0/30) | 50.0% (15/30) | **100.0%** (30/30) | **100.0%** (30/30) |
| **Outcome Semantics** | S6 Quarantine Rate | 0.0% (0/30) | **100.0%** (30/30) | 0.0% (0/30) | **100.0%** (30/30) |
| **Benign Preservation** | S0 Benign Request Success Rate | **100.0%** (30/30) | **100.0%** (30/30) | **100.0%** (30/30) | **100.0%** (30/30) |

---

## 3. 4-Mode Scenario Matrix (S0–S8)

| Scenario ID | Description | Access-only (B0) | Transition-only (B1) | Runtime-only (B2) | Full-PBEA (P) |
|---|---|:---:|:---:|:---:|:---:|
| **S0** | Benign authorized operation | `success` (0/30) | `commit` (0/30) | `success` (0/30) | `commit` (0/30) |
| **S1** | Post-auth invariant violation | `success` (30/30) | `reject` (0/30) | `success` (30/30) | `reject` (0/30) |
| **S2** | Policy-external file read | `success` (30/30) | `success` (30/30) | `reject` (0/30) | `reject` (0/30) |
| **S3** | Undeclared helper execution | `success` (30/30) | `success` (30/30) | `terminated` (0/30) | `terminated` (0/30) |
| **S4** | Disallowed loopback connect | `success` (30/30) | `success` (30/30) | `reject` (0/30) | `reject` (0/30) |
| **S5** | Invalid runtime startup | `success` (0/30) | `startup-failure` (0/30) | `startup-failure` (0/30) | `startup-failure` (0/30) |
| **S6** | Repeated valid-actor violation | `success` (30/30) | `quarantine` (0/30) | `success` (30/30) | `quarantine` (0/30) |
| **S7** | Candidate creation fault | `success` (0/30) | `abort` (0/30) | `success` (0/30) | `abort` (0/30) |
| **S8** | Mismatched policy digest | `success` (30/30) | `reject` (0/30) | `success` (30/30) | `reject` (0/30) |

*Note*: Numbers in parentheses `(x/30)` denote successful malicious effect count out of 30 deterministic iterations.

---

## 4. Steady-State S0 Benchmark & Startup Cost

### 4.1 Steady-State Latency Distribution (5,000 Operations per Mode)

| Mode | n | Min (µs) | P50 (µs) | P95 (µs) | P99 (µs) | Max (µs) | Mean (µs) | P50 Overhead vs B0 |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| **Access-only (B0)** | 5,000 | 0.50 | 0.70 | 0.70 | 1.00 | 11.20 | 0.69 | Baseline |
| **Runtime-only (B2)** | 5,000 | 0.60 | 0.70 | 0.70 | 0.80 | 9.00 | 0.69 | +0.0% |
| **Transition-only (B1)** | 5,000 | 178.00 | 208.19 | 262.39 | 378.59 | 650.19 | 200.72 | +29,642.1% |
| **Full-PBEA (P)** | 5,000 | 166.30 | 185.00 | 218.50 | 320.29 | 636.09 | 189.69 | +26,327.9% |

### 4.2 One-Time Service Startup Breakdown

| Mode | Policy Parse (µs) | Schema Validation (µs) | Policy Digest (µs) | Sandbox (`pledge`/`unveil`) (µs) | Total Startup (ms) |
|---|---:|---:|---:|---:|---:|
| **Access-only (B0)** | 17.70 | 46,033.60 | 87.90 | 0.00 | 46.14 ms |
| **Transition-only (B1)** | 20.10 | 45,694.51 | 55.20 | 0.00 | 45.77 ms |
| **Runtime-only (B2)** | 13.80 | 43,004.87 | 56.40 | 101.90 | 43.18 ms |
| **Full-PBEA (P)** | 19.10 | 42,249.29 | 42.40 | 91.60 | 42.40 ms |

---

## 5. Claim-Boundary Experiment Results (BT1 & BT2)

| Test ID | Scenario | Mode | Policy Permission | Operation Succeeded | Outcome | Interpretation |
|---|---|---|:---:|:---:|---|---|
| **BT1-B0** | Allowed Loopback Endpoint | Access-only | Allowed | Yes | `permitted` | Policy allowlist not evaluated |
| **BT1-B1** | Allowed Loopback Endpoint | Transition-only | Allowed | Yes | `permitted` | Policy allowlist not evaluated |
| **BT1-B2** | Allowed Loopback Endpoint | Runtime-only | Allowed | Yes | `permitted` | Connection permitted by allowlist |
| **BT1-P** | Allowed Loopback Endpoint | Full-PBEA | Allowed | Yes | `permitted` | PBEA permits explicitly declared operations |
| **BT2-B0** | Symlink to External Path | Access-only | Prohibited | Yes | `read-succeeded` | Host OS allows symlink without sandbox |
| **BT2-B1** | Symlink to External Path | Transition-only | Prohibited | Yes | `read-succeeded` | Application guards do not restrict OS symlinks |
| **BT2-B2** | Symlink to External Path | Runtime-only | Prohibited | No | `traversal-denied` | OpenBSD `unveil` blocks external symlink target (`ENOENT`) |
| **BT2-P** | Symlink to External Path | Full-PBEA | Prohibited | No | `traversal-denied` | OpenBSD `unveil` blocks external symlink target (`ENOENT`) |

---

## 6. Comparison Against Legacy 810-Record Baseline (`1bcfa8b`)

| Aspect | Legacy Baseline (`1bcfa8b`) | New Evaluated Revision (`62229cd`) | Rationale / Academic Impact |
|---|---|---|---|
| **Evaluated Modes** | 3 modes (B0, B1, P) | **4 modes (B0, B1, B2, P)** | Provides complete two-way ablation; proves non-substitutability |
| **Total Evaluation Corpus** | 810 records | **1,080 records** | Completely re-executed on OpenBSD 7.9 without record synthesis |
| **Security Metric Structure** | Single headline MESR (180/180 → 90/180 → 0/180) | **Decomposed Effect Families** (State Integrity, CCR, Digest Binding, FCR, QR) | Eliminates reviewer critique regarding arbitrary denominator aggregation |
| **S0 Latency Evaluation** | Mixed-scenario test harness duration (TODO note in paper) | **Dedicated 5,000-op Steady-State S0 Benchmark** | Replaces harness timing with true production request cost (~185 µs) |
| **Claim Boundary Validation** | Qualitative disclaimer in Limitations | **Empirical BT1 & BT2 Experiments** | Proves claim boundary: PBEA enforces declared policy, not arbitrary heuristics |

---

## 7. Artifact Manifest & Verification Paths

- **Raw Evidence Directory**: `docs/work_reports/202_pbea_rev_round_1/raw/`
  - `access-only.jsonl` (270 records)
  - `transition-only.jsonl` (270 records)
  - `runtime-only.jsonl` (270 records)
  - `full-pbea.jsonl` (270 records)
- **Generated Tables Directory**: `docs/work_reports/202_pbea_rev_round_1/generated/`
  - `family_metrics.tex` & `family_metrics.csv`
  - `scenario_matrix.tex` & `scenario_matrix.csv`
  - `s0_latency.tex` & `s0_latency.csv`
  - `startup_latency.csv`
  - `boundary_results.tex` & `boundary_results.csv`
  - `comparative_security.tex` & `aggregate_metrics.csv`
  - `security_metrics.tex`
  - `metrics.json`, `s0_benchmark.json`, `boundary_results.json`
- **Manifests**:
  - `docs/work_reports/202_pbea_rev_round_1/manifests/manifest.json`
  - `docs/work_reports/202_pbea_rev_round_1/manifests/manifest.sha256`
