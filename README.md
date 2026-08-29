# Policy-Bound Execution Architecture (PBEA)

PBEA (Policy-Bound Execution Architecture) is a cross-layer security architecture that binds each admitted transaction/transition to an explicit **Actor–Asset–Context–Operation (AACO)** descriptor, providing fail-closed authorization, invariant enforcement, state-change protection, and OS-level sandboxing.

---

## 1. Overview

PBEA was originally designed and validated inside `hete_sandbox` and has been separated into this standalone repository to serve as an independent policy-bound execution framework and evaluation service.

### Key Pillars

1. **AACO 5-Stage Transition Kernel**:
   - `authorize` → `validate` → `mutate_candidate` → `reconcile` → `commit`
   - Explicit terminal outcomes: `Commit`, `Reject`, `Quarantine`, `Abort`.
2. **Canonical Protocol Specification**:
   - RFC 8785 (JCS) JSON canonicalization.
   - Deterministic SHA-256 Effective Policy digests.
   - Declarative policy inheritance and fail-closed validation.
3. **OS-Level Isolation & Sandboxing**:
   - OpenBSD `pledge(2)` and `unveil(2)` system-call and filesystem restrictions.
   - Fail-closed startup enforcement (resource preparation before listener binding, locking unveil table before event loop).
4. **Three Verifier Modes for Comparative Evaluation**:
   - `access-only` (B0 Baseline): Common admission without transition invariant enforcement or OS sandboxing.
   - `transition-only` (B1 Baseline): AACO transition guards and policy digest binding without OS runtime constraints.
   - `full-pbea` (P Proposal): Full defense-in-depth combining transition policy, endpoint filtering, and native OS sandboxing.

---

## 2. Directory Structure

```text
pbea/
├── Cargo.toml                       # Rust Workspace definition (4 crates)
├── crates/
│   ├── poa-core/                    # AACO 5-stage kernel + RiskEvidence engine
│   ├── poa-protocol/                # JSON protocol spec, RFC 8785 canonicalization, SHA-256
│   ├── poa-sandbox/                 # OS isolation (OpenBSD pledge/unveil + Linux stub)
│   └── poa-verifier-example/        # PBEA Verifier server, VerifierMode, and probe binaries
├── protocol/
│   ├── schemas/                     # Data schemas (e.g. pbea-eval-transition-request.json)
│   ├── schema/                      # Protocol meta-schemas (poa-protocol-v1.schema.json)
│   ├── base/                        # Base protocol definitions
│   └── examples/                    # Protocol instance configurations (hete.verifier.pbea-eval.json)
├── evaluation/
│   └── comparative/                 # 3 × 9 × 30 comparative evaluation harness & scripts
└── docs/
    ├── architecture/                # Architecture specifications
    └── work_reports/
        └── 200_pbea/                # Complete experimental evaluation evidence & reports
```

---

## 3. Building and Testing

### Prerequisites
- Rust 2024 edition (1.85+)
- Python 3.12+ (for comparative evaluation scripts)

### Build
```bash
cargo check --workspace
cargo build --workspace --release
```

### Run Tests
```bash
cargo test --workspace
```

### Run Comparative Evidence Test
```bash
pytest evaluation/comparative/tests/test_evidence.py
```

---

## 4. License
MIT License (see [LICENSE](./LICENSE)).
