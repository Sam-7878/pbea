# Policy-Bound Execution Architecture (PBEA) Architecture Specification

**Version**: 1.0.0 (Post-Extraction)  
**Date**: 2026-08-29  
**Repository**: `pbea`  
**Origins**: Extracted from `hete_sandbox` (referenced in `architecture.2026.08.24.md`)

---

## 1. Executive Summary & Problem Definition

Traditional authorization models (e.g. RBAC, ABAC, standard Zero-Trust Access) govern request admission at the boundary. Once an actor is authenticated and permitted access, execution proceeds under full ambient authority of the receiving process. If the application logic contains vulnerabilities, domain invariant checks fail, or post-authorization logic misbehaves, existing controls fail to prevent unauthorized state alteration, file system exfiltration, or rogue network egress.

**PBEA (Policy-Bound Execution Architecture)** solves this problem by binding each admitted transaction/transition to an explicit **Actor–Asset–Context–Operation (AACO)** descriptor. It enforces defense-in-depth across the entire execution lifecycle:
1. **Pre-Execution**: Strict schema validation, canonical JSON serialization (RFC 8785), and SHA-256 Effective Policy digest verification.
2. **Transition Execution**: AACO 5-stage kernel with candidate isolation, invariant reconciliation, and explicit terminal outcomes (`Commit`, `Reject`, `Quarantine`, `Abort`).
3. **Runtime OS Sandboxing**: Dynamic OS-level restriction (OpenBSD `pledge(2)` system-call restrictions and `unveil(2)` path access control) with fail-closed startup.

---

## 2. Architecture & Layered Decomposition

```text
pbea/
├── crates/
│   │  ── [Layer 0: AACO 5-Stage Kernel] ──
│   ├── poa-core/
│   │   ├── kernel.rs       # AacoHooks trait, 5-stage execute_transition pipeline
│   │   ├── risk.rs         # RiskEvidence, QuarantinePolicy, basis points evaluation
│   │   ├── outcome.rs      # TransitionOutcome { Commit, Reject, Quarantine, Abort }
│   │   ├── audit.rs        # Deterministic AuditRecord generator
│   │   └── descriptor.rs   # TransitionDescriptor (AACO metadata wrapper)
│   │
│   │  ── [Layer 0: Protocol Specification Engine] ──
│   ├── poa-protocol/
│   │   ├── model.rs        # ProtocolSpec, ProcessConstraints, DataConstraints
│   │   ├── canonical.rs    # RFC 8785 (JCS) JSON canonicalization
│   │   ├── digest.rs       # SHA-256 Effective Policy digest computation
│   │   ├── inheritance.rs  # Declarative protocol inheritance & merge
│   │   └── validator.rs    # JSON Schema validation
│   │
│   │  ── [Layer 0: OS Sandboxing & Process Isolation] ──
│   ├── poa-sandbox/
│   │   ├── backend.rs      # ProcessConstraintBackend trait & StartupEnforcement state machine
│   │   ├── openbsd.rs      # OpenBSD pledge(2) + unveil(2) C FFI enforcement
│   │   ├── linux.rs        # Linux stub (Landlock/seccomp expansion interface)
│   │   ├── noop.rs         # No-op backend (for non-sandboxed dev/testing)
│   │   └── mapper.rs       # String permission to pledge/unveil mapper
│   │
│   │  ── [Layer 1: Verifier Service & Comparative Harness] ──
│   └── poa-verifier-example/
│       ├── main.rs         # Fail-closed TCP Verifier service daemon
│       ├── lib.rs          # Verifier core engine & inbound network authorization
│       ├── mode.rs         # VerifierMode: AccessOnly, TransitionOnly, FullPbea
│       ├── adversarial.rs  # S0-S8 controlled adversarial scenario fixtures
│       ├── fault_injection.rs # Controlled fault injection at reconciliation
│       └── bin/
│           ├── adversarial_probe.rs      # S0-S8 probe binary
│           ├── controlled_helper.rs      # Child helper for S3 execution testing
│           ├── openbsd_startup_probe.rs  # OpenBSD fail-closed startup lifecycle probe
│           └── sandbox_probe.rs          # Sandbox path violation probe
```

---

## 3. The 5-Stage AACO Pipeline

Every admitted operation is executed strictly through the 5-stage transition pipeline:

```text
       ┌───────────┐
       │ authorize │ ── (Failure) ──► Reject
       └─────┬─────┘
             │ (Pass)
       ┌─────▼─────┐
       │ validate  │ ── (Failure) ──► Reject
       └─────┬─────┘
             │ (Pass)
       ┌─────▼───────────────┐
       │ mutate_candidate    │ ── (Internal Error) ──► Abort
       └─────┬───────────────┘
             │ (Candidate ready)
       ┌─────▼─────┐
       │ reconcile │ ── (Risk Threshold Exceeded) ──► Quarantine
       └─────┬─────┘    (Reconciliation Failure)  ──► Abort
             │ (Invariants Hold)
       ┌─────▼─────┐
       │  commit   │ ──► Commit (State permanently installed, Audit logged)
       └───────────┘
```

---

## 4. Verifier Modes & Comparative Security Evaluation

To mathematically prove security benefits without confounding variables, PBEA defines three explicit, closed verifier modes:

| Mode | Capability Profile | Transition Policy | Policy Digest Binding | OS Sandboxing (`pledge`/`unveil`) |
|---|---|---|---|---|
| **`access-only` (B0)** | Standard perimeter access control | Disabled (direct business handler) | Disabled (`null`) | Disabled |
| **`transition-only` (B1)** | Application-level invariant guards | Enabled (AACO 5-stage pipeline) | Enabled (SHA-256 digest) | Disabled |
| **`full-pbea` (P)** | Defense-in-depth policy-bound execution | Enabled (AACO 5-stage pipeline) | Enabled (SHA-256 digest) | Enabled (OpenBSD native, locked) |

### Tested Scenarios (S0–S8)
- **S0**: Benign authorized transition (Baseline functionality).
- **S1**: Post-authorization domain invariant violation.
- **S2**: Controlled filesystem read outside unveiled path.
- **S3**: Controlled helper binary execution after pledge drop.
- **S4**: Controlled egress connection denied by application endpoint allowlist.
- **S5**: Invalid runtime policy startup (Fail-closed verification).
- **S6**: Repeated policy violation by legitimate actor (Quarantine trigger).
- **S7**: Injected fault after candidate preparation before commit (State rollback).
- **S8**: Mismatched deterministic policy digest.

---

## 5. Provenance & Artifact Heritage

1. **Protocol Schema**: `protocol/schemas/pbea-eval-transition-request.json` defines the canonical contract.
2. **Evaluated Evidence**: The frozen 3 × 9 × 30 matrix (810 records) and resulting metrics are preserved in `docs/work_reports/200_pbea/`.
3. **Relationship with `hete_sandbox`**: `hete_sandbox` retains the electronic warrant domain implementation, whereas `pbea` serves as the reusable, domain-neutral Policy-Bound Execution Architecture.
