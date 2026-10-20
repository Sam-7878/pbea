# W02–W04 implementation contract and runtime mapping

## Policy transformation

Source JSON is parsed by `poa_protocol::strict_json::parse` before typed validation. Duplicate keys are rejected recursively. Schema validation and semantic checks precede inheritance/default/conflict resolution (`PolicyRepository`). A resolved `EffectivePolicy` is normalized by the existing policy-specific canonicalizer and hashed. `RuntimePlan::from_policy` then derives the normalized unveil call list, pledge string, lock bit, and network-policy-containing plan identity.

The legacy canonicalizer is **not a general RFC 8785 implementation**. It uses Rust/serde JSON serialization and explicitly set-like policy arrays. Golden digests are preserved rather than changed covertly. Ordered arbitrary arrays are preserved; composed and decomposed Unicode remain different strings. General ECMAScript floating serialization and UTF-16 key ordering are not claimed. Numeric policy fields are typed bounded integers. A canonicalization error propagates as failure.

## Native installation

| Stage | Concrete action | Failure behavior |
|---|---|---|
| Validate backend | production/openbsd/lock required | no ready state |
| Prepare resources | metadata check for each required path | missing path prevents listener/business loop |
| Bind listener/open audit | resource handles acquired before confinement | failure aborts startup |
| Unveil | normalized absolute path and r/w/x/c permissions | syscall error prevents readiness |
| Empty unveil policy | mask `/` with empty permission set | does not confuse lock-only with deny-all |
| Lock | `unveil(NULL,NULL)` | error prevents readiness |
| Pledge | sorted validated promise string; `execpromises=NULL` | error prevents readiness |
| Ready evidence | effective policy ID, epoch, backend and runtime plan ID | local provenance, not attestation |
| Endpoint check | trusted application IP/port/protocol allowlist | denied before connect; not kernel endpoint filtering |

`StartupEnforcement` now records the prepared effective-policy digest and rejects a different policy at installation, before any filesystem constraints are applied. A unit test demonstrates this rejection with an explicit development backend; native testing is kept distinct.

## Policy lifetime and TCB

A worker has one immutable runtime policy. Multiple operations may share it, and changing/expanding it requires a new worker. OpenBSD restrictions cannot be arbitrarily undone per request. The mapper, policy source, application endpoint check, evidence writer/supervisor, kernel and hypervisor are trusted. Matching IDs cannot detect a mapper that lies about concrete installation. The equal-ID/wrong-install fixture deliberately demonstrates that boundary rather than promising attestation.

## State and outcome semantics

The revised pseudocode captures immutable domain and trust hashes before mutation, records them separately, and uses a before/candidate invariant relation. The original Rust probe already captured a domain hash before processing; the reviewed pseudocode defect is not reported as a previously fixed Rust state-hash bug.

Payment hooks reject invalid amounts before candidate creation, then create a tuple candidate and install it in reconcile. The optional risk-aware core has distinct read-only reconciliation and commit stages. The new inventory service clones its state, checks reservation and conservation constraints, and publishes only after success. Core crate semantics are not rewritten.

S3 in the historical probe terminates an isolated child, not the parent verifier service. Its signal and marker observation come from the parent. Parent domain hashes are not the child's post-termination state. `generated/historical_observation_view.jsonl` is a derived interpretation that retains original run IDs and marks unknown child state; it does not edit or replace raw records.

Preopened audit files/listeners and inherited descriptors are part of the authority analysis. `unveil` pathname checks do not imply revocation of existing descriptors. Safe allowed-child execution and execpromises inheritance are not evaluated. Serial processing, in-memory state, no crash persistence, and no external-I/O rollback remain explicit limits.
