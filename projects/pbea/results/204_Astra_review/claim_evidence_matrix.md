# Claim–evidence matrix

Each entry identifies the evidence actually used, not a proposed guarantee. All report paths below are relative to this revision folder.

| Claim | Implementation / original source | Evidence / derived artifact | Limit |
|---|---|---|---|
| Candidate publication preserves tested domain invariant | `poa-core` contracts, example payment hooks, new `inventory.rs` | historical S1 and applicable S7; `raw/security.jsonl`, SERVICE-sequence | Serial, in-memory state; inventory is an additive domain example, not a production deployment |
| Before-state is immutable in the revised algorithm | `main.tex`, Algorithm 1; inventory candidate cloning | native workspace regression tests; historical S1/S7 hashes | The reviewed pseudocode defect was not reported as an existing Rust bug |
| Native termination is not application Reject | historical supervisor, corrected observation contract | `generated/historical_observation_view.jsonl`, original S3 records | Child post-state remains unobserved; parent hashes are not child state |
| Strict parsing rejects duplicate members | `poa-protocol/src/strict_json.rs`, loader | native_tests.log strict JSON and canonical boundary tests | Policy-specific normalization, not a general RFC 8785 certification |
| Prepared runtime policy cannot silently change at install | `poa-sandbox/src/backend.rs` | sandbox prepare/install regression; runtime plan in native rows | Trusted mapper still required; no remote attestation |
| Supplied component identity skew is rejected | `binding.rs`, `mdpi_probe.rs`, source `afe94eb` | four mismatch fixtures: B3 120 Commit; P 120 Reject | Inheritance-drift fixture models a stale resolved epoch, not arbitrary resolver corruption |
| Equal metadata IDs do not prove correct installation | explicit mapper-defect fixture | BIND-equal-id-wrong-install: 30 successful outside reads per mode | Intentional violation of trusted-mapper assumption; retained as counterexample, not claimed prevention |
| Allowed external effect can survive Abort | synthetic loopback receiver, detached inventory candidate | BOUND-send-before-abort: receiver reads 27 bytes, all 60 records, domain unchanged | No network rollback/outbox/durable transaction guarantee |
| Preopened descriptors retain authority | actual File read before/after native install | BOUND-preopened-fd: 60 handle reads succeed; 60 new pathname reads fail | No general inherited-FD sanitizer claimed |
| Reservation sequence preserves conservation | `inventory.rs`, actual reserve/cancel calls | SERVICE-sequence: 60 exact sequences, invariant true | No concurrency or OS-crash recovery claim |
| Measured cost is nonzero | `mdpi_probe --bench`, rotating process schedule | 300 blocks, 150,000 timings; `generated/metrics.json` | Sequential samples are not independent trials; only three workloads and one policy size |
| Historical reported results reproduce | frozen historical tools and raw corpus | `historical_metrics.json`, 37-file verification | Historical individual steady-state timing samples unavailable |

`generated/metrics.json` is the canonical new numerical result. Historical data have their own canonical `generated/historical_metrics.json`. Generated TeX tables must not be edited by hand. The corpus, B3 design, and deliberately faulty mapper are not evidence of superiority over UCON, TxBox, commercial RASP, or all independently managed layers.
