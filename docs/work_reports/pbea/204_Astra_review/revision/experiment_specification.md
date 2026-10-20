# Prespecified additive campaign (W05–W09)

Machine-readable specification: `evaluation/mdpi_revision/scenarios.json`. Frozen implementation: `afe94eb`. This specification was created before native execution.

## Security and functional cases

Two modes use the same inventory transitions, policy fixture, runtime backend, resource preparation and observation pipe. B3 is `unbound-composition`; P is `full-pbea`. B3 does not apply the cross-component identity equality contract. Thirty repetitions per case/mode are planned, totaling 540 new records, separate from the old corpus.

| Case | Controlled difference | Prespecified interpretation |
|---|---|---|
| BIND-aligned | all identities agree | same benign result expected |
| BIND-runtime-epoch | runtime policy epoch differs | bound composition should reject declared skew |
| BIND-stale-evidence | evidence ID differs | reject before dispatch, not retroactively rewrite evidence |
| BIND-inheritance-drift | stale resolved epoch | proxy for one layer using stale resolved policy; not an independent resolver bug |
| BIND-request-version | request expects different epoch | check worker/request identity |
| BIND-equal-id-wrong-install | trusted-mapper defect with matching IDs | no detection guarantee; successful forbidden read is retained |
| BOUND-send-before-abort | loopback receiver sees allowed send, candidate then aborts | domain nonpublication does not roll back transmission |
| BOUND-preopened-fd | outside synthetic file opened before unveil | distinguish descriptor authority from a new pathname open |
| SERVICE-sequence | reserve, oversubscribe, duplicate, abort, cancel, repeated cancel | conservation and sequence semantics in one domain |

Each native child receives the fixed case/mode arguments from a trusted supervisor. JSON records include source revision, run ID, mode, case, iteration, actual observations and evidence origin. Failed children remain records; unobserved child state is omitted rather than synthesized. No expectation is substituted for observation.

The schema/semantic validator checks 540 unique cells and source consistency, but does not insist that Full-PBEA succeeds. A negative fixture with well-formed security failure must remain valid input to analysis.

## Performance

Twenty independent process blocks for each of five modes and three workloads produce 300 process records. Each process has 100 warm-ups and 500 measured operations; all 150,000 raw operation timings are retained. Mode ordering rotates by block. Workloads are one asset, 128 assets, and allowed file I/O. Empty-timer samples are separately retained.

The uncertainty unit is the process block. Pooled P50/P95/P99, per-block median ranges, absolute increment and baseline ratio are descriptive. No samples are deleted for being slow. This expands state occupancy and I/O coverage but does not establish policy/invariant-count scaling or throughput/memory bounds.
