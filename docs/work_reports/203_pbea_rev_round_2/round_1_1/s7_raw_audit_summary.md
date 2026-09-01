# S7 raw evidence audit

S7 asks whether a fault after candidate preparation propagates partial state.

The frozen raw corpus implements **Case B** for B0/B2: those direct-mutation paths have no after-candidate fault point. Their ordinary mutation changes state, but `malicious_effect_attempted=false`; therefore rollback metrics are not applicable and use denominator 0.

| Mode | Records | Outcome | State changed | Fault injected | Rollback failures | Metric denominator |
|---|---:|---|---:|---:|---:|---:|
| access-only | 30 | success | 30 | 0 | 0 | 0 |
| transition-only | 30 | abort | 0 | 30 | 0 | 30 |
| runtime-only | 30 | success | 30 | 0 | 0 | 0 |
| full-pbea | 30 | abort | 0 | 30 | 0 | 30 |

Root cause: the metric generator counted every S7 state change as rollback failure, while `revision_inputs.md` manually reported zero. Raw hashes were internally consistent; the denominator semantics and hand-maintained report were not.

Re-experiment decision: not required. The immutable records contain enough information to distinguish absent fault attempts (B0/B2) from guarded Abort behavior (B1/P).
