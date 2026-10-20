# Additional native evidence

Source: `afe94eb`. Security records: 540. Process benchmark blocks: 300.

| Case | B3 outcomes | P outcomes | B3/P external successes |
|---|---|---|---|
| BIND-aligned | {'commit': 30} | {'commit': 30} | 0/0 |
| BIND-equal-id-wrong-install | {'commit': 30} | {'commit': 30} | 30/30 |
| BIND-inheritance-drift | {'commit': 30} | {'reject': 30} | 0/0 |
| BIND-request-version | {'commit': 30} | {'reject': 30} | 0/0 |
| BIND-runtime-epoch | {'commit': 30} | {'reject': 30} | 0/0 |
| BIND-stale-evidence | {'commit': 30} | {'reject': 30} | 0/0 |
| BOUND-preopened-fd | {'commit': 30} | {'commit': 30} | 30/30 |
| BOUND-send-before-abort | {'abort': 30} | {'abort': 30} | 30/30 |
| SERVICE-sequence | {'commit': 30} | {'commit': 30} | 0/0 |

The equal-ID/wrong-install case is an intentional trusted-mapper defect. A matching metadata identity does not attest kernel configuration. B3 and P both permit that effect; the claim is identity consistency only.

Allowed send before Abort succeeds at the receiver while candidate state remains uninstalled. This is not external-I/O atomic rollback.

## Benign cost (pooled quantiles; uncertainty unit is process block)

| Workload | Mode | P50 µs | P95 µs | P99 µs | Δ B0 µs | Ratio B0 | Block-median min–max µs |
|---|---|---:|---:|---:|---:|---:|---|
| state1 | access-only | 0.600 | 0.700 | 0.899 | 0.000 | 1.00 | 0.600–0.700 |
| state1 | transition-only | 222.895 | 304.792 | 430.989 | 222.295 | 371.49 | 184.395–244.294 |
| state1 | runtime-only | 0.600 | 0.700 | 0.899 | 0.000 | 1.00 | 0.600–0.700 |
| state1 | full-pbea | 217.494 | 298.993 | 407.191 | 216.894 | 362.49 | 186.595–232.644 |
| state1 | unbound-composition | 214.895 | 290.993 | 399.690 | 214.295 | 358.16 | 175.396–235.744 |
| state128 | access-only | 0.700 | 0.800 | 2.700 | 0.000 | 1.00 | 0.600–0.700 |
| state128 | transition-only | 216.294 | 289.093 | 396.591 | 215.594 | 308.99 | 197.395–240.094 |
| state128 | runtime-only | 0.700 | 0.701 | 0.900 | 0.000 | 1.00 | 0.600–0.700 |
| state128 | full-pbea | 217.595 | 290.792 | 404.790 | 216.895 | 310.85 | 193.195–238.144 |
| state128 | unbound-composition | 215.495 | 290.293 | 415.690 | 214.795 | 307.85 | 191.196–232.994 |
| allowed-io | access-only | 4.200 | 4.700 | 8.000 | 0.000 | 1.00 | 4.100–4.500 |
| allowed-io | transition-only | 231.294 | 316.292 | 433.190 | 227.094 | 55.07 | 186.245–254.394 |
| allowed-io | runtime-only | 4.200 | 5.300 | 9.100 | 0.000 | 1.00 | 4.000–5.100 |
| allowed-io | full-pbea | 227.895 | 305.893 | 425.589 | 223.695 | 54.26 | 194.046–244.194 |
| allowed-io | unbound-composition | 223.795 | 305.292 | 424.889 | 219.595 | 53.28 | 194.295–242.394 |
