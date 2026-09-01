#!/usr/bin/env python3
"""Compute security metrics decomposed by effect family for 4-mode PBEA evaluation."""
import argparse, json, pathlib, statistics, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from compute_wilson_ci import wilson

MODES = ("access-only", "transition-only", "runtime-only", "full-pbea")

def ratio(name, numerator, denominator):
    ci = wilson(numerator, denominator)
    return {
        "metric": name,
        "numerator": numerator,
        "denominator": denominator,
        "rate": None if not denominator else numerator / denominator,
        "percent": None if not denominator else 100 * numerator / denominator,
        "wilson_95_low": None if ci is None else ci[0],
        "wilson_95_high": None if ci is None else ci[1],
    }

def percentile(values, p):
    if not values:
        return 0
    values = sorted(values)
    idx = max(0, min(len(values) - 1, round((len(values) - 1) * p)))
    return values[idx]

def compute(records):
    result = {}
    for mode in MODES:
        rs = [r for r in records if r["mode"] == mode]
        attempts = [r for r in rs if r["malicious_effect_attempted"]]
        benign = [r for r in rs if r["scenario_id"] == "S0"]
        s1 = [r for r in rs if r["scenario_id"] == "S1"]
        s2 = [r for r in rs if r["scenario_id"] == "S2"]
        s3 = [r for r in rs if r["scenario_id"] == "S3"]
        s4 = [r for r in rs if r["scenario_id"] == "S4"]
        s5 = [r for r in rs if r["scenario_id"] == "S5"]
        faults = s5
        s5_malformed = [r for r in s5 if r["iteration"] % 2 == 1]
        s5_missing = [r for r in s5 if r["iteration"] % 2 == 0]
        s6 = [r for r in rs if r["scenario_id"] == "S6"]
        s7 = [r for r in rs if r["scenario_id"] == "S7"]
        s8 = [r for r in rs if r["scenario_id"] == "S8"]
        noncommit = [
            r for r in rs
            if r["observed_outcome"] in ("reject", "quarantine", "abort", "terminated", "startup-failure")
        ]
        contained = [r for r in rs if r["scenario_id"] in ("S2", "S3", "S4")]
        lat = [r["duration_us"] for r in rs]

        # Decomposed effect families
        families = {
            "state_integrity": {
                "S1_invalid_state_propagation_rate": ratio(
                    "S1-ISPR",
                    sum(r["state_changed"] for r in s1),
                    len(s1)
                ),
                "S7_rollback_failure_rate": ratio(
                    "S7-RFR",
                    sum(r["state_changed"] for r in s7),
                    len(s7)
                ),
                "SIVR_aggregate": ratio(
                    "SIVR",
                    sum(r["state_changed"] for r in noncommit),
                    len(noncommit)
                ),
            },
            "runtime_capability_containment": {
                "S2_filesystem_containment": ratio(
                    "S2-CCR",
                    sum(not r["malicious_effect_succeeded"] for r in s2),
                    len(s2)
                ),
                "S3_child_execution_containment": ratio(
                    "S3-CCR",
                    sum(not r["malicious_effect_succeeded"] for r in s3),
                    len(s3)
                ),
                "S4_network_containment": ratio(
                    "S4-CCR",
                    sum(not r["malicious_effect_succeeded"] for r in s4),
                    len(s4)
                ),
                "aggregate_CCR": ratio(
                    "CCR",
                    sum(not r["malicious_effect_succeeded"] for r in contained),
                    len(contained)
                ),
            },
            "policy_binding": {
                "S8_digest_mismatch_acceptance_rate": ratio(
                    "S8-DMAR",
                    sum(r["malicious_effect_succeeded"] for r in s8),
                    len(s8)
                ),
                "S8_digest_rejection_rate": ratio(
                    "S8-DRR",
                    sum(r["observed_outcome"] == "reject" for r in s8),
                    len(s8)
                ),
            },
            "fail_closed_startup": {
                "S5_malformed_policy_FCR": ratio(
                    "S5-Malformed-FCR",
                    sum(r["observed_outcome"] == "startup-failure" for r in s5_malformed),
                    len(s5_malformed)
                ),
                "S5_missing_resource_FCR": ratio(
                    "S5-Missing-FCR",
                    sum(r["observed_outcome"] == "startup-failure" for r in s5_missing),
                    len(s5_missing)
                ),
                "S5_aggregate_FCR": ratio(
                    "FCR",
                    sum(r["observed_outcome"] == "startup-failure" for r in s5),
                    len(s5)
                ),
            },
            "outcome_quarantine_semantics": {
                "S6_quarantine_rate": ratio(
                    "S6-QR",
                    sum(r["observed_outcome"] == "quarantine" for r in s6),
                    len(s6)
                ),
                "S7_abort_rate": ratio(
                    "S7-AR",
                    sum(r["observed_outcome"] == "abort" for r in s7),
                    len(s7)
                ),
            },
            "benign_preservation": {
                "S0_BRSR": ratio(
                    "BRSR",
                    sum(r["status"] == "passed" and r["observed_outcome"] in ("success", "commit") for r in benign),
                    len(benign)
                ),
            },
        }

        # Legacy / headline aggregate metrics
        aggregate = {
            "MESR": ratio(
                "MESR",
                sum(r["malicious_effect_succeeded"] for r in attempts),
                len(attempts)
            ),
            "BRSR": ratio(
                "BRSR",
                sum(r["status"] == "passed" and r["observed_outcome"] in ("success", "commit") for r in benign),
                len(benign)
            ),
            "SIVR": ratio(
                "SIVR",
                sum(r["state_changed"] for r in noncommit),
                len(noncommit)
            ),
            "CER": ratio(
                "CER",
                sum(not r["malicious_effect_succeeded"] for r in contained),
                len(contained)
            ),
            "FCR": ratio(
                "FCR",
                sum(r["observed_outcome"] == "startup-failure" for r in faults),
                len(faults)
            ),
            "OCA": ratio(
                "OCA",
                sum(r["status"] == "passed" and r["expected_outcome"] == r["observed_outcome"] for r in rs),
                len(rs)
            ),
        }

        # Scenario breakdown
        scenario_counts = {}
        for s_id in (f"S{i}" for i in range(9)):
            s_records = [r for r in rs if r["scenario_id"] == s_id]
            scenario_counts[s_id] = {
                "total": len(s_records),
                "malicious_succeeded": sum(r["malicious_effect_succeeded"] for r in s_records),
                "observed_outcomes": {
                    out: sum(r["observed_outcome"] == out for r in s_records)
                    for out in set(r["observed_outcome"] for r in s_records)
                },
                "state_changed_count": sum(r["state_changed"] for r in s_records),
            }

        result[mode] = {
            "metrics": aggregate,
            "effect_families": families,
            "scenario_breakdown": scenario_counts,
            "latency_us": {
                "count": len(lat),
                "min": min(lat) if lat else 0,
                "p50": percentile(lat, 0.50),
                "p95": percentile(lat, 0.95),
                "max": max(lat) if lat else 0,
                "mean": statistics.fmean(lat) if lat else 0.0,
                "population_stddev": statistics.pstdev(lat) if lat else 0.0,
            },
        }
    return result

def main():
    p = argparse.ArgumentParser()
    p.add_argument("paths", nargs="+", type=pathlib.Path)
    p.add_argument("--output", type=pathlib.Path)
    a = p.parse_args()
    records = [
        json.loads(line)
        for path in a.paths
        for line in path.read_text().splitlines()
        if line.strip()
    ]
    out = json.dumps(compute(records), indent=2, sort_keys=True) + "\n"
    if a.output:
        a.output.write_text(out)
    else:
        print(out, end="")

if __name__ == "__main__":
    main()
