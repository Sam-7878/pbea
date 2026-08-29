#!/usr/bin/env python3
"""Fail-closed semantic validator for PBEA comparison evidence."""
import argparse, collections, json, pathlib, sys
import jsonschema

MODES = ("access-only", "transition-only", "full-pbea")
SCENARIOS = tuple(f"S{i}" for i in range(9))
SCHEMA = json.loads((pathlib.Path(__file__).parent / "evidence.schema.json").read_text())
SCHEMA_VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)

def expected(mode, scenario, iteration):
    if scenario == "S0": return "success" if mode == "access-only" else "commit"
    if scenario in ("S1", "S8"): return "success" if mode == "access-only" else "reject"
    if scenario == "S2": return "reject" if mode == "full-pbea" else "success"
    if scenario == "S3": return "terminated" if mode == "full-pbea" else "success"
    if scenario == "S4": return "reject" if mode == "full-pbea" else "success"
    if scenario == "S5":
        return "startup-failure" if mode == "full-pbea" or (mode == "transition-only" and iteration % 2 == 1) else "success"
    if scenario == "S6": return "success" if mode == "access-only" else "quarantine"
    if scenario == "S7": return "success" if mode == "access-only" else "abort"
    raise AssertionError(scenario)

def load(paths):
    for path in paths:
        for no, line in enumerate(path.read_text().splitlines(), 1):
            try: yield json.loads(line)
            except Exception as e: raise ValueError(f"{path}:{no}: {e}") from e

def validate(records, require_complete=True):
    errors=[]; ids=set(); cells=collections.Counter(); commits=set(); platforms=set()
    required={"run_id","experiment_id","scenario_id","mode","iteration","seed","timestamp","source_commit","platform","build_profile","policy_digest","actor_authenticated","access_authorized","operation","expected_outcome","observed_outcome","malicious_effect_attempted","malicious_effect_succeeded","state_hash_before","state_hash_after","state_changed","capability_type","target","os_errno","exit_code","signal","listener_opened","business_loop_entered","duration_us","status","details"}
    for i,r in enumerate(records,1):
        schema_errors=sorted(SCHEMA_VALIDATOR.iter_errors(r),key=lambda e:list(e.absolute_path))
        if schema_errors: errors.append(f"record {i}: schema: {schema_errors[0].message}")
        missing=required-r.keys()
        if missing: errors.append(f"record {i}: missing {sorted(missing)}"); continue
        extra=r.keys()-required
        if extra: errors.append(f"record {i}: unknown fields {sorted(extra)}")
        if r["run_id"] in ids: errors.append(f"record {i}: duplicate run_id")
        ids.add(r["run_id"]); commits.add(r["source_commit"]); platforms.add(r["platform"])
        key=(r["mode"],r["scenario_id"],r["iteration"]); cells[key]+=1
        if r["mode"] not in MODES or r["scenario_id"] not in SCENARIOS: errors.append(f"record {i}: invalid mode/scenario")
        if not r["actor_authenticated"] or not r["access_authorized"]: errors.append(f"record {i}: precondition false")
        exp=expected(r["mode"],r["scenario_id"],r["iteration"])
        if r["expected_outcome"] != exp or r["observed_outcome"] != exp: errors.append(f"record {i}: expected/observed mismatch ({exp})")
        if r["state_changed"] != (r["state_hash_before"] != r["state_hash_after"]): errors.append(f"record {i}: state hash inconsistency")
        if r["malicious_effect_succeeded"] and not r["malicious_effect_attempted"]: errors.append(f"record {i}: succeeded without attempt")
        if (r["mode"] == "access-only") != (r["policy_digest"] is None): errors.append(f"record {i}: digest null rule")
        if r["exit_code"] is not None and r["signal"] is not None: errors.append(f"record {i}: exit_code and signal both set")
        if not isinstance(r["duration_us"],int) or r["duration_us"]<0: errors.append(f"record {i}: bad duration")
        if r["scenario_id"] == "S3" and r["mode"] == "full-pbea" and not r["signal"]: errors.append(f"record {i}: pledge termination lacks signal")
        if r["observed_outcome"] in ("reject","quarantine","abort","terminated","startup-failure") and r["state_changed"]: errors.append(f"record {i}: non-commit changed state")
    if len(commits)!=1: errors.append(f"provenance: source commits={sorted(commits)}")
    if len(platforms)!=1: errors.append(f"provenance: platforms={sorted(platforms)}")
    if require_complete:
        expected_keys={(m,s,i) for m in MODES for s in SCENARIOS for i in range(1,31)}
        if set(cells)!=expected_keys: errors.append(f"coverage differs: missing={len(expected_keys-set(cells))} extra={len(set(cells)-expected_keys)}")
        bad=[k for k,v in cells.items() if v!=1]
        if bad: errors.append(f"duplicate cells: {bad[:5]}")
        if len(records)!=810: errors.append(f"record count {len(records)} != 810")
    return errors

def main():
    p=argparse.ArgumentParser(); p.add_argument("paths",nargs="+",type=pathlib.Path); p.add_argument("--allow-partial",action="store_true"); a=p.parse_args()
    records=list(load(a.paths)); errors=validate(records,not a.allow_partial)
    if errors:
        print("\n".join(errors),file=sys.stderr); raise SystemExit(1)
    print(json.dumps({"status":"valid","records":len(records),"cells":len(records)},sort_keys=True))
if __name__=="__main__": main()
