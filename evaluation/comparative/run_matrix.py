#!/usr/bin/env python3
"""Run the frozen 3 x 9 x 30 PBEA comparison matrix without synthesizing records."""
import argparse, json, pathlib, shutil, subprocess, sys

MODES = ("access-only", "transition-only", "full-pbea")
SCENARIOS = tuple(f"S{i}" for i in range(9))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True, type=pathlib.Path)
    p.add_argument("--helper", required=True, type=pathlib.Path)
    p.add_argument("--policy", required=True, type=pathlib.Path)
    p.add_argument("--policy-schema", required=True, type=pathlib.Path)
    p.add_argument("--request-schema", required=True, type=pathlib.Path)
    p.add_argument("--output", required=True, type=pathlib.Path)
    p.add_argument("--fixture-root", default="/tmp/pbea-eval", type=pathlib.Path)
    p.add_argument("--source-commit", required=True)
    p.add_argument("--iterations", type=int, default=30)
    a = p.parse_args()
    if a.iterations != 30:
        p.error("publication matrix requires exactly 30 iterations")
    for child in ("allowed", "outside", "bin", "markers", "logs"):
        (a.fixture_root / child).mkdir(parents=True, exist_ok=True)
    (a.fixture_root / "allowed/input.json").write_text('{"controlled":true}\n')
    (a.fixture_root / "outside/secret.txt").write_text("synthetic-controlled-secret\n")
    helper = a.fixture_root / "bin/marker-helper"
    shutil.copy2(a.helper, helper); helper.chmod(0o755)
    a.output.mkdir(parents=True, exist_ok=True)
    files = {m: (a.output / f"{m}.jsonl").open("w") for m in MODES}
    log = (a.output.parent / "logs" / "matrix-stderr.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log.open("w") as errors:
            for iteration in range(1, 31):
                for scenario in SCENARIOS:
                    for mode_index, mode in enumerate(MODES):
                        seed = 200_000 + iteration * 100 + int(scenario[1:]) * 3 + mode_index
                        cmd = [str(a.binary), mode, scenario, str(iteration), str(seed), str(a.policy_schema), str(a.policy),
                               str(a.request_schema), str(a.fixture_root), a.source_commit]
                        run = subprocess.run(cmd, text=True, capture_output=True)
                        errors.write(f"[{mode} {scenario} {iteration}] rc={run.returncode}\n{run.stderr}")
                        if run.returncode != 0:
                            raise SystemExit(f"probe failed: {mode} {scenario} {iteration}: {run.stderr}")
                        record = json.loads(run.stdout.strip().splitlines()[-1])
                        files[mode].write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    finally:
        for f in files.values(): f.close()
    print(json.dumps({"records": 810, "output": str(a.output)}, sort_keys=True))

if __name__ == "__main__": main()
