import json, pathlib, subprocess, tempfile, unittest, sys
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from compute_wilson_ci import wilson
from validate_records import validate
from compute_security_metrics import compute

def sample(mode="access-only", scenario_id="S0", iteration=1):
    exp = "commit" if mode in ("transition-only", "full-pbea") and scenario_id == "S0" else "success"
    return {
        "run_id": f"run-{mode}-{scenario_id}-{iteration}",
        "experiment_id": "PBEA-COMPARATIVE-001",
        "scenario_id": scenario_id,
        "mode": mode,
        "iteration": iteration,
        "seed": 1,
        "timestamp": "2026-09-01T00:00:00Z",
        "source_commit": "abcdef0",
        "platform": "openbsd-amd64",
        "build_profile": "release",
        "policy_digest": None if mode in ("access-only", "runtime-only") else "sha256:" + "0" * 64,
        "actor_authenticated": True,
        "access_authorized": True,
        "operation": "verify_transition",
        "expected_outcome": exp,
        "observed_outcome": exp,
        "malicious_effect_attempted": False,
        "malicious_effect_succeeded": False,
        "state_hash_before": "sha256:" + "0" * 64,
        "state_hash_after": "sha256:" + "0" * 64,
        "state_changed": False,
        "capability_type": None,
        "target": None,
        "os_errno": None,
        "exit_code": 0,
        "signal": None,
        "listener_opened": False,
        "business_loop_entered": True,
        "duration_us": 1,
        "status": "passed",
        "details": None,
    }

class EvidenceTests(unittest.TestCase):
    def test_evd_001_raw_schema_shape(self):
        self.assertEqual(validate([sample()], False), [])
        self.assertEqual(validate([sample(mode="runtime-only")], False), [])

    def test_evd_002_state_hash(self):
        r = sample()
        r["state_changed"] = True
        self.assertTrue(any("state hash" in e for e in validate([r], False)))

    def test_evd_003_effect_consistency(self):
        r = sample()
        r["malicious_effect_succeeded"] = True
        self.assertTrue(any("without attempt" in e for e in validate([r], False)))

    def test_evd_004_duplicate(self):
        self.assertTrue(any("duplicate" in e for e in validate([sample(), sample()], False)))

    def test_evd_005_mode_scenario(self):
        r = sample()
        r["mode"] = "toy"
        self.assertTrue(validate([r], False))

    def test_evd_006_wilson_golden(self):
        lo, hi = wilson(0, 30)
        self.assertAlmostEqual(lo, 0)
        self.assertAlmostEqual(hi, 0.113513, places=5)

    def test_evd_007_latex_regeneration(self):
        records = [sample(m, s, i) for m in ("access-only", "transition-only", "runtime-only", "full-pbea") for s in (f"S{k}" for k in range(9)) for i in range(1, 31)]
        metrics = compute(records)
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            src = d / "metrics.json"
            src.write_text(json.dumps(metrics))
            out = d / "one"
            subprocess.run([sys.executable, str(ROOT / "generate_tables.py"), str(src), str(out)], check=True)
            first = {p.name: p.read_bytes() for p in out.iterdir()}
            out2 = d / "two"
            subprocess.run([sys.executable, str(ROOT / "generate_tables.py"), str(src), str(out2)], check=True)
            self.assertEqual(first, {p.name: p.read_bytes() for p in out2.iterdir()})

    def test_evd_008_provenance(self):
        a = sample()
        b = sample()
        b["run_id"] = "y"
        b["source_commit"] = "1234567"
        self.assertTrue(any("source commits" in e for e in validate([a, b], False)))

    def test_s7_abort_with_changed_hash_fails(self):
        r = sample("transition-only", "S7")
        r.update(expected_outcome="abort", observed_outcome="abort", capability_type="fault-injection", target="after-candidate-before-commit", state_changed=True, state_hash_after="sha256:"+"1"*64)
        self.assertTrue(any("S7 abort changed state" in e or "non-commit changed state" in e for e in validate([r], False)))

    def test_rollback_failure_cannot_hide_as_false_effect(self):
        r = sample("transition-only", "S7")
        r.update(expected_outcome="abort", observed_outcome="abort", capability_type="fault-injection", target="after-candidate-before-commit", state_changed=True, state_hash_after="sha256:"+"1"*64, malicious_effect_succeeded=False)
        self.assertTrue(validate([r], False))

    def test_s7_not_applicable_excluded_from_metrics(self):
        records=[]
        for mode in ("access-only","runtime-only"):
            r=sample(mode,"S7"); r.update(capability_type="fault-injection", target="after-candidate-before-commit", state_changed=True, state_hash_after="sha256:"+"1"*64)
            records.append(r)
        metrics=compute(records)
        for mode in ("access-only","runtime-only"):
            m=metrics[mode]["effect_families"]["state_integrity"]["S7_rollback_failure_rate"]
            self.assertEqual((m["numerator"],m["denominator"],m["rate"]),(0,0,None))

    def test_report_metrics_mismatch_fails(self):
        records=[sample(m,s,i) for m in ("access-only","transition-only","runtime-only","full-pbea") for s in (f"S{k}" for k in range(9)) for i in range(1,31)]
        metrics=compute(records)
        with tempfile.TemporaryDirectory() as d:
            d=pathlib.Path(d); metric_path=d/"metrics.json"; metric_path.write_text(json.dumps(metrics)); benchmark=d/"benchmark.json"; benchmark.write_text("{}")
            generated=d/"generated"; subprocess.run([sys.executable,str(ROOT/"generate_tables.py"),str(metric_path),str(generated)],check=True)
            bad=d/"bad.md"; bad.write_text("<!-- canonical_metrics_sha256:wrong benchmark_sha256:wrong -->\n")
            run=subprocess.run([sys.executable,str(ROOT/"report_consistency_test.py"),"--metrics",str(metric_path),"--benchmark",str(benchmark),"--generated",str(generated),"--reports",str(bad)],capture_output=True)
            self.assertNotEqual(run.returncode,0)

if __name__ == "__main__":
    unittest.main()
