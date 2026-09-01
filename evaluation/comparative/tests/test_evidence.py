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

if __name__ == "__main__":
    unittest.main()
