import unittest
from analyze import CASES,validate,validate_benchmark

def corpus():
    return [{"run_id":f"{i}","source_commit":"frozen","platform":"openbsd","case":CASES[i//60],"mode":"full-pbea" if i%2 else "unbound-composition","iteration":(i//2)%30+1,"evidence_origin":"supervisor-child-pipe","scope":"controlled fixture","observation":{"native_status":"completed","application_outcome":"commit","domain_before":{},"domain_after":{"invalid":1},"domain_changed":True,"effect_succeeded":True}} for i in range(540)]

class ValidatorTests(unittest.TestCase):
    def test_true_security_failure_is_preserved(self):
        self.assertEqual(validate(corpus()),[])
    def test_duplicate_detected(self):
        r=corpus();r[1]=r[0];self.assertIn("duplicate run id",validate(r))
    def test_missing_detected(self):
        self.assertTrue(validate(corpus()[:-1]))
    def test_contradictory_hash_state_detected(self):
        r=corpus();r[0]["observation"]["domain_changed"]=False;self.assertTrue(validate(r))
    def test_missing_field_reports_error_without_exception(self):
        r=corpus();del r[0]["source_commit"];self.assertTrue(validate(r))
    def test_native_failure_is_preserved(self):
        r=corpus();r[0]["observation"]={"native_status":"child_failed"};self.assertEqual(validate(r),[])
    def test_missing_after_state_reports_error(self):
        r=corpus();del r[0]["observation"]["domain_after"];self.assertTrue(validate(r))
    def test_benchmark_duplicate_and_provenance(self):
        rows=[{"block":b,"source_commit":"frozen","observation":{"mode":m,"workload":w,"warmup":100,"samples_ns":[1]*500,"timer_empty_ns":[1]*100}} for b in range(20) for m in ("access-only","transition-only","runtime-only","full-pbea","unbound-composition") for w in ("state1","state128","allowed-io")]
        self.assertEqual(validate_benchmark(rows,"frozen"),[])
        rows[1]=rows[0];self.assertIn("duplicate benchmark cell",validate_benchmark(rows,"frozen"))
        self.assertIn("benchmark source mismatch",validate_benchmark(rows,"other"))
if __name__=="__main__":unittest.main()
