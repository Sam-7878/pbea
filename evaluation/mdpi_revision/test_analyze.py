import unittest
from analyze import validate

def corpus():
    return [{"run_id":f"{i}","source_commit":"frozen","case":f"c{i//60}","mode":"full-pbea" if i%2 else "unbound-composition","iteration":(i//2)%30+1,"observation":{"native_status":"completed","application_outcome":"commit","domain_before":{},"domain_after":{"invalid":1},"domain_changed":True,"effect_succeeded":True}} for i in range(540)]

class ValidatorTests(unittest.TestCase):
    def test_true_security_failure_is_preserved(self):
        self.assertEqual(validate(corpus()),[])
    def test_duplicate_detected(self):
        r=corpus();r[1]=r[0];self.assertIn("duplicate run id",validate(r))
    def test_missing_detected(self):
        self.assertTrue(validate(corpus()[:-1]))
    def test_contradictory_hash_state_detected(self):
        r=corpus();r[0]["observation"]["domain_changed"]=False;self.assertTrue(validate(r))
if __name__=="__main__":unittest.main()
