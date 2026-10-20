"""Check active project paths without modifying retained task evidence."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
REPORT = ROOT / 'projects/pbea/results/204_Astra_review'
PAPER = ROOT / 'projects/pbea/paper/mdpi_revision'

class LayoutTests(unittest.TestCase):
    def test_single_active_result_tree(self):
        self.assertTrue((REPORT / 'raw/security.jsonl').is_file())
        self.assertTrue((REPORT / 'raw/benchmark.jsonl').is_file())
        self.assertFalse((ROOT / 'docs/work_reports/pbea/204_Astra_review/revision').exists())

    def test_paper_evidence_and_bibliography_resolve(self):
        text = (PAPER / 'main.tex').read_text()
        relative = re.search(r'\\newcommand\{\\EvidenceDir\}\{([^}]+)\}', text).group(1)
        for name in ('historical_security.tex','historical_performance.tex','binding_results.tex','native_performance.tex'):
            self.assertTrue((PAPER / relative / name).is_file(), name)
        self.assertTrue((PAPER.parent / 'references.bib').is_file())

    def test_project_namespaces_documented(self):
        for project in ('pbea','open_banking','swarm_drones'):
            self.assertTrue((ROOT / 'projects' / project / 'README.md').is_file())

if __name__ == '__main__':
    unittest.main()
