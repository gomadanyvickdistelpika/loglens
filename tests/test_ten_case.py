"""Fast regression for the ten-case synthetic test (compact size). The full-size performance run is `python tests/ten_case_benchmark.py run`."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
import ten_case_benchmark as tcb               # noqa: E402


class TenCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = {c['id']: tcb.run_worker(c['id'], 300) for c in tcb.C}

    def test_ten_cases_defined(self):
        self.assertEqual(len(tcb.C), 10)
        self.assertEqual(sum(1 for c in tcb.C if not c['root']), 1)

    def test_every_case_passes(self):
        bad = {k: (r['root_rank'], r['also_found'], r['false_high'], r['evidence_ok']) for k, r in self.rows.items() if not r['passed']}
        self.assertEqual(bad, {})

    def test_root_cause_first_and_no_false_high(self):
        for r in self.rows.values():
            if r['root']:
                self.assertEqual(r['root_rank'], 1, r['id'])
                self.assertTrue(r['evidence_ok'], r['id'])
            self.assertEqual(r['false_high'], [], r['id'])

    def test_window_removes_most_noise(self):
        for r in self.rows.values():
            self.assertGreater(r['noise_removed_pct'], 80, r['id'])


if __name__ == '__main__':
    unittest.main()
