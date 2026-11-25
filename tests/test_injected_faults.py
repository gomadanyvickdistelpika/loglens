"""End-to-end: build fault-injected bundles (tests/fault_bundles.py) and check LogLens finds and correctly ranks the planted cause."""
import os, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
os.environ['FB_OUT'] = tempfile.mkdtemp(prefix='lvx_fault_')
import fault_bundles as fb                                         # noqa: E402
from lvx import bundle, analyzer                                    # noqa: E402


def run(name, issue, when):
    import time, calendar
    b = bundle.open_bundle('t-' + name, os.path.join(fb.OUT, name + '.tgz'), work_base=fb.OUT)
    ts = calendar.timegm(time.strptime(when, '%Y-%m-%dT%H:%M:%SZ'))
    return analyzer.analyze(b, issue=issue, anchor=ts)


class Faults(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fb.esxi(); fb.vcsa()

    def ids(self, res):
        return [f['id'] for f in res['findings']]

    def test_esxi_apd(self):
        r = run('ESX-APD-01', 'VMs on datastore PROD-DS01 hung', '2026-11-20T09:14:00Z')
        self.assertEqual(self.ids(r)[0], 'esx.apd')

    def test_vcsa_disk_full_outranks_its_symptoms(self):
        r = run('VCSA-DISKFULL-01', 'vCenter web client down, vpxd will not start', '2026-11-19T03:45:00Z')
        ids = self.ids(r)
        self.assertEqual(ids[0], 'vc.disk_full')
        self.assertLess(ids.index('vc.disk_full'), ids.index('vc.db'))
        self.assertLess(ids.index('vc.disk_full'), ids.index('vc.service_down'))


if __name__ == '__main__':
    unittest.main()
