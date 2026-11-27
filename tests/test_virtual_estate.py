"""The six virtual-estate bundles (fictional client, 2 XCP-ng hosts + Xen Orchestra): each planted fault must be found and ranked first,
every expected downstream finding must be present, no unexpected high finding may appear, and the cause must be confirmable in the raw logs."""
import os
import re
import sys
import tarfile
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..')
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import build_virtual_estate as be                      # noqa: E402
from lvx import analyzer, bundle, export, guidance      # noqa: E402


class VirtualEstate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp(prefix='lvx_estate_')
        cls.res = {}
        for c in be.CASES:
            p = be.build(c, cls.out)
            b = bundle.open_bundle('t-' + c['id'], p, work_base=cls.out)
            cls.res[c['id']] = analyzer.Analyzer(b, issue=c['issue'], anchor=c['incident']).run()

    def test_bundle_shape(self):
        self.assertGreaterEqual(len(be.CASES), 6)
        self.assertEqual(len({c['expect'] for c in be.CASES}), len(be.CASES), 'each case must have a different primary issue')
        c = be.CASES[0]
        with tarfile.open(os.path.join(self.out, c['id'] + '-' + c['slug'] + '.tgz')) as tf:
            names = tf.getnames()
        for need in ('xcp-dub-01/var/log/xensource.log', 'xcp-dub-01/var/log/SMlog', 'xcp-dub-01/var/log/kern.log', 'xcp-dub-01/var/log/xha.log',
                     'xcp-dub-02/var/log/daemon.log', 'xcp-dub-01/commands/df_-h.txt', 'xcp-dub-01/commands/xe_sr-list.txt',
                     'xoa-dub-01/xo/journalctl-xo-server.txt', 'xoa-dub-01/xo/xoa-updater.log', 'xoa-dub-01/commands/df_-h.txt', 'NOTES.txt'):
            self.assertTrue(any(n.endswith(need) for n in names), need)

    def test_each_fault_found_and_ranked_first(self):
        for c in be.CASES:
            ids = [f['id'] for f in self.res[c['id']]['findings']]
            self.assertEqual(ids[0], c['expect'], '%s: %s' % (c['id'], ids[:6]))
            for a in c['also']:
                self.assertIn(a, ids, '%s missing %s' % (c['id'], a))

    def test_no_unexpected_high_findings(self):
        for c in be.CASES:
            ok = {c['expect']} | set(c['also'])
            bad = [f['id'] for f in self.res[c['id']]['findings'] if f['kind'] == 'rule' and f['severity'] in ('critical', 'high') and f['id'] not in ok]
            self.assertEqual(bad, [], c['id'])

    def test_chronic_background_warning_is_not_a_top_finding(self):
        for c in be.CASES:
            ids = [f['id'] for f in self.res[c['id']]['findings']]
            real = [ids.index(i) for i in [c['expect']] + c['also']]
            noise = [n for n, i in enumerate(ids) if 'rrdd_proxy' in i]          # the slow-RRD warning repeats all week: background, not the incident
            self.assertTrue(all(max(real) < n for n in noise), (c['id'], ids[:8]))

    def test_cause_confirmable_in_raw_logs(self):
        """Replays the 'confirm it by hand' greps: the first grep of every case must hit real lines in the extracted bundle."""
        for c in be.CASES:
            d = tempfile.mkdtemp(prefix='lvx_conf_')
            with tarfile.open(os.path.join(self.out, c['id'] + '-' + c['slug'] + '.tgz')) as tf:
                tf.extractall(d)
            root = os.path.join(d, c['id'] + '-' + c['slug'])
            m = re.match(r'grep -h "([^"]+)" ([^|#]+)', c['hand'][0])
            if not m:
                continue                                              # cat-style hint
            pats = [p for p in m.group(1).replace('\\|', '\x00').split('\x00')]
            hits = 0
            for rel in m.group(2).split():
                with open(os.path.join(root, rel), encoding='utf-8') as f:
                    hits += sum(1 for ln in f if any(p in ln for p in pats))
            self.assertGreater(hits, 0, c['id'])

    def test_reports_render_with_case_pack_and_redaction(self):
        for c in be.CASES:
            res = dict(self.res[c['id']], issue=c['issue'] + ' contact ops@brightwater.example')
            md, cats = export.render(res, 'md', redact=True)
            self.assertIn('Action plan and drafts', md)
            self.assertNotIn('ops@brightwater.example', md)
            self.assertIn('Vates/XCP-ng KB research', md)
            self.assertTrue(guidance.build(res)['safe_checks'])


if __name__ == '__main__':
    unittest.main()
