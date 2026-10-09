"""Case templates: schema, privacy guard, detection accuracy on the synthetic bundles, KB/resolution wiring."""
import hashlib
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
from lvx import kb, templates            # noqa: E402
from lvx.rules import BY_ID              # noqa: E402
import templates_accuracy                # noqa: E402

TPL_PATH = os.path.join(HERE, '..', 'lvx', 'case_templates.json')
ALLOWED_EMAIL = re.compile(r'@(?:[\w.-]+\.example|vsphere\.local)$', re.I)
OK_IP = re.compile(r'^(?:192\.0\.2\.|198\.51\.100\.|203\.0\.113\.|127\.0\.0\.1$)')
REAL_TLD = re.compile(r'\b[\w-]+(?:\.[\w-]+)*\.(?:fr|de|nl|se|uk|cz|org|net|es|pt|tr|tz|br|gov|co|ie|it|ch|at|be|dk|pl)\b', re.I)
PUBLIC_OK = ('broadcom.com', 'vmware.com', 'dell.com', 'vsphere.local', 'lab.example')


class TemplateSchema(unittest.TestCase):
    def setUp(self):
        self.t = templates.all_templates()

    def test_count_and_ids(self):
        self.assertGreaterEqual(len(self.t), 25)
        ids = [x['id'] for x in self.t]
        self.assertEqual(len(ids), len(set(ids)))

    def test_fields(self):
        for x in self.t:
            for k in ('id', 'title', 'product', 'version', 'issue', 'evidence', 'bundle', 'expect_rules', 'lines', 'cause', 'resolution', 'kb', 'notes'):
                self.assertIn(k, x, x['id'])
            self.assertIn(x['evidence'], ('case-excerpts', 'mixed', 'no-log'), x['id'])
            for r in x['expect_rules']:
                self.assertIn(r, BY_ID, '%s: unknown rule %s' % (x['id'], r))
            if x['bundle']:
                self.assertTrue(x['lines'], x['id'])
                for ln in x['lines']:
                    self.assertEqual(len(ln), 4, x['id'])
                    self.assertIn(ln[3], ('case', 'typical'))
            else:
                self.assertEqual(x['lines'], [], x['id'])
            for k in x['kb']:
                self.assertTrue(k['id'] and k['title'] and k['role'], x['id'])
                self.assertRegex(kb.article_url(k['id']), r'^https://knowledge\.broadcom\.com/external/article(/\d+|\?legacyId=\d+)$')

    def test_no_resolution_invented(self):
        # a template with no cause AND no resolution must say nothing rather than guess
        for x in self.t:
            if not x['resolution']:
                self.assertTrue(x['notes'] or not x['cause'], x['id'])


class PrivacyGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(TPL_PATH, encoding='utf-8') as f:
            cls.text = f.read()
        with open(os.path.join(HERE, 'privacy_denylist.sha256')) as f:
            cls.deny = {ln.strip() for ln in f if ln.strip() and not ln.startswith('#')}

    def test_no_denylisted_tokens(self):
        bad = sorted({w for w in re.findall(r'[a-z0-9]+', self.text.lower()) if hashlib.sha256(w.encode()).hexdigest() in self.deny})
        self.assertEqual(bad, [], 'denylisted token(s) in templates (values withheld): %d' % len(bad))

    def test_no_case_numbers(self):
        self.assertEqual(re.findall(r'\b36\d{6}\b', self.text), [])

    def test_no_real_emails_or_ips_or_domains(self):
        for m in re.findall(r'[\w.+-]+@[\w-]+(?:\.[\w-]+)+', self.text):
            self.assertRegex(m, ALLOWED_EMAIL, m)
        for ip in re.findall(r'(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])', self.text):
            self.assertRegex(ip, OK_IP, ip)
        for m in REAL_TLD.finditer(self.text):
            self.assertTrue(any(m.group(0).lower().endswith(ok) for ok in PUBLIC_OK), m.group(0))


class TemplateDetection(unittest.TestCase):
    def test_accuracy_at_least_95_percent(self):
        rate, rows = templates_accuracy.run(verbose=False)
        bad = [(r[0], r[2]) for r in rows if not r[1]]
        self.assertGreaterEqual(rate, 95.0, bad)

    def test_bundle_builder_is_deterministic_and_complete(self):
        import tempfile
        import shutil
        a, b = tempfile.mkdtemp(), tempfile.mkdtemp()
        try:
            templates.build_bundle('CT-13', a)
            templates.build_bundle('CT-13', b)
            fa = sorted(os.listdir(os.path.join(a, 'var/log/vmware/vpxd')))
            self.assertEqual(fa, sorted(os.listdir(os.path.join(b, 'var/log/vmware/vpxd'))))
            with open(os.path.join(a, 'var/log/vmware/vpxd/vpxd-1.log')) as f1, open(os.path.join(b, 'var/log/vmware/vpxd/vpxd-1.log')) as f2:
                self.assertEqual(f1.read(), f2.read())
            self.assertIn('missing heartbeats', open(os.path.join(a, 'var/log/vmware/vpxd/vpxd-1.log')).read())
            with self.assertRaises(ValueError):
                templates.build_bundle('CT-03', tempfile.mkdtemp())
        finally:
            shutil.rmtree(a, ignore_errors=True)
            shutil.rmtree(b, ignore_errors=True)

    def test_template_resolution_and_kb_attached(self):
        r = kb.research('vc.ldaps', "Server SSL certificate verification failed SHA1 Fingerprint Signature does not match")
        e = r['entries'][0]
        self.assertEqual(e['precision'], 'case-template')
        self.assertTrue(e['resolution'])
        self.assertIn('313460', [a['id'] for a in e['articles']])

    def test_no_kb_cited_is_stated(self):
        r = kb.research('esx.heap_admission', 'Admission failure in path: host:system:net:heap:vmxnet3TxdHeap')
        t = [e for e in r['entries'] if e['precision'] == 'case-template'][0]
        self.assertEqual(t['articles'], [])
        self.assertEqual(t['resolution'], [])


if __name__ == '__main__':
    unittest.main()
