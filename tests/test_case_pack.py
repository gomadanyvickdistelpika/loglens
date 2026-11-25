"""Features merged from vmware-case-agent: redaction, risk-classified action plan, KB candidates; plus the new rules."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
os.environ['FB_OUT'] = tempfile.mkdtemp(prefix='lvx_cp_')
import fault_bundles as fb                                     # noqa: E402
from lvx import analyzer, bundle, export, guidance, privacy    # noqa: E402


class Redaction(unittest.TestCase):
    def test_masks_pii_and_secrets(self):
        t, cats = privacy.redact('Contact: Jane Doe jane@corp.com call +353 87 123 4567 password=Hunter2 Bearer abcdef0123456789abcd case SR-1234567 host 10.20.30.40')
        for leak in ('jane@corp.com', 'Hunter2', '+353 87 123 4567', '10.20.30.40', 'abcdef0123456789abcd', 'Jane Doe'):
            self.assertNotIn(leak, t)
        for c in ('email', 'secret', 'phone', 'ipv4', 'person_name'):
            self.assertIn(c, cats)

    def test_does_not_destroy_log_evidence(self):
        line = '2026-11-20T09:14:02.351Z cpu4:2097411)ScsiPath: 4394: Path vmhba64:C0:T1:L12 is now dead build 24022510 at 03:42:11'
        self.assertEqual(privacy.redact(line, mask_ips=True)[0], line)     # timestamps, build numbers, path ids survive

    def test_keeps_official_kb_links_but_masks_others(self):
        t, _ = privacy.redact('see https://knowledge.broadcom.com/external/article/399833 and https://intranet.corp.example/ticket/9 and https://docs.xcp-ng.org/storage')
        self.assertIn('knowledge.broadcom.com/external/article/399833', t)
        self.assertIn('docs.xcp-ng.org', t)
        self.assertNotIn('intranet.corp.example', t)

    def test_extra_terms(self):
        t, cats = privacy.redact('customer ACME-Corp vm prod-sql01', extra_terms=['ACME-Corp', 'prod-sql01'])
        self.assertNotIn('ACME', t)
        self.assertNotIn('prod-sql01', t)
        self.assertIn('custom_term', cats)


class Guidance(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(guidance.classify('Run df -h on /storage/log'), 'READ-ONLY')
        self.assertEqual(guidance.classify('Replace the machine SSL certificate with vecs-cli'), 'RISKY')
        self.assertEqual(guidance.classify('Restart the vpxd service during a window'), 'DISRUPTIVE')

    def test_descriptive_sentences_are_not_actions(self):
        self.assertEqual(guidance._sentences('A VCSA partition is full. Full /storage/seat stops vpostgres.'), [])
        self.assertTrue(guidance._sentences('Run df -h and find which volume is at 100%; grow the VMDK.'))

    def test_case_pack_for_real_analysis(self):
        fb.vcsa()
        b = bundle.open_bundle('cp', os.path.join(fb.OUT, 'VCSA-DISKFULL-01.tgz'), work_base=fb.OUT)
        import calendar, time
        res = analyzer.analyze(b, issue='vCenter down', anchor=calendar.timegm(time.strptime('2026-11-19T03:45:00Z', '%Y-%m-%dT%H:%M:%SZ')))
        cp = guidance.build(res)
        self.assertIn(cp['confidence'], ('low', 'medium'))              # never 'high' until a reviewer confirms
        self.assertTrue(cp['risky_checks'] and cp['rollback'])
        self.assertTrue(any('grow' in r['text'].lower() for r in cp['risky_checks']))
        self.assertIn('not yet confirmed', cp['customer_draft'])
        res['verdicts'] = {res['findings'][0]['id']: {'v': 'confirm', 'note': ''}}
        self.assertEqual(guidance.build(res)['confidence'], 'high')
        md = export.render(res, 'md')[0]
        self.assertIn('Action plan and drafts', md)
        self.assertEqual(export.render(res, 'json')[0].count('"case_pack"'), 1)
        red, cats = export.render(dict(res, issue='call jane@corp.com'), 'md', redact=True)
        self.assertNotIn('jane@corp.com', red)
        self.assertIn('2026-11-19T03:42', red)


class NewRulesAndKB(unittest.TestCase):
    def run_text(self, name, text):
        d = tempfile.mkdtemp(prefix='lvx_r_')
        os.makedirs(os.path.join(d, 'var', 'log', 'vmware', 'vpxd'))
        with open(os.path.join(d, 'var', 'log', 'vmware', 'vpxd', 'vpxd.log'), 'w') as f:
            f.write(text)
        res = analyzer.analyze(bundle.open_bundle('r' + name, d), issue='')
        return {f['id']: f for f in res['findings']}

    def test_patching_backup_rule_and_kb(self):
        f = self.run_text('a', '2026-11-20T09:00:00.000Z error vpxd[1] Update staging failed: [Errno 2] No such file or directory: patching_backup_config.json\n')
        self.assertIn('vc.upg_patching_backup', f)
        ids = [a['id'] for en in f['vc.upg_patching_backup']['kb_research']['entries'] for a in en['articles']]
        self.assertIn('399833', ids)

    def test_lcm_remediation_rule_and_kb(self):
        f = self.run_text('b', '2026-11-20T09:00:00.000Z error vpxd[1] Remediation of host esx01 failed: The software or system configuration is incompatible: VIB vendor-xyz missing dependencies\n')
        self.assertIn('vc.lcm_remediation', f)
        ids = [a['id'] for en in f['vc.lcm_remediation']['kb_research']['entries'] for a in en['articles']]
        self.assertIn('412258', ids)

    def test_vmotion_evc_kb(self):
        from lvx import kb
        r = kb.research('esx.vmotion', 'vMotion failed: CPU incompatibility, EVC baseline not met', 'vmotion')
        self.assertIn('390403', [a['id'] for en in r['entries'] for a in en['articles']])


if __name__ == '__main__':
    unittest.main()
