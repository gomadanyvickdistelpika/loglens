"""One engine, two rule packs: detection, vendor-specific KB text, Vates-only build, and live mode on an XCP-ng host."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..')
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
from lvx import analyzer, bundle, live, packs, templates, kb, export   # noqa: E402

SH = shutil.which('sh') or shutil.which('bash')


def posix(p):
    p = os.path.abspath(p).replace('\\', '/')
    return '/' + p[0].lower() + p[2:] if len(p) > 1 and p[1] == ':' else p


class Detection(unittest.TestCase):
    def test_both_packs_loaded(self):
        from lvx import rules
        ids = [r['id'] for r in rules.R]
        self.assertTrue(any(i.startswith('esx.') for i in ids))
        self.assertEqual(len([i for i in ids if i.startswith('xcp.')]), 25)
        self.assertEqual(len(ids), len(set(ids)))
        for r in rules.R:
            self.assertEqual(r['kws'], tuple(r['kws']))
            self.assertIn('any_level', r)

    def test_product_classification(self):
        c = analyzer.classify_product
        self.assertEqual(c('var/run/log/vmkernel.log'), 'esxi')
        self.assertEqual(c('var/log/vmware/vpxd/vpxd.log'), 'vcenter')
        self.assertEqual(c('var/log/SMlog'), 'xcpng')
        self.assertEqual(c('var/log/xensource.log'), 'xcpng')
        self.assertEqual(c('xo/journalctl-xo-server.txt'), 'xo')
        self.assertEqual(c('commands/journalctl_-u_vmware-vpxd.txt'), 'vcenter')       # a vCenter journal must not become 'xo'
        self.assertEqual(c('commands/journalctl_-b.txt'), 'unknown')
        self.assertEqual(c('var/log/messages'), 'unknown')

    def test_vendor(self):
        self.assertEqual(packs.vendor('xcp.sr_full'), 'vates')
        self.assertEqual(packs.vendor('esx.apd'), 'broadcom')
        self.assertEqual(packs.vendor(None, ['xcpng', 'xo']), 'vates')
        self.assertEqual(packs.vendor(None, ['xcpng', 'esxi']), 'broadcom')

    def test_templates_both_packs_no_id_clash(self):
        ids = [t['id'] for t in templates.all_templates()]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(templates.pack_templates('vates')), 19)
        self.assertGreaterEqual(len(templates.pack_templates('vmware')), 49)

    def test_kb_is_vendor_specific(self):
        v = kb.research('xcp.sr_full', 'SR full insufficient space SR_BACKEND_FAILURE_44', 'x')
        self.assertEqual(v['vendor'], 'Vates/XCP-ng')
        self.assertTrue(all(a['url'].startswith('https://') and 'broadcom' not in a['url'] for en in v['entries'] for a in en['articles']))
        b = kb.research('esx.apd', 'all paths down', 'x')
        self.assertEqual(b['vendor'], 'Broadcom')
        self.assertTrue(any('knowledge.broadcom.com' in a['url'] for en in b['entries'] for a in en['articles']))

    def test_mixed_bundle_finds_both_vendors(self):
        import fault_bundles as fb
        os.environ['FB_OUT'] = tempfile.mkdtemp(prefix='lvx_pk_')
        import importlib
        importlib.reload(fb)
        fb.esxi(); fb.xcp()
        d = tempfile.mkdtemp(prefix='lvx_mix_')
        import tarfile
        for n in ('ESX-APD-01', 'XCP-SRFULL-01'):
            with tarfile.open(os.path.join(fb.OUT, n + '.tgz')) as tf:
                tf.extractall(d)
        b = bundle.open_bundle('mix', d)
        import calendar
        res = analyzer.analyze(b, issue='VMs hung and db02 will not start', anchor=calendar.timegm((2026, 11, 20, 9, 30, 0)), before_s=24 * 3600, after_s=3 * 3600)
        ids = {f['id']: f for f in res['findings']}
        self.assertIn('esx.apd', ids)
        self.assertIn('xcp.sr_full', ids)
        self.assertEqual(ids['esx.apd']['kb_research']['vendor'], 'Broadcom')
        self.assertEqual(ids['xcp.sr_full']['kb_research']['vendor'], 'Vates/XCP-ng')
        md = export.to_markdown(res)
        self.assertIn('Broadcom KB research', md)
        self.assertIn('Vates/XCP-ng KB research', md)


class VatesOnlyBuild(unittest.TestCase):
    def run_py(self, code, packs_env):
        env = dict(os.environ, LVX_PACKS=packs_env, PYTHONPATH=ROOT)
        return subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env, timeout=120).stdout.strip()

    def test_vates_only(self):
        out = self.run_py("from lvx import rules, templates, kb; print(len(rules.R), len(templates.all_templates()), len(kb._load()['entries']))", 'vates')
        r, t, k = (int(x) for x in out.split())
        self.assertEqual((r, t), (25, 19))
        self.assertGreaterEqual(k, 15)

    def test_vmware_only(self):
        out = self.run_py("from lvx import rules; print(sum(1 for r in rules.R if r['id'].startswith('xcp.')))", 'vmware')
        self.assertEqual(out, '0')


@unittest.skipUnless(SH, 'needs a POSIX sh')
class LiveXcp(unittest.TestCase):
    """Live mode on an XCP-ng host now gets the full Vates rules, case pack and redaction (they used to live in another repo)."""

    def test_live_sr_full(self):
        tmp = tempfile.mkdtemp(prefix='lvx_lx_')
        remote = os.path.join(tmp, 'remote', 'var', 'log')
        os.makedirs(remote)
        pref = live.ALLOWED_PREFIXES
        live.ALLOWED_PREFIXES = pref + (posix(os.path.join(tmp, 'remote')) + '/',)
        smlog = posix(os.path.join(remote, 'SMlog'))
        live.PRODUCTS['_x'] = dict(label='xcp test', logs=[smlog], commands={'df_-h': 'df -h'})
        s = None
        try:
            now = time.time()

            def sl(t, msg):
                tt = time.gmtime(t)
                return '%s %2d %s xcp01 %s\n' % (time.strftime('%b', tt), tt.tm_mday, time.strftime('%H:%M:%S', tt), msg)
            with open(os.path.join(remote, 'SMlog'), 'w') as f:
                for i in range(30):
                    f.write(sl(now - 3000 + i * 60, 'SM: [%d] lock: acquired /var/lock/sm/x/sr' % (2000 + i)))
            s = live.LiveSession('lx', lambda: live.ProcShell([SH]), '_x', os.path.join(tmp, 'm'), interval=2)
            s.shell = live.ProcShell([SH])
            s.poll_once()
            s.analyze()
            self.assertEqual([f for f in s.result['findings'] if f['id'].startswith('xcp.') and f['severity'] in ('high', 'critical')], [])
            with open(os.path.join(remote, 'SMlog'), 'a') as f:
                f.write(sl(now, "SM: [18211] ***** LVHDoISCSISR.create: EXCEPTION <class 'SR.SROSError'>, Insufficient space on SR (no space left in volume group VG_XenStorage-3b5c)"))
                f.write(sl(now + 4, 'SMGC: [24311] gc: ***** Exception while coalescing: Unable to allocate 4096 MB for coalesce, SR has 0 MB free'))
            s.poll_once()
            s.analyze()
            ids = [f['id'] for f in s.result['findings']]
            self.assertEqual(ids[0], 'xcp.sr_full', ids)
            self.assertIn('xcp.coalesce_stuck', ids)
            self.assertTrue(any(e['kind'] == 'finding' and 'SR full' in e['msg'] for e in s.events), s.events)
            md = export.render(dict(s.result, issue='db02 will not start, contact: a@b.com'), 'md', redact=True)[0]
            self.assertNotIn('a@b.com', md)
            self.assertIn('Action plan and drafts', md)
        finally:
            live.ALLOWED_PREFIXES = pref
            live.PRODUCTS.pop('_x', None)
            if s and s.shell:
                s.shell.close()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
