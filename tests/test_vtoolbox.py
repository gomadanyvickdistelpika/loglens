"""Vates Toolbox (health modules) and VTLog (signature history + certificates): unit checks, text round-trip, estate bundles, live mode."""
import os
import shutil
import sys
import tempfile
import time
import unittest
from calendar import timegm

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..')
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import build_virtual_estate as be                           # noqa: E402
from lvx import analyzer, bundle, export, live, vtlog, vtoolbox   # noqa: E402

SH = shutil.which('sh') or shutil.which('bash')
REF = timegm((2026, 11, 20, 0, 0, 0))
CTX = dict(kind='xcpng', ref=REF, pool_hosts=3, pool_versions={}, primary=True)


def mod(fn, raw, **ctx):
    return fn(raw, dict(CTX, **ctx))


class Checks(unittest.TestCase):
    def test_units_and_xe_parsing(self):
        self.assertAlmostEqual(vtoolbox.to_bytes('3.4TiB'), 3.4 * (1 << 40))
        self.assertEqual(vtoolbox.to_bytes('210GiB'), 210 * (1 << 30))
        self.assertIsNone(vtoolbox.to_bytes('lots'))
        recs = vtoolbox.xe_records('uuid ( RO) : a\n name-label ( RW): x\n\nuuid ( RO) : b\n name-label ( RW): y\n')
        self.assertEqual([r['name-label'] for r in recs], ['x', 'y'])

    def test_filesystem(self):
        ok = mod(vtoolbox.chk_filesystem, {'df_-h': '/dev/sda1 18G 6G 11G 36% /\ntmpfs 3G 0 3G 0% /dev/shm\n'})
        self.assertEqual(ok['alert'], 'ok')
        warn = mod(vtoolbox.chk_filesystem, {'df_-h': '/dev/sda5 3.9G 3.4G 0.5G 88% /var/log\n'})
        self.assertEqual(warn['alert'], 'warning')
        crit = mod(vtoolbox.chk_filesystem, {'df_-h': '/dev/sda5 3.9G 3.9G 0 100% /var/log\n'})
        self.assertEqual((crit['alert'], crit['rule']), ('critical', 'xcp.host_disk_full'))
        self.assertEqual(mod(vtoolbox.chk_filesystem, {'df_-h': '/dev/xvdb 200G 200G 0 100% /var/lib/xo-server\n'}, kind='xo')['rule'], 'xcp.xo_disk_full')
        self.assertIsNone(mod(vtoolbox.chk_filesystem, {}))

    def test_memory(self):
        free = lambda av, sw: '              total used free shared buff/cache available\nMem: 4096 3000 500 20 500 %d\nSwap: 1023 %d 1000\n' % (av, sw)
        self.assertEqual(mod(vtoolbox.chk_memory, {'free_-m': free(2000, 0)})['alert'], 'ok')
        self.assertEqual(mod(vtoolbox.chk_memory, {'free_-m': free(300, 0)})['alert'], 'warning')
        self.assertEqual(mod(vtoolbox.chk_memory, {'free_-m': free(100, 0)})['alert'], 'critical')
        self.assertEqual(mod(vtoolbox.chk_memory, {'free_-m': free(2000, 990)})['alert'], 'critical')

    def test_sr_space(self):
        sr = lambda u: 'name-label ( RW): SAN\n physical-utilisation ( RO): %s\n physical-size ( RO): 3.4TiB\n' % u
        self.assertEqual(mod(vtoolbox.chk_sr_space, {'xe_sr-list': sr('1.9TiB')})['alert'], 'ok')
        self.assertEqual(mod(vtoolbox.chk_sr_space, {'xe_sr-list': sr('3.0TiB')})['alert'], 'warning')
        c = mod(vtoolbox.chk_sr_space, {'xe_sr-list': sr('3.4TiB')})
        self.assertEqual((c['alert'], c['rule']), ('critical', 'xcp.sr_full'))

    def test_ha_and_versions(self):
        pool = 'name-label ( RW): P\n master ( RO): h1\n ha-enabled ( RO): true\n'
        self.assertEqual(mod(vtoolbox.chk_ha, {'xe_pool-list': pool}, pool_hosts=2)['alert'], 'warning')
        self.assertEqual(mod(vtoolbox.chk_ha, {'xe_pool-list': pool}, pool_hosts=3)['alert'], 'ok')
        self.assertEqual(mod(vtoolbox.chk_ha, {'xe_pool-list': pool.replace('true', 'false')})['alert'], 'info')
        self.assertEqual(mod(vtoolbox.chk_versions, {}, pool_versions={'a': '8.2.1', 'b': '8.2.0'})['alert'], 'warning')
        self.assertEqual(mod(vtoolbox.chk_versions, {}, pool_versions={'a': '8.2.1', 'b': '8.2.1'})['alert'], 'ok')

    def test_multipath_time_toolstack_cert(self):
        good = '3600 dm-3 SAN,X\n|-+- policy=x status=active\n| `- 3:0:0:3 sdc 8:32 active ready running\n`-+- status=enabled\n  `- 4:0:0:3 sdd 8:48 active ready running\n'
        self.assertEqual(mod(vtoolbox.chk_multipath, {'multipath_-ll': good})['alert'], 'ok')
        self.assertEqual(mod(vtoolbox.chk_multipath, {'multipath_-ll': good.replace('active ready running', 'failed faulty running', 1)})['alert'], 'critical')
        self.assertIsNone(mod(vtoolbox.chk_multipath, {'multipath_-ll': 'sh: multipath: not found'}))
        self.assertEqual(mod(vtoolbox.chk_time, {'chronyc_tracking': 'System time : 0.0001 seconds fast of NTP time\nLeap status : Normal\n'})['alert'], 'ok')
        self.assertEqual(mod(vtoolbox.chk_time, {'chronyc_tracking': 'Leap status : Not synchronised\n'})['alert'], 'critical')
        self.assertEqual(mod(vtoolbox.chk_time, {'chronyc_tracking': 'System time : 4.2 seconds slow of NTP time\nLeap status : Normal\n'})['alert'], 'warning')
        self.assertIsNone(mod(vtoolbox.chk_time, {'chronyc_tracking': 'sh: chronyc: not found'}))
        self.assertEqual(mod(vtoolbox.chk_toolstack, {'systemctl_is-active_xapi': 'active\n'})['alert'], 'ok')
        self.assertEqual(mod(vtoolbox.chk_toolstack, {'systemctl_is-active_xapi': 'failed\n'})['alert'], 'critical')
        self.assertIsNone(mod(vtoolbox.chk_toolstack, {'systemctl_is-active_xapi': 'sh: systemctl: not found'}))
        for days, want in ((-3, 'critical'), (9, 'critical'), (20, 'warning'), (200, 'ok')):
            end = time.strftime('%b %e %H:%M:%S %Y GMT', time.gmtime(REF + days * 86400 + 3600))
            self.assertEqual(mod(vtoolbox.chk_certificate, {'openssl_x509_enddate': 'notAfter=%s\n' % end})['alert'], want, days)

    def test_text_roundtrip(self):
        raw = {'df_-h': '/dev/sda5 3.9G 3.9G 0 100% /var/log\n', 'free_-m': 'Mem: 4096 100 3000 0 996 3900\nSwap: 1023 0 1023\n', 'systemctl_is-active_xapi': 'failed\n'}
        rep = vtoolbox.evaluate('xcp-dub-01', raw, ref=REF)
        back = vtoolbox.parse_text(vtoolbox.render(rep))
        self.assertEqual([(m['module'], m['alert'], m['description'], m['rule']) for m in back['modules']], [(m['module'], m['alert'], m['description'], m['rule']) for m in rep['modules']])
        self.assertEqual(back['meta']['hostname'], 'xcp-dub-01')
        self.assertTrue(any(m['resolution'] for m in back['modules'] if m['alert'] == 'critical'))
        self.assertTrue(vtoolbox.sniff(vtoolbox.render(rep)))


class EstateReports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp(prefix='lvx_vtb_')
        cls.res = {}
        for c in be.CASES:
            p = be.build(c, cls.out)
            b = bundle.open_bundle('v-' + c['id'], p, work_base=cls.out)
            cls.res[c['id']] = analyzer.Analyzer(b, issue=c['issue'], anchor=c['incident']).run()

    def tb(self, cid, source='Vates Toolbox'):
        return {rf['title'].split(':')[0]: rf for rf in self.res[cid]['report_findings'] if rf['source'] == source}

    def test_toolbox_flags_what_the_incident_is_about(self):
        self.assertIn('sr_space', self.tb('BW-01'))
        self.assertIn('filesystem', self.tb('BW-03'))
        self.assertIn('toolstack', self.tb('BW-03'))
        self.assertIn('memory', self.tb('BW-05'))
        self.assertIn('filesystem', self.tb('BW-06'))
        self.assertIn('toolstack', self.tb('BW-06'))

    def test_toolbox_also_finds_unrelated_problem(self):
        cert = self.tb('BW-04').get('certificate')
        self.assertIsNotNone(cert)
        self.assertEqual(cert['host'], 'xcp-dub-02')
        self.assertIn('9 day', cert['title'])

    def test_pool_wide_modules_reported_once(self):
        for c in be.CASES:
            reps = [r for r in self.res[c['id']]['reports'] if r['kind'] == 'vtoolbox']
            self.assertEqual(len(reps), 3, c['id'])                                           # 2 hosts + XOA
            self.assertEqual(sum(1 for r in reps for m in r['modules'] if m['module'] == 'sr_space'), 1, c['id'])
            self.assertEqual(sum(1 for r in reps for m in r['modules'] if m['module'] == 'ha_config'), 1, c['id'])

    def test_clean_modules_are_not_findings(self):
        for c in be.CASES:
            for rf in self.res[c['id']]['report_findings']:
                self.assertIn(rf['severity'], ('high', 'medium'))

    def test_vtlog_history_and_precursor(self):
        rep = next(r for r in self.res['BW-01']['reports'] if r['kind'] == 'vtlog')
        sigs = {s['rule']: s for s in rep['sections']['signatures']}
        self.assertTrue(sigs['xcp.sr_full']['in_window'])
        self.assertGreaterEqual(sigs['xcp.sr_full']['count'], 1)
        self.assertTrue(sigs['xcp.sr_full']['evidence'])
        io = sigs['xcp.io_error']                                                            # a transient I/O error ~28 h before the incident
        self.assertFalse(io['in_window'])
        self.assertEqual(io['days_hit'], 1)
        stale = [rf for rf in self.res['BW-01']['report_findings'] if rf['id'] == 'vtl.xcp.io_error']
        self.assertTrue(stale and stale[0]['stale'])

    def test_kb_research_attached_with_vates_vendor(self):
        for rf in self.res['BW-01']['report_findings']:
            if rf.get('rule'):
                self.assertEqual(rf['kb_research']['vendor'], 'Vates/XCP-ng', rf['id'])

    def test_export_lists_vates_sources(self):
        md = export.to_markdown(self.res['BW-03'])
        self.assertIn('## Vates Toolbox / VTLog findings', md)
        self.assertNotIn('GSS Toolbox', md)

    def test_toolbox_text_file_in_bundle_is_parsed_not_scanned_as_log(self):
        rep = next(r for r in self.res['BW-03']['reports'] if r['kind'] == 'vtoolbox' and r['meta']['hostname'] == 'xcp-dub-01')
        d = tempfile.mkdtemp(prefix='lvx_vtbf_')
        with open(os.path.join(d, 'vates-toolbox-xcp-dub-01.txt'), 'w', encoding='utf-8') as f:
            f.write(vtoolbox.render(rep))
        with open(os.path.join(d, 'SMlog'), 'w') as f:
            f.write('Nov 14 22:50:01 xcp-dub-01 SM: [1] lock: acquired /var/lock/sm/x/sr\n')
        res = analyzer.Analyzer(bundle.open_bundle('vtbf', d), issue='x', anchor=timegm((2026, 11, 14, 22, 50, 0))).run()
        self.assertTrue(any(r['kind'] == 'vtoolbox' and r['file'] == 'vates-toolbox-xcp-dub-01.txt' for r in res['reports']))
        self.assertTrue(any(rf['title'].startswith('filesystem') for rf in res['report_findings']))


@unittest.skipUnless(SH, 'needs a POSIX sh')
class LiveToolbox(unittest.TestCase):
    def test_live_snapshots_feed_the_toolbox_and_missing_commands_do_not_alarm(self):
        tmp = tempfile.mkdtemp(prefix='lvx_lt_')
        remote = os.path.join(tmp, 'remote', 'var', 'log')
        os.makedirs(remote)
        pref = live.ALLOWED_PREFIXES
        p = os.path.abspath(os.path.join(tmp, 'remote')).replace('\\', '/')
        p = '/' + p[0].lower() + p[2:] if len(p) > 1 and p[1] == ':' else p
        live.ALLOWED_PREFIXES = pref + (p + '/',)
        now = time.time()
        tt = time.gmtime(now)
        with open(os.path.join(remote, 'SMlog'), 'w') as f:
            f.write('%s %2d %s xcp01 SM: [1] lock: acquired /var/lock/sm/x/sr\n' % (time.strftime('%b', tt), tt.tm_mday, time.strftime('%H:%M:%S', tt)))
        live.PRODUCTS['_v'] = dict(label='v', logs=[p + '/var/log/SMlog'], commands={
            'free_-m': "echo 'Mem: 4096 4021 38 8 37 21'; echo 'Swap: 1023 988 35'",
            'systemctl_is-active_xapi': 'echo active',
            'chronyc_tracking': 'chronyc tracking',                  # not installed here: must produce no verdict, no alarm
            'multipath_-ll': 'multipath -ll'})
        s = live.LiveSession('lt', lambda: live.ProcShell([SH]), '_v', os.path.join(tmp, 'm'), interval=2)
        try:
            s.shell = live.ProcShell([SH])
            s.snapshot_commands()
            s.poll_once()
            s.analyze()
            rep = next(r for r in s.result['reports'] if r['kind'] == 'vtoolbox')
            mods = {m['module']: m for m in rep['modules']}
            self.assertEqual(mods['memory']['alert'], 'critical')
            self.assertEqual(mods['toolstack']['alert'], 'ok')
            self.assertNotIn('time_sync', mods)
            self.assertNotIn('multipath', mods)
            self.assertTrue(any(rf['title'].startswith('memory') for rf in s.result['report_findings']))
        finally:
            live.ALLOWED_PREFIXES = pref
            live.PRODUCTS.pop('_v', None)
            if s.shell:
                s.shell.close()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
