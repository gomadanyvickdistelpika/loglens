import http.client
import json
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
import gen
from lvx import export, reports, viewer
from lvx.analyzer import Analyzer, detect_level, normalise, issue_topics, is_log_candidate
from lvx.bundle import open_bundle, BundleError
from lvx.server import create_server
from lvx.timeparse import parse_ts, parse_user_time, fmt_ts

DL = os.path.join(os.path.expanduser('~'), 'Downloads')
TB1 = os.path.join(DL, 'gsstoolbox-results (25).txt')
TB2 = os.path.join(DL, 'gsstoolbox-results.txt')
TDPDF = os.path.join(DL, 'TD Log Report - HD Report.pdf')


class TimeTests(unittest.TestCase):
    def test_iso(self):
        self.assertEqual(fmt_ts(parse_ts('2026-02-11T11:05:29.123Z cpu1:2)x')), '2026-02-11T11:05:29Z')
        self.assertEqual(fmt_ts(parse_ts('[2026-02-11 11:05:29,123] x')), '2026-02-11T11:05:29Z')

    def test_syslog(self):
        self.assertEqual(fmt_ts(parse_ts('Feb  1 03:04:05 host x', 2026)), '2026-02-01T03:04:05Z')
        self.assertIsNone(parse_ts('Feb  1 03:04:05 host x'))

    def test_garbage(self):
        for s in ('', 'hello', '2026-13-45T99:99:99', '    indented', '\t at com.vmware.Foo(Foo.java:12)'):
            self.assertIsNone(parse_ts(s, 2026), s)

    def test_user_time(self):
        self.assertEqual(parse_user_time('2026-09-27T14:30:00Z'), parse_user_time('2026-09-27 14:30'))
        self.assertEqual(parse_user_time('2026-09-27T15:30:00+01:00'), parse_user_time('2026-09-27T14:30:00Z'))
        self.assertIsNone(parse_user_time(''))
        with self.assertRaises(ValueError):
            parse_user_time('last tuesday')


class LevelTests(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(detect_level('2026-01-01T00:00:00Z error vpxd[1] x'), 'error')
        self.assertEqual(detect_level('2026-01-01T00:00:00Z cpu1:2)WARNING: x'), 'warning')
        self.assertEqual(detect_level('2026-01-01T00:00:00Z info hostd[1] Failed to x'), 'info')
        self.assertEqual(detect_level('Sep 27 14:15:00 vc kernel: something'), 'unknown')
        self.assertEqual(detect_level('Sep 27 14:15:00 vc ntpd: lost server'), 'warning')

    def test_normalise_groups(self):
        a = normalise('2026-01-01T00:00:00.1Z error vpxd[123] Host 10.0.0.1 failed op-4567')
        b = normalise('2026-01-02T05:06:07.9Z error vpxd[999] Host 10.9.9.9 failed op-1')
        self.assertEqual(a, b)

    def test_topics(self):
        t, _ = issue_topics('Users cannot login, SSO fails after certificate expired')
        self.assertTrue({'auth', 'certificate'} <= t)
        t, _ = issue_topics('datastore went offline')
        self.assertIn('storage', t)

    def test_candidates(self):
        self.assertTrue(is_log_candidate('var/run/log/vmkernel.log'))
        self.assertTrue(is_log_candidate('var/log/vmware/vpxd/vpxd-1.log.2.gz'))
        self.assertFalse(is_log_candidate('commands/esxcli.txt'))
        self.assertFalse(is_log_candidate('gsstoolbox-results.txt'))


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='lvt_')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_zip_slip_blocked(self):
        z = os.path.join(self.d, 'evil.zip')
        with zipfile.ZipFile(z, 'w') as zf:
            zf.writestr('../../escape.log', 'x')
            zf.writestr('ok/a.log', '2026-01-01T00:00:00Z info a\n')
        b = open_bundle('x', z)
        try:
            paths = [f['path'] for f in b.list_files()]
            self.assertEqual(paths, ['ok/a.log'])
            self.assertFalse(os.path.exists(os.path.join(self.d, '..', 'escape.log')))
        finally:
            b.close()

    def test_tar_symlink_ignored(self):
        t = os.path.join(self.d, 'l.tgz')
        src = os.path.join(self.d, 's')
        os.makedirs(src)
        with open(os.path.join(src, 'a.log'), 'w') as f:
            f.write('2026-01-01T00:00:00Z info a\n')
        with tarfile.open(t, 'w:gz') as tf:
            tf.add(src, arcname='b')
            ti = tarfile.TarInfo('b/link')
            ti.type = tarfile.SYMTYPE
            ti.linkname = '/etc/passwd'
            tf.addfile(ti)
        b = open_bundle('x', t)
        try:
            self.assertEqual([f['path'] for f in b.list_files()], ['b/a.log'])
        finally:
            b.close()

    def test_corrupt_archive(self):
        p = os.path.join(self.d, 'bad.tgz')
        with open(p, 'wb') as f:
            f.write(b'\x1f\x8b\x08\x00garbage' * 10)
        with self.assertRaises(Exception):
            open_bundle('x', p)

    def test_single_file_and_missing(self):
        p = os.path.join(self.d, 'vmkernel.log')
        with open(p, 'w') as f:
            f.write('2026-01-01T00:00:00Z cpu1:2)WARNING: All Paths Down\n')
        b = open_bundle('x', p)
        try:
            r = Analyzer(b, issue='storage', anchor=parse_user_time('2026-01-01T00:10:00Z')).run()
            self.assertEqual(r['findings'][0]['id'], 'esx.apd')
        finally:
            b.close()
        with self.assertRaises(BundleError):
            open_bundle('x', os.path.join(self.d, 'nope'))

    def test_empty_and_binaryish(self):
        d = os.path.join(self.d, 'e')
        os.makedirs(os.path.join(d, 'var/log'))
        open(os.path.join(d, 'var/log/empty.log'), 'w').close()
        with open(os.path.join(d, 'var/log/bin.log'), 'wb') as f:
            f.write(b'\x00\x01\x02' * 100)
        with open(os.path.join(d, 'var/log/undated.log'), 'w') as f:
            f.write('hello\nworld\n' * 500)
        b = open_bundle('x', d)
        r = Analyzer(b, issue='x').run()
        self.assertEqual(r['findings'], [])
        reasons = {x[1] for x in r['skipped']}
        self.assertTrue({'binary', 'undated'} <= reasons)

    def test_gz_log_scanned(self):
        import gzip
        d = os.path.join(self.d, 'g')
        os.makedirs(os.path.join(d, 'var/log'))
        with gzip.open(os.path.join(d, 'var/log/vmkernel.log.1.gz'), 'wt') as f:
            f.write('2026-01-01T00:00:00.000Z cpu1:2)@BlueScreen: #PF Exception 14 in world 1\n')
        b = open_bundle('x', d)
        r = Analyzer(b, issue='crash', anchor=parse_user_time('2026-01-01T00:30:00Z')).run()
        self.assertEqual(r['findings'][0]['id'], 'esx.psod')


class AnalysisBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='lvb_')
        cls.truth = gen.build_dir(os.path.join(cls.d, 'a'), 'esx_apd')
        cls.b = open_bundle('x', os.path.join(cls.d, 'a'))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_window_excludes_decoys(self):
        r = Analyzer(self.b, issue='storage', anchor=self.truth['anchor'], before_s=3600 * 24).run()
        self.assertTrue(all(f['first_seen'] >= r['window']['start'] for f in r['findings']))
        self.assertGreater(r['stats']['errors_outside_window'], 0)

    def test_wide_window_includes_decoy(self):
        r = Analyzer(self.b, issue='storage', anchor=self.truth['anchor'], before_s=3600 * 24 * 14).run()
        apd = [f for f in r['findings'] if f['id'] == 'esx.apd'][0]
        self.assertLess(apd['first_seen'], fmt_ts(self.truth['anchor'] - 10 * 86400))

    def test_wrong_time_finds_nothing_relevant(self):
        r = Analyzer(self.b, issue='storage', anchor=self.truth['anchor'] - 5 * 86400, before_s=3600, after_s=3600).run()
        self.assertNotIn('esx.apd', [f['id'] for f in r['findings']])

    def test_auto_anchor(self):
        r = Analyzer(self.b, issue='datastore offline').run()
        self.assertIn('auto', r['window']['anchor_source'])
        self.assertTrue(r['window']['anchor'].startswith('2026-09-27'))

    def test_issue_changes_ranking(self):
        d = tempfile.mkdtemp(prefix='lvr_')
        try:
            a = gen.build_dir(os.path.join(d, 'x'), 'esx_apd')
            # add a network incident in the same window
            with open(os.path.join(d, 'x/var/run/log/vmkernel.log'), 'a') as f:
                for i in range(30):
                    f.write('%s cpu5:2097252)WARNING: vmnic3: NIC Link is Down\n' % gen.iso(a['anchor'] - 600 + i))
            b = open_bundle('x', os.path.join(d, 'x'))
            net = Analyzer(b, issue='VMs lose network connectivity, vmnic flapping', anchor=a['anchor']).run()
            sto = Analyzer(b, issue='datastore went offline, storage paths down', anchor=a['anchor']).run()
            ids = lambda r: [f['id'] for f in r['findings'] if f['kind'] == 'rule']
            self.assertEqual(ids(net)[0], 'esx.nic_down')
            self.assertEqual(ids(sto)[0], 'esx.apd')
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_exports(self):
        r = Analyzer(self.b, issue='storage', anchor=self.truth['anchor']).run()
        md = export.to_markdown(r)
        self.assertIn('Ranked findings', md)
        self.assertIn('esx.apd'.split('.')[0], 'esx')
        json.loads(export.to_json(r))
        h = export.to_html('<script>' and r)
        self.assertNotIn('<script>', h)


class NoiseTests(unittest.TestCase):
    def test_advisory_and_chronic_separated(self):
        d = tempfile.mkdtemp(prefix='lvn_')
        try:
            t = gen.build_dir(os.path.join(d, 'x'), 'vc_sso')
            b = open_bundle('x', os.path.join(d, 'x'))
            r = Analyzer(b, issue=t['issue'], anchor=t['anchor']).run()
            self.assertNotIn('vc.acl_legacy', [f['id'] for f in r['findings']])
            self.assertIn('vc.acl_legacy', [f['id'] for f in r['advisories']])
            self.assertEqual(r['findings'][0]['id'], 'vc.sso')
            self.assertNotIn('vc.replication', [f['id'] for f in r['findings']])   # 'vmdird' must not match 'vmdir'
            chronic = [f for f in r['findings'] if f['kind'] == 'pattern' and f['chronic']]
            self.assertTrue(chronic, 'steady background warning should be flagged chronic')
            self.assertTrue(all(f['score'] < 25 for f in chronic))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class UpgradeFailureRanking(unittest.TestCase):
    """Failed VCSA upgrade (synthetic): root cause must outrank downstream symptoms; old decoys excluded."""

    @classmethod
    def setUpClass(cls):
        import demo_vcenter_upgrade as demo
        cls.tmp = tempfile.mkdtemp(prefix='lvx_upg_')
        demo.main(cls.tmp)
        b = open_bundle('u', os.path.join(cls.tmp, 'vcsa-upgrade-failed.tgz'))
        cls.res = Analyzer(b, issue=demo.SCENARIO['issue'], anchor=demo.FAIL, before_s=86400, after_s=3600).run()
        b.close()
        cls.rank = {f['id']: i for i, f in enumerate(cls.res['findings'])}
        cls.by = {f['id']: f for f in cls.res['findings']}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_root_cause_first(self):
        self.assertEqual(self.res['findings'][0]['id'], 'vc.upg_sizing')

    def test_symptoms_below_cause(self):
        for sym in ('vc.503', 'vc.upg_fail'):
            self.assertGreater(self.rank[sym], self.rank['vc.disk_full'])
            self.assertTrue(self.by[sym].get('symptom_of'))

    def test_old_decoys_excluded(self):
        self.assertEqual(self.by['vc.503']['count'], 1)

    def test_df_snapshot_reported(self):
        self.assertIn('snap.fs_full', self.by)
        self.assertIn('/storage/seat', self.by['snap.fs_full']['title'])

    def test_no_esxi_wording_for_vcenter_disk(self):
        self.assertNotIn('ESXi', self.by['vc.disk_full']['search'])

    def test_kb_research_on_every_finding(self):
        for f in self.res['findings']:
            self.assertIn(f['kb_research']['status'], ('found', 'none'), f['id'])
            self.assertTrue(f['kb_research']['message'])
        top = self.by['vc.disk_full']['kb_research']
        self.assertEqual(top['status'], 'found')
        ids = [a['id'] for e in top['entries'] for a in e['articles']]
        self.assertIn('322286', ids)
        self.assertTrue(all(e['resolution'] for e in top['entries'] if e['basis'] == 'summary'))
        self.assertEqual(self.by['vc.upg_sizing']['kb_research']['entries'][0]['articles'][0]['id'], '322286')
        gen = [f for f in self.res['findings'] if f['id'].startswith('gen.')]
        self.assertTrue(gen)
        for f in gen:
            self.assertEqual(f['kb_research']['status'], 'none')

    def test_markdown_and_html_include_kb(self):
        md = export.to_markdown(self.res)
        self.assertIn('Broadcom KB research', md)
        self.assertIn('knowledge.broadcom.com/external/article/410118', md)
        self.assertIn('No Broadcom KB found', md)
        self.assertIn('not a live search', md)
        h = export.to_html(self.res)
        self.assertIn('Broadcom KB research', h)
        self.assertIn('href="https://knowledge.broadcom.com/external/article/410118"', h)

    def test_markdown_export_mentions_links(self):
        md = export.to_markdown(self.res)
        self.assertIn('downstream symptom', md)
        self.assertIn('Earlier warning', md)


class KbResearch(unittest.TestCase):
    """Broadcom KB research: every rule covered or explicitly 'none', honest wording, well-formed links."""

    def test_library_schema(self):
        from lvx import kb
        from lvx.rules import BY_ID
        lib = kb._load()
        self.assertGreater(len(lib['entries']), 40)
        for e in lib['entries']:
            self.assertTrue(e['topic'] and e['articles'], e['topic'])
            for r in e['rules']:
                self.assertIn(r, BY_ID, '%s: unknown rule %s' % (e['topic'], r))
            for a in e['articles']:
                self.assertTrue(a['title'])
                self.assertRegex(kb.article_url(a['id']), r'^https://knowledge\.broadcom\.com/external/article(/\d+|\?legacyId=\d+)$')
            if e.get('basis', 'summary') == 'summary':
                self.assertTrue(e['resolution'] or e['cause'], e['topic'])

    def test_every_rule_has_library_entries(self):
        from lvx import kb
        from lvx.rules import R
        from lvx import templates
        covered = {r for e in kb._load()['entries'] for r in e['rules']} | {r for t in templates.all_templates() for r in t['expect_rules']}
        self.assertEqual([r['id'] for r in R if r['id'] not in covered], [])

    def test_none_is_stated_plainly(self):
        from lvx import kb
        r = kb.research('esx.psod', 'nothing specific about any known driver', 'x')
        self.assertEqual(r['status'], 'none')
        self.assertIn('No Broadcom KB found', r['message'])
        g = kb.research(None, '', 'some random message', kind='generic')
        self.assertEqual(g['status'], 'none')
        self.assertIn('No Broadcom KB found', g['message'])
        rp = kb.research(None, '', report_kb=None, kind='report')
        self.assertEqual(rp['status'], 'none')

    def test_match_specific_entry_first(self):
        from lvx import kb
        r = kb.research('esx.psod', 'PSOD in world nfnic_worker backtrace', 'x')
        self.assertEqual(r['status'], 'found')
        self.assertEqual(r['entries'][0]['articles'][0]['id'], '317954')
        self.assertTrue(r['entries'][0]['resolution'])

    def test_report_kb_linked(self):
        from lvx import kb
        r = kb.research(None, '', report_kb='80867', kind='report')
        self.assertEqual(r['entries'][0]['articles'][0]['url'], 'https://knowledge.broadcom.com/external/article/80867')

    def test_extra_file_merged_and_broken_file_ignored(self):
        from lvx import kb
        d = tempfile.mkdtemp(prefix='lvx_kbx_')
        try:
            good = os.path.join(d, 'x.json')
            with open(good, 'w') as f:
                json.dump({'entries': [{'topic': 'Mine', 'rules': ['esx.psod'], 'match': None, 'articles': [{'id': '1', 'title': 't'}], 'cause': 'c', 'resolution': ['r']}]}, f)
            os.environ['LVX_KB_FILE'] = good
            kb.reset_cache()
            self.assertTrue(any(e['topic'] == 'Mine' for e in kb._load()['entries']))
            with open(good, 'w') as f:
                f.write('{not json')
            kb.reset_cache()
            self.assertGreater(len(kb._load()['entries']), 40)
        finally:
            os.environ.pop('LVX_KB_FILE', None)
            kb.reset_cache()
            shutil.rmtree(d, ignore_errors=True)


class ViewerTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix='lvv_')
        self.p = os.path.join(self.d, 'x.log')
        with open(self.p, 'w') as f:
            for i in range(5000):
                lv = 'error' if i % 500 == 0 else 'info'
                f.write('2026-01-01T00:%02d:%02d.000Z %s svc[1] line number %d\n' % (i // 60 % 60, i % 60, lv, i))
                if i == 10:
                    f.write('   continuation of line 10\n')

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_paging(self):
        r = viewer.view(self.p, offset=0, limit=100)
        self.assertEqual(len(r['lines']), 100)
        self.assertEqual(r['total'], 5001)
        r = viewer.view(self.p, offset=4950, limit=100)
        self.assertEqual(r['lines'][0]['n'], 4951)
        self.assertEqual(len(r['lines']), 51)

    def test_around(self):
        r = viewer.view(self.p, around=3000, limit=100)
        ns = [l['n'] for l in r['lines']]
        self.assertIn(3000, ns)

    def test_filters(self):
        r = viewer.view(self.p, level='error')
        self.assertEqual(r['matched'], 10)
        r = viewer.view(self.p, q='line number 42', limit=50)
        self.assertGreaterEqual(r['matched'], 11)
        r = viewer.view(self.p, q=r'number 4\d$', regex=True)
        self.assertEqual(r['matched'], 10)
        r = viewer.view(self.p, q='LINE NUMBER 7', case=True)
        self.assertEqual(r['matched'], 0)
        f = viewer.find(self.p, 'continuation')
        self.assertEqual(f['lines'], [12])

    def test_continuation_inherits_level(self):
        r = viewer.view(self.p, offset=10, limit=3)
        self.assertEqual(r['lines'][1]['text'].strip(), 'continuation of line 10')

    def test_bad_regex(self):
        import re
        with self.assertRaises(re.error):
            viewer.view(self.p, q='(', regex=True)


@unittest.skipUnless(os.path.exists(TB1), 'sample GSS Toolbox report not present')
class RealToolbox(unittest.TestCase):
    def test_toolbox_parse(self):
        ts = parse_user_time('2026-02-11T11:00:00Z')
        rep = reports.parse_report_file(TB1, ts - 86400, ts + 3600)
        self.assertEqual(rep['kind'], 'toolbox')
        self.assertEqual(rep['meta']['hostname'], 'gapxesxor01.global-bilgi.entp')
        self.assertEqual(rep['meta']['plugins_matched'], 11)
        mods = {m['module']: m for m in rep['modules']}
        self.assertEqual(len(rep['modules']), 11)
        self.assertEqual(mods['KB90837']['kb'], '90837')
        self.assertTrue(mods['SelEventAsserts']['stale'])          # 2021/2022 events, 2026 window
        self.assertFalse(mods['KB90837']['stale'])
        f = {x['id']: x for x in reports.report_findings(rep)}
        self.assertTrue(f['tb.SelEventAsserts']['stale'])

    def test_second_toolbox(self):
        if not os.path.exists(TB2):
            self.skipTest('no second sample')
        rep = reports.parse_report_file(TB2)
        self.assertEqual(rep['kind'], 'toolbox')
        self.assertEqual(rep['meta']['plugins_matched'], 19)
        self.assertEqual(len(rep['modules']), 19)

    def test_toolbox_in_bundle(self):
        d = tempfile.mkdtemp(prefix='lvtb_')
        try:
            shutil.copy(TB1, os.path.join(d, 'gsstoolbox-results.txt'))
            b = open_bundle('x', d)
            r = Analyzer(b, issue='hardware memory ECC', anchor=parse_user_time('2026-02-11T11:00:00Z')).run()
            titles = [x['title'] for x in r['report_findings']]
            self.assertTrue(any('SelEventAsserts' in t for t in titles))
            stale = {x['id']: x['stale'] for x in r['report_findings']}
            self.assertTrue(stale['tb.SelEventAsserts'])
        finally:
            shutil.rmtree(d, ignore_errors=True)


@unittest.skipUnless(os.path.exists(TDPDF) and shutil.which('pdftotext'), 'TDLog PDF or pdftotext missing')
class RealTDLog(unittest.TestCase):
    def test_td_parse(self):
        ts = parse_user_time('2024-02-29T10:00:00Z')
        rep = reports.parse_report_file(TDPDF, ts - 86400, ts + 3600)
        self.assertEqual(rep['kind'], 'tdlog')
        sigs = rep['sections']['signatures']
        self.assertGreaterEqual(len(sigs), 3)
        kb80867 = [s for s in sigs if s['kb'] == 'KB80867'][0]
        self.assertTrue(kb80867['in_window'])
        self.assertEqual(kb80867['count'], 6)
        self.assertTrue(any(s['kb'] == 'KB78543' for s in sigs))
        old = parse_user_time('2023-01-01T00:00:00Z')
        rep2 = reports.parse_report_file(TDPDF, old, old + 3600)
        self.assertTrue(all(not s['in_window'] for s in rep2['sections']['signatures']))
        self.assertGreaterEqual(len(rep['sections']['certificates']), 1)


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='lva_')
        cls.truth = gen.build_dir(os.path.join(cls.d, 'b'), 'vc_503')
        cls.tgz = gen.pack(os.path.join(cls.d, 'b'), os.path.join(cls.d, 'b.tgz'), 'tgz', inner_name='vc')
        cls.srv = create_server('127.0.0.1', 0)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.lvx_state.cleanup()
        shutil.rmtree(cls.d, ignore_errors=True)

    def req(self, method, path, body=None, raw=None):
        c = http.client.HTTPConnection('127.0.0.1', self.port, timeout=60)
        hdr = {}
        if raw is not None:
            data = raw
        elif body is not None:
            data = json.dumps(body).encode()
            hdr['Content-Type'] = 'application/json'
        else:
            data = None
        c.request(method, path, body=data, headers=hdr)
        r = c.getresponse()
        b = r.read()
        c.close()
        return r.status, b

    def jreq(self, *a, **k):
        s, b = self.req(*a, **k)
        return s, json.loads(b.decode())

    def test_full_flow(self):
        s, b = self.req('GET', '/')
        self.assertEqual(s, 200)
        self.assertIn(b'LogLens', b)
        with open(self.tgz, 'rb') as f:
            s, j = self.jreq('POST', '/api/upload?name=vc.tgz', raw=f.read())
        self.assertEqual(s, 200, j)
        bid = j['id']
        s, j = self.jreq('GET', '/api/bundles/%s/files' % bid)
        self.assertTrue(any(f['path'].endswith('vpxd-1.log') for f in j['files']))
        s, j = self.jreq('POST', '/api/analyze', {'bundle': bid, 'issue': self.truth['issue'],
                                                  'time': fmt_ts(self.truth['anchor']), 'before_h': 24, 'after_h': 3})
        self.assertEqual(s, 200)
        jid = j['job']
        for _ in range(300):
            s, j = self.jreq('GET', '/api/jobs/' + jid)
            if j['state'] != 'running':
                break
            time.sleep(0.2)
        self.assertEqual(j['state'], 'done', j)
        top = [f['id'] for f in j['result']['findings'][:2]]
        self.assertEqual(top, ['vc.ls_client', 'vc.503'])      # earlier LS client failure ranks above its 503 symptom
        self.assertTrue(j['result']['findings'][1].get('symptom_of'))
        for fmt, needle in (('md', b'Ranked findings'), ('html', b'<h1>'), ('json', b'"findings"')):
            s, b = self.req('GET', '/api/report/%s.%s' % (jid, fmt))
            self.assertEqual(s, 200)
            self.assertIn(needle, b)
        path = [f['path'] for f in self.jreq('GET', '/api/bundles/%s/files' % bid)[1]['files'] if f['path'].endswith('rhttpproxy.log')][0]
        s, j = self.jreq('GET', '/api/view?bundle=%s&path=%s&limit=50&q=healthy' % (bid, path))
        self.assertEqual(s, 200)
        self.assertGreaterEqual(j['matched'], 2)
        s, j = self.jreq('GET', '/api/find?bundle=%s&path=%s&q=healthy' % (bid, path))
        self.assertGreaterEqual(len(j['lines']), 2)
        s, j = self.jreq('GET', '/api/view?bundle=%s&path=%s&q=(&regex=1' % (bid, path))
        self.assertEqual(s, 400)
        s, j = self.jreq('GET', '/api/view?bundle=%s&path=../../../etc/passwd' % bid)
        self.assertIn(s, (400, 404))
        s, j = self.jreq('DELETE', '/api/bundles/' + bid)
        self.assertEqual(s, 200)
        s, j = self.jreq('GET', '/api/bundles/%s/files' % bid)
        self.assertEqual(s, 404)

    def test_errors(self):
        self.assertEqual(self.jreq('POST', '/api/analyze', {'bundle': 'nope'})[0], 404)
        self.assertEqual(self.jreq('POST', '/api/open', {'path': ''})[0], 400)
        self.assertEqual(self.jreq('POST', '/api/open', {'path': os.path.join(self.d, 'missing')})[0], 400)
        s, j = self.jreq('POST', '/api/open', {'path': os.path.join(self.d, 'b')})
        self.assertEqual(s, 200)
        self.assertEqual(self.jreq('POST', '/api/analyze', {'bundle': j['id'], 'time': 'garbage'})[0], 400)
        self.assertEqual(self.jreq('GET', '/api/jobs/zzz')[0], 404)
        self.assertEqual(self.req('GET', '/nope.txt')[0], 404)
        self.assertEqual(self.req('GET', '/../lvx/server.py')[0], 404)

    def test_bad_upload(self):
        s, j = self.jreq('POST', '/api/upload?name=x.tgz', raw=b'not an archive at all')
        self.assertEqual(s, 400)
        self.assertIn('Cannot read archive', j['error'])
        s, j = self.jreq('POST', '/api/upload?name=notes.log', raw=b'just text')
        self.assertEqual(s, 200)
        s, j2 = self.jreq('POST', '/api/analyze', {'bundle': j['id']})
        self.assertEqual(s, 200)


if __name__ == '__main__':
    unittest.main(verbosity=1)
