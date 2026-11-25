"""Engine tests (time parsing, levels, bundles, windowing, KB library, viewer, HTTP API) on XCP-ng / XO synthetic bundles."""
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
import vates_gen as gen
from lvx import export, viewer
from lvx.analyzer import Analyzer, detect_level, normalise, issue_topics, is_log_candidate
from lvx.bundle import open_bundle, BundleError
from lvx.server import create_server
from lvx.timeparse import parse_ts, parse_user_time, fmt_ts


class TimeTests(unittest.TestCase):
    def test_iso(self):
        self.assertEqual(parse_ts('2026-09-27T14:30:00.123Z info x'), parse_user_time('2026-09-27T14:30:00Z'))
        self.assertEqual(parse_ts('[2026-09-27 14:30:00] x'), parse_user_time('2026-09-27T14:30:00Z'))

    def test_syslog(self):
        self.assertEqual(parse_ts('Sep 27 14:30:00 xcp01 xapi: x', 2026), parse_user_time('2026-09-27T14:30:00Z'))
        self.assertIsNone(parse_ts('Sep 27 14:30:00 xcp01 xapi: x', None))

    def test_garbage(self):
        self.assertIsNone(parse_ts('no timestamp here'))
        self.assertIsNone(parse_ts('2026-13-45T99:99:99 x'))
        self.assertIsNone(parse_ts(''))

    def test_user_time(self):
        self.assertEqual(parse_user_time('2026-09-27T14:30:00Z'), parse_user_time('2026-09-27 14:30'))
        self.assertIsNone(parse_user_time(''))
        with self.assertRaises(ValueError):
            parse_user_time('tomorrow-ish')


class LevelTests(unittest.TestCase):
    def test_levels(self):
        self.assertEqual(detect_level('Sep 27 14:15:00 xcp01 xapi: [error|xcp01|12 ||xapi] x'), 'error')
        self.assertEqual(detect_level('Sep 27 14:15:00 xcp01 xapi: [ warn|xcp01|12 ||xapi] x'), 'warning')
        self.assertEqual(detect_level('Sep 27 14:15:00 xcp01 xapi: [ info|xcp01|12 ||xapi] Failed to x'), 'info')
        self.assertEqual(detect_level('Sep 27 14:15:00 xcp01 kernel: something'), 'unknown')
        self.assertEqual(detect_level('Sep 27 14:15:00 xcp01 ntpd: lost server'), 'warning')

    def test_normalise_groups(self):
        a = normalise('Sep 27 14:15:00 xcp01 xapi: [error|xcp01|123 ||xapi] Host 10.0.0.1 failed op-4567')
        b = normalise('Sep 28 05:06:07 xcp01 xapi: [error|xcp01|999 ||xapi] Host 10.9.9.9 failed op-1')
        self.assertEqual(a, b)

    def test_topics(self):
        t, _ = issue_topics('Pool master unreachable, HA fenced a host')
        self.assertIn('ha', t)
        t, _ = issue_topics('The SR is full and coalesce is stuck')
        self.assertIn('storage', t)
        t, _ = issue_topics('XO shows a certificate error')
        self.assertIn('certificate', t)

    def test_candidates(self):
        for p in ('var/log/xensource.log', 'var/log/SMlog', 'var/log/SMlog.1.gz', 'var/log/xha.log', 'xo/journalctl-xo-server.txt'):
            self.assertTrue(is_log_candidate(p), p)
        self.assertFalse(is_log_candidate('commands/xe_sr_list.txt'))


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
            self.assertEqual([f['path'] for f in b.list_files()], ['ok/a.log'])
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
        p = os.path.join(self.d, 'SMlog')
        with open(p, 'w') as f:
            f.write('2026-01-01T00:00:00Z xcp01 SM: [1] Raising exception [44, Insufficient space on SR]\n')
        b = open_bundle('x', p)
        try:
            r = Analyzer(b, issue='storage', anchor=parse_user_time('2026-01-01T00:10:00Z')).run()
            self.assertEqual(r['findings'][0]['id'], 'xcp.sr_full')
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
        self.assertTrue({'binary', 'undated'} <= {x[1] for x in r['skipped']})

    def test_gz_log_scanned(self):
        import gzip
        d = os.path.join(self.d, 'g')
        os.makedirs(os.path.join(d, 'var/log'))
        with gzip.open(os.path.join(d, 'var/log/SMlog.1.gz'), 'wt') as f:
            f.write('2026-01-01T00:00:00.000Z xcp01 SMGC: [1] UNDO LEAF-COALESCE of 5c4d3e2f\n')
        b = open_bundle('x', d)
        r = Analyzer(b, issue='storage', anchor=parse_user_time('2026-01-01T00:30:00Z')).run()
        self.assertEqual(r['findings'][0]['id'], 'xcp.coalesce_stuck')


class AnalysisBehaviour(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='lvb_')
        cls.truth = gen.build_dir(os.path.join(cls.d, 'a'), 'sr_insufficient_space')
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
        sr = [f for f in r['findings'] if f['id'] == 'xcp.sr_full'][0]
        self.assertLess(sr['first_seen'], fmt_ts(self.truth['anchor'] - 10 * 86400))

    def test_wrong_time_finds_nothing_relevant(self):
        r = Analyzer(self.b, issue='storage', anchor=self.truth['anchor'] - 5 * 86400, before_s=3600, after_s=3600).run()
        self.assertNotIn('xcp.sr_full', [f['id'] for f in r['findings']])

    def test_auto_anchor(self):
        r = Analyzer(self.b, issue='SR full').run()
        self.assertIn('auto', r['window']['anchor_source'])
        self.assertTrue(r['window']['anchor'].startswith('2026-09-27'))

    def test_issue_changes_ranking(self):
        d = tempfile.mkdtemp(prefix='lvr_')
        try:
            a = gen.build_dir(os.path.join(d, 'x'), 'sr_insufficient_space')
            with open(os.path.join(d, 'x/var/log/xensource.log'), 'a') as f:     # a second, unrelated incident in the same window: memory
                for i in range(30):
                    f.write('%s xcp02 xapi: [error|xcp02|1 ||xapi] Async.VM.start failed: HOST_NOT_ENOUGH_FREE_MEMORY(17179869184, 12884901888)\n'
                            % time.strftime('%b %d %H:%M:%S', time.gmtime(a['anchor'] - 600 + i)))
            b = open_bundle('x', os.path.join(d, 'x'))
            mem = Analyzer(b, issue='a VM will not start, not enough memory on the host', anchor=a['anchor']).run()
            sto = Analyzer(b, issue='the SR is full, insufficient space, snapshots fail', anchor=a['anchor']).run()
            ids = lambda r: [f['id'] for f in r['findings'] if f['kind'] == 'rule']
            self.assertEqual(ids(mem)[0], 'xcp.vm_no_memory')
            self.assertEqual(ids(sto)[0], 'xcp.sr_full')
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_exports(self):
        r = Analyzer(self.b, issue='storage', anchor=self.truth['anchor']).run()
        self.assertIn('Ranked findings', export.to_markdown(r))
        json.loads(export.to_json(r))
        self.assertNotIn('<script>', export.to_html(r))


class NoiseTests(unittest.TestCase):
    def test_chronic_background_is_down_ranked(self):
        d = tempfile.mkdtemp(prefix='lvn_')
        try:
            t = gen.build_dir(os.path.join(d, 'x'), 'sr_insufficient_space', noisy=True)
            with open(os.path.join(d, 'x/var/log/xensource.log'), 'a') as f:       # steady background warning, once a minute across the whole window
                for i in range(0, 26 * 3600, 60):
                    f.write('%s xcp01 xapi: [ warn|xcp01|1 ||xapi] Failed to contact NTP peer 192.0.2.123 (will retry)\n'
                            % time.strftime('%b %d %H:%M:%S', time.gmtime(t['anchor'] - 24 * 3600 + i)))
            b = open_bundle('x', os.path.join(d, 'x'))
            r = Analyzer(b, issue=t['issue'], anchor=t['anchor']).run()
            self.assertEqual(r['findings'][0]['id'], 'xcp.sr_full')
            chronic = [f for f in r['findings'] if f['kind'] == 'pattern' and f['chronic']]
            self.assertTrue(chronic, 'steady background warning should be flagged chronic')
            self.assertTrue(all(f['score'] < 25 for f in chronic))
        finally:
            shutil.rmtree(d, ignore_errors=True)


class DfSnapshot(unittest.TestCase):
    def test_df_output_reported_as_supporting_evidence(self):
        d = tempfile.mkdtemp(prefix='lvdf_')
        try:
            t = gen.build_dir(os.path.join(d, 'x'), 'host_enospc_rsyslog')
            os.makedirs(os.path.join(d, 'x/commands'), exist_ok=True)
            with open(os.path.join(d, 'x/commands/df.txt'), 'w') as f:
                f.write('Filesystem  Size Used Avail Use% Mounted on\n/dev/sda1    18G  18G  100M  99% /\n/dev/sda5   3.9G 58M  3.6G   2% /var/log\n')
            b = open_bundle('x', os.path.join(d, 'x'))
            r = Analyzer(b, issue=t['issue'], anchor=t['anchor']).run()
            snap = [f for f in r['findings'] if f['id'] == 'snap.fs_full']
            self.assertTrue(snap)
            self.assertIn('/ (99%)', snap[0]['title'])
            self.assertNotIn('VCSA', snap[0]['advice'])
            self.assertEqual(snap[0]['kb_research']['vendor'], 'Vates/XCP-ng')
        finally:
            shutil.rmtree(d, ignore_errors=True)


class DfEarlyWarning(unittest.TestCase):
    def _run(self, df_text):
        d = tempfile.mkdtemp(prefix='lvdf2_')
        try:
            t = gen.build_dir(os.path.join(d, 'x'), 'sr_insufficient_space')
            os.makedirs(os.path.join(d, 'x/commands'), exist_ok=True)
            with open(os.path.join(d, 'x/commands/df.txt'), 'w') as f:
                f.write(df_text)
            b = open_bundle('x', os.path.join(d, 'x'))
            return Analyzer(b, issue=t['issue'], anchor=t['anchor']).run()
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_75_to_94_percent_is_a_medium_early_warning(self):
        r = self._run('Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 18G 14G 3G 80% /\n/dev/sda5 3.9G 58M 3.6G 2% /var/log\n')
        snap = [f for f in r['findings'] if f['id'] == 'snap.fs_high']
        self.assertTrue(snap)
        self.assertEqual(snap[0]['severity'], 'medium')
        self.assertIn('/ (80%)', snap[0]['title'])
        self.assertNotIn('snap.fs_full', [f['id'] for f in r['findings']])

    def test_under_75_percent_is_silent(self):
        r = self._run('Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 18G 9G 8G 52% /\n')
        self.assertFalse([f for f in r['findings'] if f['id'].startswith('snap.')])

    def test_95_percent_still_high_and_lists_only_the_full_mounts(self):
        r = self._run('Filesystem Size Used Avail Use% Mounted on\n/dev/sda1 18G 18G 1G 99% /\n/dev/sda5 3.9G 3.2G 0.7G 82% /var/log\n')
        snap = [f for f in r['findings'] if f['id'] == 'snap.fs_full'][0]
        self.assertEqual(snap['severity'], 'high')
        self.assertIn('/ (99%)', snap['title'])
        self.assertNotIn('/var/log', snap['title'])


class KbResearch(unittest.TestCase):
    """Every rule is covered or explicitly 'none'; honest wording; well-formed public links."""

    def test_library_schema(self):
        from lvx import kb
        from lvx.rules import BY_ID
        lib = kb._load()['libs']['vates']
        self.assertGreaterEqual(len(lib['entries']), 15)
        self.assertIn('not read', lib['source'])
        for e in lib['entries']:
            self.assertTrue(e['topic'] and e['articles'], e['topic'])
            for r in e['rules']:
                self.assertIn(r, BY_ID, '%s: unknown rule %s' % (e['topic'], r))
            for a in e['articles']:
                self.assertTrue(a['title'])
                self.assertRegex(kb.article_url(a['id']), r'^https://(?:docs\.)?(?:xcp-ng\.org|xen-orchestra\.com|docs\.xen-orchestra\.com|github\.com)/')
                self.assertRegex(a.get('seen', ''), r'^\d{4}-\d\d-\d\d$')
            if e.get('basis', 'summary') == 'summary':
                self.assertTrue(e['resolution'] or e['cause'], e['topic'])

    def test_every_rule_has_library_entries(self):
        from lvx import kb, templates
        from lvx.rules import R
        covered = {r for e in kb._load()['entries'] for r in e['rules']} | {r for t in templates.all_templates() for r in t['expect_rules']}
        self.assertEqual([r['id'] for r in R if r['id'] not in covered], [])

    def test_none_is_stated_plainly(self):
        from lvx import kb
        g = kb.research(None, '', 'some random message', kind='generic', vendor='vates')
        self.assertEqual(g['status'], 'none')
        self.assertIn('No public Vates KB found', g['message'])
        r = kb.research('xcp.vm_start_fail', 'nothing that matches', 'x')
        if r['status'] == 'none':
            self.assertIn('No public Vates KB found', r['message'])

    def test_found_says_article_text_not_read(self):
        from lvx import kb
        r = kb.research('xcp.sr_chain', 'SR_BACKEND_FAILURE_109 The snapshot chain is too long', 'x')
        self.assertEqual(r['status'], 'found')
        self.assertIn('article text was not read', r['message'])
        self.assertTrue(r['entries'][0]['articles'][0]['seen'])

    def test_extra_file_merged_and_broken_file_ignored(self):
        from lvx import kb
        d = tempfile.mkdtemp(prefix='lvx_kbx_')
        try:
            good = os.path.join(d, 'x.json')
            with open(good, 'w') as f:
                json.dump({'entries': [{'topic': 'Mine', 'rules': ['xcp.sr_full'], 'match': None, 'articles': [{'id': 'https://docs.xcp-ng.org/', 'title': 't'}], 'cause': 'c', 'resolution': ['r']}]}, f)
            os.environ['LVX_KB_FILE'] = good
            kb.reset_cache()
            self.assertTrue(any(e['topic'] == 'Mine' for e in kb._load()['entries']))
            with open(good, 'w') as f:
                f.write('{not json')
            kb.reset_cache()
            self.assertGreaterEqual(len(kb._load()['entries']), 15)
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
        self.assertIn(3000, [l['n'] for l in r['lines']])

    def test_filters(self):
        self.assertEqual(viewer.view(self.p, level='error')['matched'], 10)
        self.assertGreaterEqual(viewer.view(self.p, q='line number 42', limit=50)['matched'], 11)
        self.assertEqual(viewer.view(self.p, q=r'number 4\d$', regex=True)['matched'], 10)
        self.assertEqual(viewer.view(self.p, q='LINE NUMBER 7', case=True)['matched'], 0)
        self.assertEqual(viewer.find(self.p, 'continuation')['lines'], [12])

    def test_continuation_inherits_level(self):
        r = viewer.view(self.p, offset=10, limit=3)
        self.assertEqual(r['lines'][1]['text'].strip(), 'continuation of line 10')

    def test_bad_regex(self):
        import re
        with self.assertRaises(re.error):
            viewer.view(self.p, q='(', regex=True)

    def test_syslog_year_for_window_filter(self):
        p = os.path.join(self.d, 'SMlog')
        with open(p, 'w') as f:
            f.write('Mar 10 09:00:00 xcp01 SM: [1] a\nMar 10 11:00:00 xcp01 SM: [1] b\n')
        r = viewer.view(p, start=parse_user_time('2026-03-10T08:00:00Z'), end=parse_user_time('2026-03-10T10:00:00Z'), year=2026)
        self.assertEqual([l['n'] for l in r['lines']], [1])


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='lva_')
        cls.truth = gen.build_dir(os.path.join(cls.d, 'b'), 'sr_full_coalesce_chain_vmfail')
        cls.tgz = gen.pack(os.path.join(cls.d, 'b'), os.path.join(cls.d, 'b.tgz'), 'tgz', inner_name='xcp')
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
            s, j = self.jreq('POST', '/api/upload?name=xcp.tgz', raw=f.read())
        self.assertEqual(s, 200, j)
        bid = j['id']
        s, j = self.jreq('GET', '/api/bundles/%s/files' % bid)
        self.assertTrue(any(f['path'].endswith('SMlog') for f in j['files']))
        s, j = self.jreq('POST', '/api/analyze', {'bundle': bid, 'issue': self.truth['issue'], 'time': fmt_ts(self.truth['anchor']), 'before_h': 24, 'after_h': 3})
        self.assertEqual(s, 200)
        jid = j['job']
        for _ in range(300):
            s, j = self.jreq('GET', '/api/jobs/' + jid)
            if j['state'] != 'running':
                break
            time.sleep(0.2)
        self.assertEqual(j['state'], 'done', j)
        top = [f['id'] for f in j['result']['findings'][:2]]
        self.assertEqual(top[0], 'xcp.sr_full')                      # root cause first; downstream effects ranked below it
        for fmt, needle in (('md', b'Ranked findings'), ('html', b'<h1>'), ('json', b'"findings"')):
            s, b = self.req('GET', '/api/report/%s.%s' % (jid, fmt))
            self.assertEqual(s, 200)
            self.assertIn(needle, b)
        path = [f['path'] for f in self.jreq('GET', '/api/bundles/%s/files' % bid)[1]['files'] if f['path'].endswith('SMlog')][0]
        s, j = self.jreq('GET', '/api/view?bundle=%s&path=%s&limit=50&q=Insufficient' % (bid, path))
        self.assertEqual(s, 200)
        self.assertGreaterEqual(j['matched'], 1)
        s, j = self.jreq('GET', '/api/find?bundle=%s&path=%s&q=Insufficient' % (bid, path))
        self.assertGreaterEqual(len(j['lines']), 1)
        s, j = self.jreq('GET', '/api/view?bundle=%s&path=%s&q=(&regex=1' % (bid, path))
        self.assertEqual(s, 400)
        s, j = self.jreq('GET', '/api/view?bundle=%s&path=../../../etc/passwd' % bid)
        self.assertIn(s, (400, 404))
        self.assertEqual(self.jreq('DELETE', '/api/bundles/' + bid)[0], 200)
        self.assertEqual(self.jreq('GET', '/api/bundles/%s/files' % bid)[0], 404)

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
        self.assertEqual(self.jreq('POST', '/api/analyze', {'bundle': j['id']})[0], 200)


if __name__ == '__main__':
    unittest.main(verbosity=1)
