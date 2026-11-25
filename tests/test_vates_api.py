"""HTTP API tests for the Vates web experience: raw-log evidence per finding, reviewer verdicts, exports, public-KB wording."""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
from lvx import templates                 # noqa: E402
from lvx.server import create_server      # noqa: E402


class VatesApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='lvx_vapi_')
        cls.meta = {}
        for tid in ('CT-53', 'CT-59'):
            cls.meta[tid] = templates.build_bundle(tid, os.path.join(cls.d, tid))
        cls.srv = create_server('127.0.0.1', 0)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.jobs = {tid: cls.analyse(tid) for tid in cls.meta}

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.lvx_state.cleanup()
        shutil.rmtree(cls.d, ignore_errors=True)

    @classmethod
    def req(cls, method, path, body=None):
        c = http.client.HTTPConnection('127.0.0.1', cls.port, timeout=60)
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None, headers={'Content-Type': 'application/json'} if body is not None else {})
        r = c.getresponse()
        b = r.read()
        c.close()
        return r.status, b

    @classmethod
    def jreq(cls, *a, **k):
        s, b = cls.req(*a, **k)
        return s, json.loads(b.decode())

    @classmethod
    def analyse(cls, tid):
        s, b = cls.jreq('POST', '/api/open', {'path': os.path.join(cls.d, tid)})
        assert s == 200, b
        m = cls.meta[tid]
        s, j = cls.jreq('POST', '/api/analyze', {'bundle': b['id'], 'issue': m['issue'], 'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(m['anchor'])), 'before_h': 24, 'after_h': 3})
        for _ in range(200):
            s, job = cls.jreq('GET', '/api/jobs/' + j['job'])
            if job['state'] != 'running':
                break
            time.sleep(0.1)
        assert job['state'] == 'done', job
        return dict(bundle=b['id'], job=j['job'], result=job['result'])

    def test_evidence_for_every_finding_matches_raw_file(self):
        for tid, info in self.jobs.items():
            xcp = [f for f in info['result']['findings'] if f['id'].startswith('xcp.')]
            self.assertTrue(xcp, tid)
            for f in xcp:
                s, ev = self.jreq('GET', '/api/evidence?job=%s&finding=%s&ctx=3' % (info['job'], f['id']))
                self.assertEqual(s, 200)
                self.assertEqual(len(ev['samples']), len(f['samples']))
                for sm in ev['samples']:
                    self.assertIsNotNone(sm['hit'], (tid, f['id']))
                    self.assertEqual(sm['hit']['n'], sm['line'])
                    self.assertEqual(sm['hit']['text'], sm['text'])
                    self.assertLessEqual(len(sm['before']), 3)
                    self.assertLessEqual(len(sm['after']), 3)
                    self.assertTrue(all(x['n'] < sm['line'] for x in sm['before']) and all(x['n'] > sm['line'] for x in sm['after']))
                    # the lines really come from the file in the bundle
                    s2, v = self.jreq('GET', '/api/view?bundle=%s&path=%s&around=%d&limit=7' % (info['bundle'], sm['file'], sm['line']))
                    self.assertIn(sm['text'], [x['text'] for x in v['lines']])

    def test_evidence_contains_syslog_timestamp_and_level(self):
        info = self.jobs['CT-53']
        s, ev = self.jreq('GET', '/api/evidence?job=%s&finding=xcp.sr_full&ctx=2' % info['job'])
        hit = ev['samples'][0]['hit']
        self.assertTrue(hit['ts'].startswith('2026-03-10'), hit)       # year-less syslog line resolved to the incident year
        self.assertIn(hit['level'], ('error', 'warning', 'info', 'critical'))
        self.assertIn('Insufficient space', hit['text'])

    def test_evidence_errors(self):
        info = self.jobs['CT-53']
        self.assertEqual(self.req('GET', '/api/evidence?job=%s&finding=nope' % info['job'])[0], 404)
        self.assertEqual(self.req('GET', '/api/evidence?job=zzz&finding=x')[0], 404)

    def test_verdicts_roundtrip_and_exports(self):
        info = self.jobs['CT-53']
        v = {'xcp.sr_full': {'v': 'confirm', 'note': 'seen in SMlog line 120'}, 'xcp.coalesce_stuck': {'v': 'reject', 'note': ''}, 'xcp.sr_chain': {'v': 'unsure', 'note': 'check <b>xo</b>'}}
        s, r = self.jreq('POST', '/api/jobs/%s/verdicts' % info['job'], {'verdicts': v})
        self.assertEqual((s, r['count']), (200, 3))
        md = self.req('GET', '/api/report/%s.md' % info['job'])[1].decode()
        self.assertIn('**Reviewer verdict:** CONFIRMED against the raw log - seen in SMlog line 120', md)
        self.assertIn('REJECTED', md)
        self.assertIn('not reviewed yet', md)
        h = self.req('GET', '/api/report/%s.html' % info['job'])[1].decode()
        self.assertIn('Reviewer verdict:</b> CONFIRMED against the raw log', h)
        self.assertNotIn('check <b>xo</b>', h)                          # note is HTML-escaped
        self.assertIn('check &lt;b&gt;xo&lt;/b&gt;', h)
        js = json.loads(self.req('GET', '/api/report/%s.json' % info['job'])[1].decode())
        byid = {f['id']: f for f in js['findings']}
        self.assertEqual(byid['xcp.sr_full']['verdict'], {'v': 'confirm', 'note': 'seen in SMlog line 120'})
        self.assertEqual(js['verdicts']['xcp.sr_chain']['v'], 'unsure')

    def test_verdict_validation(self):
        info = self.jobs['CT-59']
        for bad in ({'verdicts': {'x': {'v': 'maybe'}}}, {'verdicts': []}, {'nothing': 1}):
            self.assertEqual(self.req('POST', '/api/jobs/%s/verdicts' % info['job'], bad)[0], 400)
        self.assertEqual(self.req('POST', '/api/jobs/nojob/verdicts', {'verdicts': {}})[0], 404)

    def test_vates_kb_links_or_explicit_none(self):
        for tid, info in self.jobs.items():
            for f in info['result']['findings']:
                if not f['id'].startswith('xcp.'):
                    continue
                r = f['kb_research']
                self.assertEqual(r['vendor'], 'Vates/XCP-ng')
                if r['status'] == 'found':
                    arts = [a for e in r['entries'] for a in e['articles']]
                    self.assertTrue(arts, f['id'])
                    for a in arts:
                        self.assertTrue(a['url'].startswith('https://') and a['seen'] and a['title'], a)
                    self.assertIn('article text was not read', r['message'])
                else:
                    self.assertIn('No public Vates KB found', r['message'])

    def test_generic_findings_in_vates_bundle_say_no_public_vates_kb(self):
        gens = [f for info in self.jobs.values() for f in info['result']['findings'] if f['kind'] == 'pattern']
        for f in gens:
            self.assertIn('No public Vates KB found', f['kb_research']['message'])

    def test_ui_has_controls(self):
        s, b = self.req('GET', '/')
        html = b.decode()
        for needle in ('verdictBlock', 'showEvidence', "'/api/evidence?'", '/verdicts', 'Confirm', 'Reject', 'Unsure', 'localStorage'):
            self.assertIn(needle, html)

    def test_view_year_for_incident_window_filter(self):
        info = self.jobs['CT-53']
        w = info['result']['window']
        s, v = self.jreq('GET', '/api/view?bundle=%s&path=var/log/SMlog&start=%s&end=%s&limit=50' % (info['bundle'], w['start'], w['end']))
        self.assertTrue(v['lines'])
        self.assertTrue(all(x['ts'] and x['ts'].startswith('2026-03') for x in v['lines']))


if __name__ == '__main__':
    unittest.main()
