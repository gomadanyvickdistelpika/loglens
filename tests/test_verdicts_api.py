"""HTTP API tests for the VMware web experience: raw-log evidence per finding, reviewer verdicts, exports, public-KB wording."""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
sys.path.insert(0, HERE)
from lvx import templates                 # noqa: E402
from lvx.server import create_server      # noqa: E402


class VerdictsApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix='lvx_vapi_')
        cls.meta = {}
        for tid in ('CT-46', 'CT-20'):
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
            fs = info['result']['findings']
            self.assertTrue(fs, tid)
            for f in fs:
                s, ev = self.jreq('GET', '/api/evidence?job=%s&finding=%s&ctx=3' % (info['job'], urllib.parse.quote(f['id'], safe='')))
                self.assertEqual(s, 200)
                self.assertEqual(len(ev['samples']), len(f['samples']))
                for sm in ev['samples']:
                    self.assertIsNotNone(sm['hit'], (tid, f['id']))
                    self.assertEqual(sm['hit']['n'], sm['line'])
                    self.assertLessEqual(len(sm['before']), 3)
                    self.assertLessEqual(len(sm['after']), 3)
                    self.assertTrue(all(x['n'] < sm['line'] for x in sm['before']) and all(x['n'] > sm['line'] for x in sm['after']))
                    s2, v = self.jreq('GET', '/api/view?bundle=%s&path=%s&around=%d&limit=7' % (info['bundle'], sm['file'], sm['line']))
                    self.assertIn(sm['text'], [x['text'] for x in v['lines']])

    def test_evidence_errors(self):
        info = self.jobs['CT-46']
        self.assertEqual(self.req('GET', '/api/evidence?job=%s&finding=nope' % info['job'])[0], 404)
        self.assertEqual(self.req('GET', '/api/evidence?job=zzz&finding=x')[0], 404)

    def test_verdicts_roundtrip_and_exports(self):
        info = self.jobs['CT-46']
        ids = [f['id'] for f in info['result']['findings']][:3]
        self.assertGreaterEqual(len(ids), 2)
        v = {ids[0]: {'v': 'confirm', 'note': 'seen in vpxd line 12'}, ids[1]: {'v': 'unsure', 'note': 'check <b>x</b>'}}
        s, r = self.jreq('POST', '/api/jobs/%s/verdicts' % info['job'], {'verdicts': v})
        self.assertEqual((s, r['count']), (200, 2))
        md = self.req('GET', '/api/report/%s.md' % info['job'])[1].decode()
        self.assertIn('**Reviewer verdict:** CONFIRMED against the raw log - seen in vpxd line 12', md)
        self.assertIn('UNSURE', md)
        h = self.req('GET', '/api/report/%s.html' % info['job'])[1].decode()
        self.assertIn('Reviewer verdict:</b> CONFIRMED against the raw log', h)
        self.assertNotIn('check <b>x</b>', h)
        self.assertIn('check &lt;b&gt;x&lt;/b&gt;', h)
        js = json.loads(self.req('GET', '/api/report/%s.json' % info['job'])[1].decode())
        byid = {f['id']: f for f in js['findings']}
        self.assertEqual(byid[ids[0]]['verdict'], {'v': 'confirm', 'note': 'seen in vpxd line 12'})

    def test_verdict_validation(self):
        info = self.jobs['CT-20']
        for bad in ({'verdicts': {'x': {'v': 'maybe'}}}, {'verdicts': []}, {'nothing': 1}):
            self.assertEqual(self.req('POST', '/api/jobs/%s/verdicts' % info['job'], bad)[0], 400)
        self.assertEqual(self.req('POST', '/api/jobs/nojob/verdicts', {'verdicts': {}})[0], 404)

    def test_ui_has_controls(self):
        html = self.req('GET', '/')[1].decode()
        for needle in ('verdictBlock', 'showEvidence', "'/api/evidence?'", '/verdicts', 'Confirm', 'Reject', 'Unsure', 'localStorage'):
            self.assertIn(needle, html)


if __name__ == '__main__':
    unittest.main()
