"""End-to-end HTTP smoke test against a running LogLens server.
Usage: python tests/smoke_http.py [base_url]   (builds a synthetic tgz bundle, uploads, analyzes, exports)"""
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import gen  # noqa: E402

BASE = (sys.argv[1] if len(sys.argv) > 1 else 'http://127.0.0.1:8765').rstrip('/')
TOKEN = os.environ.get('LVX_TOKEN', '')
fails = []


def call(method, path, body=None, raw=None, ctype=None):
    h = {}
    if TOKEN:
        h['Authorization'] = 'Bearer ' + TOKEN
    data = raw
    if body is not None:
        data, h['Content-Type'] = json.dumps(body).encode(), 'application/json'
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def check(name, ok, detail=''):
    print('%-34s %s %s' % (name, 'PASS' if ok else 'FAIL', '' if ok else detail))
    if not ok:
        fails.append(name)


tmp = tempfile.mkdtemp(prefix='lvx_smoke_')
try:
    truth = gen.build_dir(os.path.join(tmp, 'src'), 'esx_apd')
    tgz = gen.pack(os.path.join(tmp, 'src'), os.path.join(tmp, 'b.tgz'), 'tgz', inner_name='esx_apd')
    s, b = call('GET', '/api/health'); check('health', s == 200 and json.loads(b)['ok'])
    s, b = call('GET', '/'); check('index.html', s == 200 and b'LogLens' in b)
    s, b = call('GET', '/..%2f..%2fetc/passwd'); check('static traversal blocked', s == 404, s)
    s, b = call('GET', '/api/bundles/nope/files'); check('unknown bundle 404', s == 404, s)
    with open(tgz, 'rb') as f:
        s, b = call('POST', '/api/upload?name=b.tgz', raw=f.read())
    check('upload tgz', s == 200, b[:200]); bid = json.loads(b)['id']
    s, b = call('GET', '/api/bundles/%s/files' % bid); files = json.loads(b)['files']
    check('list files', s == 200 and files, b[:200])
    s, b = call('POST', '/api/analyze', {'bundle': bid, 'issue': truth['issue'],
                                          'time': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(truth['anchor']))})
    check('analyze start', s == 200, b[:200]); jid = json.loads(b)['job']
    for _ in range(300):
        s, b = call('GET', '/api/jobs/' + jid); j = json.loads(b)
        if j['state'] != 'running':
            break
        time.sleep(0.2)
    check('analyze done', j['state'] == 'done', j.get('error'))
    for fmt in ('md', 'json', 'html'):
        s, b = call('GET', '/api/report/%s.%s' % (jid, fmt)); check('report.' + fmt, s == 200 and len(b) > 200, s)
    path = next(f['path'] if isinstance(f, dict) else f for f in files if 'vmkernel' in (f['path'] if isinstance(f, dict) else f))
    q = urllib.parse.urlencode({'bundle': bid, 'path': path, 'limit': 20})
    s, b = call('GET', '/api/view?' + q); check('view', s == 200 and json.loads(b), s)
    q = urllib.parse.urlencode({'bundle': bid, 'path': path, 'q': 'APD'})
    s, b = call('GET', '/api/find?' + q); check('find', s == 200, s)
    q = urllib.parse.urlencode({'bundle': bid, 'path': '../../etc/passwd'})
    s, b = call('GET', '/api/view?' + q); check('view path traversal blocked', s in (400, 403, 404), s)
    q = urllib.parse.urlencode({'bundle': bid, 'path': path, 'q': '(', 'regex': '1'})
    s, b = call('GET', '/api/find?' + q); check('bad regex -> 400', s == 400, s)
    s, b = call('POST', '/api/analyze', {'bundle': bid, 'time': 'garbage'}); check('bad time -> 400', s == 400, s)
    s, b = call('DELETE', '/api/bundles/' + bid); check('delete bundle', s == 200, s)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print('\n%s' % ('ALL PASS' if not fails else 'FAILED: ' + ', '.join(fails)))
sys.exit(1 if fails else 0)
