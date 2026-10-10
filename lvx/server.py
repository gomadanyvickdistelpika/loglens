"""HTTP API + static UI (standard library only: runs unchanged on Windows and Linux)."""
import json
import mimetypes
import os
import re
import shutil
import tempfile
import threading
import time
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import __version__, export, viewer
from .analyzer import Analyzer
from .bundle import open_bundle, BundleError
from .timeparse import parse_user_time

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web')
MAX_UPLOAD = int(os.environ.get('LVX_MAX_UPLOAD', 20 << 30))


class State:
    def __init__(self):
        self.lock = threading.Lock()
        self.bundles = {}
        self.jobs = {}
        self.tmp = tempfile.mkdtemp(prefix='lvx_srv_')
        self.roots = [os.path.realpath(p) for p in os.environ.get('LVX_ROOTS', '').split(os.pathsep) if p]
        self.token = os.environ.get('LVX_TOKEN') or None
        self.allow_open = os.environ.get('LVX_ALLOW_OPEN', '1') != '0'

    def path_allowed(self, p):
        if not self.allow_open:
            return False
        if not self.roots:
            return True
        rp = os.path.realpath(p)
        return any(rp == r or rp.startswith(r + os.sep) for r in self.roots)

    def cleanup(self):
        for b in list(self.bundles.values()):
            b.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


def _json(h, code, obj):
    data = json.dumps(obj, default=str).encode()
    h.send_response(code)
    h.send_header('Content-Type', 'application/json; charset=utf-8')
    h.send_header('Content-Length', str(len(data)))
    h.send_header('Cache-Control', 'no-store')
    h.end_headers()
    h.wfile.write(data)


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        server_version = 'LogLens/' + __version__
        protocol_version = 'HTTP/1.1'

        def log_message(self, *a):
            if os.environ.get('LVX_VERBOSE'):
                super().log_message(*a)

        # ---- helpers
        def _auth(self, qs):
            if not state.token:
                return True
            tok = (self.headers.get('Authorization', '')[7:] if self.headers.get('Authorization', '').startswith('Bearer ')
                   else (qs.get('token') or [''])[0])
            return tok == state.token

        def _body(self):
            n = int(self.headers.get('Content-Length') or 0)
            raw = self.rfile.read(n) if n else b''
            return json.loads(raw.decode() or '{}')

        def _bundle(self, bid):
            b = state.bundles.get(bid)
            if not b:
                raise KeyError('Unknown bundle')
            return b

        def _dispatch(self, method):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            path = u.path
            try:
                if not path.startswith('/api/'):
                    return self._static(path)
                if not self._auth(qs):
                    return _json(self, 401, {'error': 'unauthorized'})
                route = (method, path)
                if route == ('GET', '/api/health'):
                    return _json(self, 200, {'ok': True, 'version': __version__})
                if route == ('POST', '/api/upload'):
                    return self._upload(qs)
                if route == ('POST', '/api/open'):
                    return self._open()
                if route == ('POST', '/api/analyze'):
                    return self._analyze()
                if route == ('GET', '/api/view'):
                    return self._view(qs)
                if route == ('GET', '/api/find'):
                    return self._find(qs)
                if route == ('GET', '/api/evidence'):
                    return self._evidence(qs)
                m = re.match(r'^/api/jobs/([\w-]+)/verdicts$', path)
                if m and method == 'POST':
                    return self._verdicts(m.group(1))
                m = re.match(r'^/api/bundles/([\w-]+)/files$', path)
                if m and method == 'GET':
                    b = self._bundle(m.group(1))
                    return _json(self, 200, {'files': b.list_files(), 'name': b.display})
                m = re.match(r'^/api/bundles/([\w-]+)$', path)
                if m and method == 'DELETE':
                    b = state.bundles.pop(m.group(1), None)
                    if b:
                        b.close()
                    return _json(self, 200, {'ok': True})
                m = re.match(r'^/api/jobs/([\w-]+)$', path)
                if m and method == 'GET':
                    j = state.jobs.get(m.group(1))
                    if not j:
                        return _json(self, 404, {'error': 'unknown job'})
                    return _json(self, 200, {k: v for k, v in j.items() if k != 'thread'})
                m = re.match(r'^/api/report/([\w-]+)\.(md|json|html)$', path)
                if m and method == 'GET':
                    return self._report(m.group(1), m.group(2))
                return _json(self, 404, {'error': 'not found'})
            except KeyError as e:
                _json(self, 404, {'error': str(e).strip("'\"")})
            except (ValueError, BundleError, re.error) as e:
                _json(self, 400, {'error': str(e)})
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                traceback.print_exc()
                try:
                    _json(self, 500, {'error': 'internal error: %s' % e})
                except Exception:
                    pass

        def do_GET(self):
            self._dispatch('GET')

        def do_POST(self):
            self._dispatch('POST')

        def do_DELETE(self):
            self._dispatch('DELETE')

        # ---- routes
        def _static(self, path):
            if path in ('', '/'):
                path = '/index.html'
            rel = os.path.normpath(path.lstrip('/'))
            full = os.path.join(WEB_DIR, rel)
            if rel.startswith('..') or not os.path.isfile(full):
                return _json(self, 404, {'error': 'not found'})
            with open(full, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', mimetypes.guess_type(full)[0] or 'application/octet-stream')
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()
            self.wfile.write(data)

        def _register(self, path):
            bid = uuid.uuid4().hex[:12]
            b = open_bundle(bid, path, work_base=state.tmp)
            state.bundles[bid] = b
            files = b.list_files()
            return _json(self, 200, {'id': bid, 'name': b.display, 'files': len(files)})

        def _upload(self, qs):
            name = os.path.basename((qs.get('name') or ['upload.bin'])[0]) or 'upload.bin'
            n = int(self.headers.get('Content-Length') or 0)
            if n <= 0 or n > MAX_UPLOAD:
                return _json(self, 400, {'error': 'missing or oversized upload'})
            d = tempfile.mkdtemp(prefix='up_', dir=state.tmp)
            dest = os.path.join(d, re.sub(r'[<>:"|?*]', '_', name))
            left = n
            with open(dest, 'wb') as out:
                while left > 0:
                    chunk = self.rfile.read(min(1 << 20, left))
                    if not chunk:
                        break
                    out.write(chunk)
                    left -= len(chunk)
            if left:
                shutil.rmtree(d, ignore_errors=True)
                return _json(self, 400, {'error': 'upload truncated'})
            try:
                self._register(dest)
            finally:
                if not os.environ.get('LVX_KEEP_UPLOADS'):
                    pass   # archive remains until server exit (single-file bundles copy it); removed in cleanup()

        def _open(self):
            body = self._body()
            p = (body.get('path') or '').strip().strip('"')
            if not p:
                return _json(self, 400, {'error': 'path required'})
            if not state.path_allowed(p):
                return _json(self, 403, {'error': 'opening server paths is disabled or outside LVX_ROOTS'})
            self._register(p)

        def _analyze(self):
            body = self._body()
            b = self._bundle(body.get('bundle', ''))
            anchor = parse_user_time(body.get('time') or '')
            before = float(body.get('before_h') or (24 if anchor else 240)) * 3600
            after = float(body.get('after_h') or 3) * 3600
            if before < 60 or before > 3650 * 86400 or after < 0:
                raise ValueError('invalid window')
            jid = uuid.uuid4().hex[:12]
            job = dict(id=jid, state='running', progress=0.0, message='Starting', result=None, error=None, bundle=b.id, verdicts={})
            state.jobs[jid] = job

            def prog(p, msg):
                job['progress'], job['message'] = round(p, 3), msg

            def work():
                try:
                    az = Analyzer(b, issue=body.get('issue', ''), anchor=anchor, before_s=before, after_s=after,
                                  min_level=body.get('min_level') or 'warning', progress=prog)
                    job['result'] = az.run()
                    job['state'] = 'done'
                except Exception as e:
                    traceback.print_exc()
                    job['state'], job['error'] = 'error', str(e)
            t = threading.Thread(target=work, daemon=True)
            t.start()
            _json(self, 200, {'job': jid})

        def _view(self, qs):
            g = lambda k, d='': (qs.get(k) or [d])[0]
            b = self._bundle(g('bundle'))
            full = b.resolve(g('path'))
            if not os.path.isfile(full):
                raise KeyError('file not found')
            res = viewer.view(full, offset=int(g('offset', 0)), limit=int(g('limit', 500)), q=g('q'),
                              regex=g('regex') == '1', case=g('case') == '1', level=g('level') or None,
                              start=parse_user_time(g('start')) if g('start') else None,
                              end=parse_user_time(g('end')) if g('end') else None,
                              around=int(g('around')) if g('around') else None)
            _json(self, 200, res)

        def _find(self, qs):
            g = lambda k, d='': (qs.get(k) or [d])[0]
            b = self._bundle(g('bundle'))
            full = b.resolve(g('path'))
            _json(self, 200, viewer.find(full, g('q'), regex=g('regex') == '1', case=g('case') == '1'))

        def _verdicts(self, jid):
            body = self._body()               # always drain the request body, even when the job is unknown
            j = state.jobs.get(jid)
            if not j:
                raise KeyError('unknown job')
            vs = body.get('verdicts')
            if not isinstance(vs, dict) or len(vs) > 2000:
                raise ValueError('verdicts must be an object keyed by finding id')
            clean = {}
            for fid, v in vs.items():
                if not isinstance(v, dict) or v.get('v') not in ('confirm', 'reject', 'unsure'):
                    raise ValueError('verdict must be confirm, reject or unsure')
                clean[str(fid)[:200]] = dict(v=v['v'], note=str(v.get('note') or '')[:2000])
            j['verdicts'] = clean
            _json(self, 200, {'ok': True, 'count': len(clean)})

        def _evidence(self, qs):
            """Raw log context for one finding: each stored sample with `ctx` lines before and after, straight from the bundle file."""
            g = lambda k, d='': (qs.get(k) or [d])[0]
            j = state.jobs.get(g('job'))
            if not j or j['state'] != 'done':
                raise KeyError('unknown or unfinished job')
            res = j['result']
            f = next((x for x in res['findings'] + res.get('advisories', []) if x['id'] == g('finding')), None)
            if not f:
                raise KeyError('unknown finding')
            b = self._bundle(j['bundle'])
            ctx = max(0, min(int(g('ctx', 4)), 50))
            out = []
            for sm in f['samples']:
                full = b.resolve(sm['file'])
                v = viewer.view(full, around=sm['line'], limit=2 * ctx + 1)
                lines = v['lines']
                out.append(dict(file=sm['file'], line=sm['line'], ts=sm['ts'], text=sm['text'],
                                before=[x for x in lines if x['n'] < sm['line']][-ctx:] if ctx else [],
                                hit=next((x for x in lines if x['n'] == sm['line']), None),
                                after=[x for x in lines if x['n'] > sm['line']][:ctx]))
            _json(self, 200, dict(finding=f['id'], title=f['title'], samples=out))

        def _report(self, jid, fmt):
            j = state.jobs.get(jid)
            if not j or j['state'] != 'done':
                raise KeyError('report not ready')
            res = dict(j['result'], verdicts=j.get('verdicts') or {})
            body, ctype = {'md': (export.to_markdown(res), 'text/markdown; charset=utf-8'),
                           'json': (export.to_json(res), 'application/json; charset=utf-8'),
                           'html': (export.to_html(res), 'text/html; charset=utf-8')}[fmt]
            data = body.encode()
            self.send_response(200)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Disposition', 'attachment; filename="loglens-report.%s"' % fmt)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return H


def create_server(host='127.0.0.1', port=8765):
    state = State()
    srv = ThreadingHTTPServer((host, port), make_handler(state))
    srv.daemon_threads = True
    srv.lvx_state = state
    return srv


def serve(host='127.0.0.1', port=8765, open_browser=False):
    srv = create_server(host, port)
    url = 'http://%s:%d/' % ('127.0.0.1' if host in ('0.0.0.0', '::') else host, srv.server_address[1])
    print('LogLens %s listening on %s' % (__version__, url), flush=True)
    if open_browser:
        import webbrowser
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.lvx_state.cleanup()
