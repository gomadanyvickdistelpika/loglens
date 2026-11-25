#!/usr/bin/env python3
"""Try LIVE mode without a real server: replays a virtual-estate bundle into a local "remote" host while LogLens follows it.

    python tools/live_demo.py BW-03                 # host xcp-dub-01 of case BW-03, web UI on http://127.0.0.1:8799
    python tools/live_demo.py BW-06 --node xoa-dub-01
    python tools/live_demo.py BW-02 --node xcp-dub-02 --speed 60 --port 8800

Open the page, expand "Live: connect over SSH", pick the target type shown in the console, enter any host name and press
"Connect and follow".  The incident starts about a minute later and the finding appears within one refresh interval.
Real SSH is replaced by a local `sh` here (needs sh/bash on PATH: Git for Windows, WSL, macOS, Linux); everything else
(allowlisted read-only polling, rotation handling, analysis, UI) is the real code path."""
import argparse
import os
import shutil
import sys
import tarfile
import tempfile
import threading
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_virtual_estate as be                                    # noqa: E402
from lvx import live, live_profiles, server                          # noqa: E402
from lvx.timeparse import parse_ts                                   # noqa: E402


def posix(p):
    p = os.path.abspath(p).replace('\\', '/')
    return '/' + p[0].lower() + p[2:] if len(p) > 1 and p[1] == ':' else p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('case', help='BW-01 .. BW-06')
    ap.add_argument('--node', default=None, help='which machine to follow (default: xcp-dub-01, or xoa-dub-01 for the XO case)')
    ap.add_argument('--port', type=int, default=8799)
    ap.add_argument('--speed', type=float, default=40, help='replay speed (40 = 40 log seconds per real second)')
    ap.add_argument('--lead', type=int, default=20, help='minutes of history already present when you connect')
    a = ap.parse_args()
    sh = shutil.which('sh') or shutil.which('bash')
    if not sh:
        sys.exit('this demo needs sh or bash on PATH')
    case = next((c for c in be.CASES if c['id'] == a.case.upper()), None)
    if not case:
        sys.exit('unknown case; choose one of ' + ', '.join(c['id'] for c in be.CASES))
    node = a.node or (be.XOA if case['expect'].startswith('xcp.xo') else be.H1)
    tmp = tempfile.mkdtemp(prefix='lvx_livedemo_')
    tgz = be.build(case, tmp)
    with tarfile.open(tgz) as tf:
        tf.extractall(tmp, **({'filter': 'data'} if hasattr(tarfile, 'data_filter') else {}))
    src = os.path.join(tmp, case['id'] + '-' + case['slug'], node)
    remote = os.path.join(tmp, 'remote')
    shutil.copytree(src, remote)
    T = case['incident']
    year = time.gmtime(T).tm_year
    cut = T - a.lead * 60
    pending, files = [], []
    for dp, _d, fns in os.walk(remote):
        if os.sep + 'commands' in dp:
            continue
        for fn in fns:
            full = os.path.join(dp, fn)
            keep, last = [], None
            with open(full, encoding='utf-8') as f:
                for ln in f:
                    ts = parse_ts(ln, year) or last
                    last = ts
                    if ts is None or ts < cut:
                        keep.append(ln)
                    else:
                        pending.append((ts, full, ln))
            with open(full, 'w', encoding='utf-8', newline='\n') as f:
                f.writelines(keep)
            files.append(full)
    pending.sort(key=lambda x: x[0])
    prefix = posix(remote) + '/'
    live.ALLOWED_PREFIXES = live.ALLOWED_PREFIXES + (prefix,)
    product = 'xo' if node == be.XOA else 'xcpng'
    live.PRODUCTS[product] = dict(live.PRODUCTS[product], logs=[posix(f) for f in files], journal=[])
    live.LiveSession.local_path = lambda self, r: os.path.join(self.dir, *r[len(prefix):].split('/')) if r.startswith(prefix) else os.path.join(self.dir, *r.strip('/').split('/'))
    live_profiles.open_ssh = lambda *x, **k: live.ProcShell([sh])
    live_profiles.ssh_argv = lambda *x, **k: ['ssh']
    live._find_ssh = lambda: 'ssh'
    os.environ['LVX_HOME'] = os.path.join(tmp, 'home')

    def replay():
        t0 = time.time()
        for ts, full, ln in pending:
            wait = (ts - cut) / a.speed - (time.time() - t0)
            if wait > 0:
                time.sleep(wait)
            with open(full, 'a', encoding='utf-8', newline='\n') as f:
                f.write(ln)
        print('replay finished', flush=True)
    started = []
    real_start = live_profiles.start_ssh_session

    def start_and_replay(*x, **k):                       # the incident begins ~10 s after the first connection, not at server start
        s = real_start(*x, **k)
        if not started:
            started.append(1)
            threading.Timer(10, lambda: threading.Thread(target=replay, daemon=True).start()).start()
        return s
    live_profiles.start_ssh_session = start_and_replay
    print('Case %s (%s): following %s as target type "%s".' % (case['id'], case['slug'], node, live.PRODUCTS[product]['label']))
    print('Customer issue: %s' % case['issue'])
    print('Expected first finding: %s.  Incident replays in about %d s.' % (case['expect'], int(a.lead * 60 / a.speed)))
    print('Open http://127.0.0.1:%d/  ->  "Live: connect over SSH"  ->  Connect and follow  (Ctrl+C here to stop)' % a.port, flush=True)
    try:
        server.serve('127.0.0.1', a.port, live_enabled=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == '__main__':
    main()
