"""Run LogLens against every case-template synthetic bundle.
Pass criteria per template:  (1) every expected rule is among the top RANK_LIMIT findings,
(2) the template itself is attached as 'Resolved-case template' KB research on one of those findings,
(3) templates that cite KBs show those KB links, (4) if expect_snapshot: the df snapshot finding exists.
Usage: python tests/templates_accuracy.py [CT-01 ...]"""
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from lvx import templates                    # noqa: E402
from lvx.analyzer import Analyzer            # noqa: E402
from lvx.bundle import open_bundle           # noqa: E402

RANK_LIMIT = 8


def check(t, res):
    fails = []
    by = {f['id']: (i, f) for i, f in enumerate(res['findings'])}
    tmpl_seen = False
    for r in t['expect_rules']:
        if r not in by:
            fails.append('missing %s' % r)
            continue
        i, f = by[r]
        if i >= RANK_LIMIT:
            fails.append('%s ranked %d (> %d)' % (r, i + 1, RANK_LIMIT))
        kr = f.get('kb_research') or {}
        if any(e.get('template') == t['id'] for e in kr.get('entries', [])):
            tmpl_seen = True
            ents = [e for e in kr['entries'] if e.get('template') == t['id']][0]
            cited = [k['id'] for k in t['kb'] if k.get('role') != 'noise']
            got = [a['id'].replace('legacy ', 'legacy:') for a in ents['articles']]
            if cited and sorted(cited) != sorted(got):
                fails.append('KB links differ for %s' % r)
    if t['expect_rules'] and not tmpl_seen:
        fails.append('template not attached to any expected finding')
    if t.get('expect_snapshot') and 'snap.fs_full' not in by:
        fails.append('df snapshot finding missing')
    return fails


def run(only=None, verbose=True, days=3):
    base = tempfile.mkdtemp(prefix='lvx_tpl_')
    total = passed = 0
    rows = []
    t0 = time.time()
    try:
        for t in templates.all_templates():
            if not t['bundle'] or (only and t['id'] not in only):
                continue
            total += 1
            d = os.path.join(base, t['id'])
            try:
                meta = templates.build_bundle(t, d, days=days)
                b = open_bundle('t', d)
                try:
                    res = Analyzer(b, issue=meta['issue'], anchor=meta['anchor'], before_s=24 * 3600, after_s=3 * 3600).run()
                finally:
                    b.close()
                fails = check(t, res)
                top = ', '.join('%s' % f['id'] for f in res['findings'][:4])
            except Exception as e:           # noqa: BLE001
                fails, top = ['EXC %s: %s' % (type(e).__name__, e)], ''
            ok = not fails
            passed += ok
            rows.append((t['id'], ok, fails, top))
            if verbose:
                print('%-6s %-5s %-34s %s' % (t['id'], 'PASS' if ok else 'FAIL', t['evidence'], '' if ok else '; '.join(fails)[:200]), flush=True)
                if not ok:
                    print('        top: %s' % top)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    rate = 100.0 * passed / max(total, 1)
    print('\n%d/%d templates passed = %.1f%%  (%.1fs)' % (passed, total, rate, time.time() - t0))
    return rate, rows


if __name__ == '__main__':
    rate, _ = run(only=sys.argv[1:] or None)
    sys.exit(0 if rate >= 95 else 1)
