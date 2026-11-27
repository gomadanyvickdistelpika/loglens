"""Vates (XCP-ng / Xen Orchestra) accuracy harness - counterpart of tests/accuracy.py.
Every scenario x container format (dir / tgz / nested zip-with-tgz) x noise profile (base / noisy).
Pass: the expected rule is rank 1 (min_rank for exceptions), no finding starts before the window, lines outside the window were suppressed.
Negative scenarios (expect = []): no high/critical *rule* finding may appear.
Usage: python tests/vates_accuracy.py [scenario ...]   (exit 0 when >= 95%)"""
import os
import shutil
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vates_gen as vg                              # noqa: E402
from lvx.analyzer import analyze                    # noqa: E402
from lvx.bundle import open_bundle                  # noqa: E402

FORMATS = ['dir', 'tgz', 'nested']
NOISE = [False, True]


def check(res, truth):
    fails = []
    rules = [f for f in res['findings'] if f['kind'] == 'rule']
    if not truth['expect']:
        bad = [f['id'] for f in rules if f['severity'] in ('high', 'critical')]
        if bad:
            fails.append('false high/critical findings on a clean bundle: %s' % bad)
        return fails
    ranked = [f['id'] for f in res['findings']]
    top = ranked[:truth['min_rank']]
    if not any(e in top for e in truth['expect']):
        fails.append('expected one of %s in top %d, got %s' % (truth['expect'], truth['min_rank'], ranked[:4]))
    w_start = res['window']['start']
    for f in res['findings']:
        if f['first_seen'] and f['first_seen'] < w_start:
            fails.append('finding %s starts before window (%s)' % (f['id'], f['first_seen']))
    if res['stats'].get('lines_outside_window', 0) == 0:
        fails.append('no lines suppressed outside window')
    if not set(res['products']) & {'xcpng', 'xo'}:
        fails.append('bundle not recognised as Vates: %s' % res['products'])
    return fails


def run(verbose=True, only=None, formats=FORMATS, noise=NOISE):
    base = tempfile.mkdtemp(prefix='lvx_vacc_')
    passed = total = 0
    failures = []
    t0 = time.time()
    try:
        for name in vg.S:
            if only and name not in only:
                continue
            for noisy in noise:
                src = os.path.join(base, '%s_%d' % (name, noisy))
                truth = vg.build_dir(src, name, noisy=noisy)
                for fmt in formats:
                    total += 1
                    try:
                        path = vg.pack(src, os.path.join(base, '%s_%d.%s' % (name, noisy, fmt)), fmt, inner_name=name)
                        b = open_bundle('t', path)
                        try:
                            res = analyze(b, issue=truth['issue'], anchor=truth['anchor'], before_s=24 * 3600, after_s=3 * 3600)
                        finally:
                            b.close()
                        fails = check(res, truth)
                    except Exception:
                        fails = ['EXC %s' % traceback.format_exc(limit=3)]
                    if fails:
                        failures.append((name, fmt, noisy, fails))
                    else:
                        passed += 1
                    if verbose:
                        print('%-30s %-7s %-6s %s' % (name, fmt, 'noisy' if noisy else 'base', 'PASS' if not fails else 'FAIL ' + '; '.join(fails)[:300]), flush=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    rate = 100.0 * passed / max(total, 1)
    print('\n%d/%d passed = %.1f%%  (%.1fs)  scenarios=%d' % (passed, total, rate, time.time() - t0, len([n for n in vg.S if not only or n in only])))
    return rate, failures


if __name__ == '__main__':
    rate, _ = run(only=sys.argv[1:] or None)
    sys.exit(0 if rate >= 95 else 1)
