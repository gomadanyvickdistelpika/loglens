"""Accuracy harness: every scenario x container format. Prints pass-rate (target >= 95%)."""
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.dirname(__file__))
import gen
from lvx.analyzer import analyze
from lvx.bundle import open_bundle
from lvx.timeparse import parse_user_time

FORMATS = ['dir', 'zip', 'tgz', 'nested']


def check(res, truth):
    fails = []
    rule_rank = [f['id'] for f in res['findings'] if f['kind'] == 'rule']
    all_rank = [f['id'] for f in res['findings']]
    for exp in truth['expect']:
        if exp not in all_rank[:truth['min_rank']]:
            fails.append('expected %s in top %d, got %s' % (exp, truth['min_rank'], all_rank[:truth['min_rank'] + 2]))
    w_start = res['window']['start']
    for f in res['findings']:
        if f['first_seen'] and f['first_seen'] < w_start:
            fails.append('finding %s starts before window (%s)' % (f['id'], f['first_seen']))
    if res['stats'].get('errors_outside_window', 0) == 0 and res['stats'].get('lines_outside_window', 0) == 0:
        fails.append('no lines suppressed outside window')
    return fails


def run(verbose=True, only=None, formats=FORMATS):
    base = tempfile.mkdtemp(prefix='lvx_acc_')
    passed = total = 0
    failures = []
    t0 = time.time()
    try:
        for name in gen.S:
            if only and name not in only:
                continue
            src = os.path.join(base, name)
            truth = gen.build_dir(src, name)
            for fmt in formats:
                total += 1
                try:
                    path = gen.pack(src, os.path.join(base, '%s.%s' % (name, fmt)), fmt, inner_name=name)
                    b = open_bundle('t', path)
                    try:
                        res = analyze(b, issue=truth['issue'], anchor=truth['anchor'], before_s=24 * 3600, after_s=3 * 3600)
                    finally:
                        b.close()
                    fails = check(res, truth)
                except Exception as e:
                    import traceback
                    fails = ['EXC %s' % traceback.format_exc(limit=3)]
                if fails:
                    failures.append((name, fmt, fails))
                else:
                    passed += 1
                if verbose:
                    print('%-18s %-7s %s' % (name, fmt, 'PASS' if not fails else 'FAIL ' + '; '.join(fails)[:300]), flush=True)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    rate = 100.0 * passed / max(total, 1)
    print('\n%d/%d passed = %.1f%%  (%.1fs)' % (passed, total, rate, time.time() - t0))
    return rate, failures


if __name__ == '__main__':
    only = sys.argv[1:] or None
    rate, _ = run(only=only)
    sys.exit(0 if rate >= 95 else 1)
