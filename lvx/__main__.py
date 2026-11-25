"""CLI:  python -m lvx serve | analyze <bundle> --issue ... --time ..."""
import argparse
import os
import sys

from . import __version__


def main(argv=None):
    ap = argparse.ArgumentParser(prog='lvx', description='LogLens - targeted VMware log analysis')
    ap.add_argument('--version', action='version', version=__version__)
    sub = ap.add_subparsers(dest='cmd')
    s = sub.add_parser('serve', help='start the web UI')
    s.add_argument('--host', default=os.environ.get('LVX_HOST', '127.0.0.1'))
    s.add_argument('--port', type=int, default=int(os.environ.get('LVX_PORT', 8765)))
    s.add_argument('--open', action='store_true', help='open the browser')
    s.add_argument('--live', action='store_true', help='enable live SSH collection (read-only; needs LVX_TOKEN if not on localhost)')
    lv = sub.add_parser('live', help='connect over SSH, follow the logs and analyse them live (read-only)')
    lv.add_argument('target', help='[user@]host  (key / ssh-agent / ~/.ssh/config auth; add --password to be prompted)')
    lv.add_argument('--product', required=True, choices=['esxi', 'vcsa', 'xcpng', 'xo'])
    lv.add_argument('--port', type=int, default=22)
    lv.add_argument('--key', help='private key file')
    lv.add_argument('--password', action='store_true', help='prompt for a password (kept in memory only)')
    lv.add_argument('--host-key', choices=['accept-new', 'strict'], default='accept-new', help='strict = host must already be in known_hosts')
    lv.add_argument('--extra-log', action='append', default=[], help='additional absolute log path under /var/log, /var/run/log or /storage/log')
    lv.add_argument('--interval', type=float, default=10)
    lv.add_argument('--window-h', type=float, default=2, help='analyse the last N hours of log time')
    lv.add_argument('--issue', default='')
    lv.add_argument('--save', metavar='DIR', help='keep the mirrored logs in DIR (otherwise a temp dir that is deleted on exit)')
    a = sub.add_parser('analyze', help='analyze a bundle from the command line')
    a.add_argument('bundle')
    a.add_argument('--issue', default='')
    a.add_argument('--time', default='', help='incident time, e.g. 2026-09-27T14:30:00Z (UTC if no zone)')
    a.add_argument('--before-h', type=float, default=None)
    a.add_argument('--after-h', type=float, default=3)
    a.add_argument('--format', choices=['md', 'json', 'html'], default='md')
    a.add_argument('-o', '--output')
    a.add_argument('--redact', action='store_true', help='mask emails, secrets, links, IPs (official KB links are kept)')
    a.add_argument('--redact-term', action='append', default=[], help='also mask this literal (customer, host or VM name); repeatable')
    tp = sub.add_parser('templates', help='anonymised resolved-case templates: list | show ID | build ID OUT_DIR')
    tp.add_argument('action', choices=['list', 'show', 'build'])
    tp.add_argument('id', nargs='?')
    tp.add_argument('out', nargs='?', help='output directory for build (also writes OUT/<id>.tgz)')
    args = ap.parse_args(argv)
    if args.cmd == 'templates':
        return _templates(args)
    if args.cmd == 'live':
        return _live(args)
    if args.cmd == 'serve' or args.cmd is None:
        from .server import serve
        host = getattr(args, 'host', '127.0.0.1')
        serve(host, getattr(args, 'port', 8765), open_browser=getattr(args, 'open', False),
              live_enabled=True if getattr(args, 'live', False) else None)
        return 0
    from . import export
    from .analyzer import Analyzer
    from .bundle import open_bundle
    from .timeparse import parse_user_time
    anchor = parse_user_time(args.time)
    b = open_bundle('cli', args.bundle)
    try:
        before = (args.before_h if args.before_h is not None else (24 if anchor else 240)) * 3600
        res = Analyzer(b, issue=args.issue, anchor=anchor, before_s=before, after_s=args.after_h * 3600).run()
    finally:
        b.close()
    out, cats = export.render(res, args.format, redact=args.redact, terms=args.redact_term)
    if args.redact:
        print('redacted: %s' % (', '.join(cats) or 'nothing found'), file=sys.stderr)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(out)
        print('wrote', args.output)
    else:
        sys.stdout.reconfigure(encoding='utf-8')
        print(out)
    return 0


def _live(args):
    import getpass
    import shutil
    import tempfile
    import time
    from . import live, live_profiles
    user, _, host = args.target.rpartition('@')
    work = args.save or tempfile.mkdtemp(prefix='lvx_live_')
    os.makedirs(work, exist_ok=True)
    pw = getpass.getpass('SSH password for %s: ' % args.target) if args.password else None
    spec = dict(host=host, user=user or None, port=args.port, key=args.key, product=args.product, host_key=args.host_key,
                extra_logs=args.extra_log, interval=args.interval, window_h=args.window_h, issue=args.issue)
    try:
        s = live_profiles.start_ssh_session(spec, work, password=pw)
    except live.LiveError as e:
        print('error: %s' % e, file=sys.stderr)
        return 2
    print('Connecting to %s ... (Ctrl+C to stop; read-only, nothing is changed on the server)' % args.target, flush=True)
    seen, last_state = 0, None
    try:
        while True:
            st = s.status(seen)
            if st['state'] != last_state:
                print('[%s] %s%s' % (time.strftime('%H:%M:%S'), st['state'], (' - ' + st['error']) if st['error'] else ''), flush=True)
                last_state = st['state']
            for e in st['events']:
                seen = max(seen, e['n'])
                print('[%s] %s' % (e['t'][11:19], e['msg']), flush=True)
            if st['state'] in ('error', 'stopped'):
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print('\nstopping...')
    finally:
        s.stop()
        s.thread.join(10)
        if s.result:
            print('\nTop findings at exit:')
            for i, f in enumerate(s.result['findings'][:5], 1):
                print('%d. [%s] %s (score %s)' % (i, f['severity'], f['title'], f['score']))
        if args.save:
            print('Mirrored logs kept in', work)
        else:
            shutil.rmtree(work, ignore_errors=True)
    return 0 if s.state != 'error' else 1


def _templates(args):
    from . import templates
    if args.action == 'list':
        for t in templates.all_templates():
            print('%-6s %-9s %-14s %-13s %s' % (t['id'], t['product'], t['version'], t['evidence'], t['title']))
        i = templates.info()
        print('\n%d templates from %s resolved case reports (anonymised; synthetic logs)' % (i['count'], i['reviewed_cases']))
        return 0
    if not args.id:
        print('template id required', file=sys.stderr)
        return 2
    t = templates.get(args.id)
    if args.action == 'show':
        sys.stdout.reconfigure(encoding='utf-8')
        print('%s  %s\nproduct: %s %s   evidence: %s\n\nIssue: %s\n\nCause: %s\n\nResolution:' % (t['id'], t['title'], t['product'], t['version'], t['evidence'], t['issue'], t['cause'] or 'not documented in the case'))
        for i, r in enumerate(t['resolution'], 1):
            print('  %d. %s' % (i, r))
        if not t['resolution']:
            print('  (none documented in the case)')
        print('\nKB cited in the case:')
        for k in t['kb']:
            print('  KB %s  %s  [%s]' % (k['id'], k['title'], k['role']))
        if not t['kb']:
            print('  No Broadcom KB was cited in the case.')
        if t['notes']:
            print('\nNotes: %s' % t['notes'])
        return 0
    out = args.out or '.'
    os.makedirs(out, exist_ok=True)
    d = os.path.join(out, t['id'])
    meta = templates.build_bundle(t, d)
    tgz = templates.pack_tgz(d, os.path.join(out, t['id'] + '.tgz'), inner=t['id'])
    print('bundle: %s\nissue : %s\ntime  : %s' % (tgz, t['issue'], time_str(meta['anchor'])))
    return 0


def time_str(ts):
    import time
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))


if __name__ == '__main__':
    sys.exit(main())
