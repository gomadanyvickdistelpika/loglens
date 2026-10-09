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
    a = sub.add_parser('analyze', help='analyze a bundle from the command line')
    a.add_argument('bundle')
    a.add_argument('--issue', default='')
    a.add_argument('--time', default='', help='incident time, e.g. 2026-09-27T14:30:00Z (UTC if no zone)')
    a.add_argument('--before-h', type=float, default=None)
    a.add_argument('--after-h', type=float, default=3)
    a.add_argument('--format', choices=['md', 'json', 'html'], default='md')
    a.add_argument('-o', '--output')
    tp = sub.add_parser('templates', help='anonymised resolved-case templates: list | show ID | build ID OUT_DIR')
    tp.add_argument('action', choices=['list', 'show', 'build'])
    tp.add_argument('id', nargs='?')
    tp.add_argument('out', nargs='?', help='output directory for build (also writes OUT/<id>.tgz)')
    args = ap.parse_args(argv)
    if args.cmd == 'templates':
        return _templates(args)
    if args.cmd == 'serve' or args.cmd is None:
        from .server import serve
        host = getattr(args, 'host', '127.0.0.1')
        serve(host, getattr(args, 'port', 8765), open_browser=getattr(args, 'open', False))
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
    out = {'md': export.to_markdown, 'json': export.to_json, 'html': export.to_html}[args.format](res)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(out)
        print('wrote', args.output)
    else:
        sys.stdout.reconfigure(encoding='utf-8')
        print(out)
    return 0


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
