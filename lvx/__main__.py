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
    args = ap.parse_args(argv)
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


if __name__ == '__main__':
    sys.exit(main())
