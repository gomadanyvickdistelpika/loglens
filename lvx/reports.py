"""Parsers for GSS Toolbox text results and TDLog reports (text or PDF via pdftotext).
Both are filtered against the incident window so stale findings are demoted (the 'noise')."""
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone

from .timeparse import parse_ts

ALERT_RANK = {'critical': 3, 'error': 3, 'warning': 2, 'info': 0}
DATE_RE = re.compile(r'(\d{4})-(\d\d)-(\d\d)')


def pdf_to_text(path):
    exe = shutil.which('pdftotext')
    if not exe:
        raise RuntimeError("PDF import needs 'pdftotext' (poppler). Install poppler-utils, or export the report as text.")
    r = subprocess.run([exe, '-layout', path, '-'], capture_output=True, timeout=120)
    return r.stdout.decode('utf-8', 'replace')


def read_report_text(path):
    if path.lower().endswith('.pdf'):
        return pdf_to_text(path)
    with open(path, 'rt', encoding='utf-8', errors='replace') as f:
        return f.read()


def sniff(text):
    head = text[:4000]
    if '##Result Data Begin' in head or 'GSS Toolbox Version' in head:
        return 'toolbox'
    if 'Welcome to TD Log' in head or 'TD Log Report' in head or 'FaultFinder' in text[:200000]:
        return 'tdlog'
    return None


def _day_ts(y, m, d):
    return int(datetime(int(y), int(m), int(d), tzinfo=timezone.utc).timestamp())


# ---------------------------------------------------------------- GSS Toolbox
def parse_toolbox(text, win_start=None, win_end=None):
    meta = {}
    for key, rx in (('toolbox_version', r'GSS Toolbox Version:\s*(.+)'), ('hostname', r'Hostname:\s*(.+)'),
                    ('uptime', r'Uptime:\s*(.+)'), ('log_type', r'Log Type:\s*(.+)'),
                    ('log_date', r'Log Date:\s*(\S+)'), ('hardware', r'Hardware Model:\s*(.+)'),
                    ('product', r'Product:\s*(.+?)\s+Build:')):
        m = re.search(rx, text)
        if m:
            meta[key] = m.group(1).strip()
    m = re.search(r'Product:\s*(.+?)\s+Version:\s*(\S+)\s+Build:\s*(\d+)', text)
    if m:
        meta['product'], meta['version'], meta['build'] = m.group(1), m.group(2), m.group(3)
    m = re.search(r'Plugins Run (\d+)\. Matched: (\d+)', text)
    if m:
        meta['plugins_run'], meta['plugins_matched'] = int(m.group(1)), int(m.group(2))
    modules = []
    parts = re.split(r'^Matched Module:\s*', text, flags=re.M)[1:]
    for p in parts:
        lines = p.split('\n')
        name = lines[0].strip()
        body = '\n'.join(lines[1:])
        g = lambda k: (re.search(r'^\s*%s:\s*(.*)$' % k, body, re.M) or [None, ''])[1].strip()
        alert = (g('Alert Level') or 'Info').lower()
        space = g('Plugin Space')
        desc = g('Description')
        kb = g('KB Article')
        res = ''
        m2 = re.search(r'Resolution:\s*\n(.*?)(?:\n Investigation Details:|\n Additional Information:|\Z)', body, re.S)
        if m2:
            res = ' '.join(x.strip() for x in m2.group(1).splitlines() if x.strip())
        det = ''
        m3 = re.search(r'Investigation Details:\s*\n(.*)', body, re.S)
        if m3:
            det = m3.group(1).rstrip()
        # staleness: dated rows entirely outside the window
        dts = DATE_RE.findall(det)
        stale = False
        newest = None
        if dts and win_start is not None:
            tss = [_day_ts(*d) for d in dts if 1990 < int(d[0]) < 2100]
            if tss:
                newest = max(tss)
                stale = newest < win_start - 86400
        modules.append(dict(module=name, space=space, description=desc, alert=alert, kb=kb or None,
                            resolution=res, details=det[:6000], stale=stale,
                            newest_event=newest))
    return dict(kind='toolbox', meta=meta, modules=modules)


# ---------------------------------------------------------------- TDLog
def _unwrap(text):
    """pdftotext splits long tokens across lines ('2024-02-\\n28T21:..', 'sig-\\n235'); rejoin."""
    t = re.sub(r'\n\s*\nhttps://\S+ +\d+/\d+\n', '\n', text)       # page footers
    t = re.sub(r'\n\d+/\d+/\d+, [\d:]+ [AP]M[^\n]*\n', '\n', t)    # page headers
    t = re.sub(r'(\d{4}-\d\d-)\s*\n\s*\n?\s*(\d\d)', r'\1\2', t)
    t = re.sub(r'(\d{4}-\d\d-\d\d)\s*\n\s*\n?\s*(T\d\d)', r'\1\2', t)
    t = re.sub(r'(sig-)\s*\n\s*\n?\s*(\d)', r'\1\2', t)
    return t


def parse_tdlog(text, win_start=None, win_end=None):
    t = _unwrap(text)
    sections = {}
    m = re.search(r'Certificate Issues(.*?)(?:Database Configuration|Logs / KBs)', t, re.S)
    certs = []
    if m:
        for cm in re.finditer(r'Subject: (.+?)\n.*?Not Before: .*?\| Not After : (.+?) GMT \| expires in \'(-?\d+)\' days', m.group(1), re.S):
            certs.append(dict(subject=cm.group(1).strip()[:120], not_after=cm.group(2).strip(), days_left=int(cm.group(3))))
    sections['certificates'] = certs
    sigs = []
    for chunk in re.split(r"# checked '", t)[1:]:
        head = chunk[:1200]
        m = re.search(r"related to '([^']+)'.*?had (\d+) matches on (\d+) of (\d+) unique days \(([^)]*)\)", chunk, re.S)
        if not m:
            continue
        kb, cnt, days_hit, days_all, dates = m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), m.group(5)
        file_m = re.search(r"against '([^']+)'", head)
        title_m = re.search(r"KB title or comment: '(.*?)'\s*\n", chunk, re.S)
        rx_m = re.search(r"signature regex[^:]*: '(.*?)'\s*\n", chunk, re.S)
        wgt_m = re.search(r'weight \[GSS:([\d.]+)%\|TriggerHappy:([\d.]+)%\]', chunk)
        sig_m = re.search(r'sig-?\s*(\d+)', chunk)
        ev = []
        for ln in chunk.splitlines():
            ln = ln.strip()
            if re.match(r'\d{4}-\d\d-\d\dT', ln):
                ts = parse_ts(ln)
                ev.append((ts, ln[:400]))
        days = [_day_ts(*d) for d in DATE_RE.findall(dates)]
        in_win = True
        if win_start is not None and days:
            in_win = any(win_start - 86400 <= d <= win_end + 86400 for d in days)
        if win_start is not None:
            ev_in = [e for e in ev if e[0] is None or win_start <= e[0] <= win_end]
        else:
            ev_in = ev
        sigs.append(dict(kb=kb, count=cnt, days_hit=days_hit, days_total=days_all,
                         dates=DATE_RE.findall(dates) and ['-'.join(d) for d in DATE_RE.findall(dates)],
                         file=file_m.group(1) if file_m else None,
                         title=' '.join(title_m.group(1).split()) if title_m else None,
                         regex=rx_m.group(1)[:200] if rx_m else None,
                         weight_gss=float(wgt_m.group(1)) if wgt_m else None,
                         trigger_happy=float(wgt_m.group(2)) if wgt_m else None,
                         sig=sig_m.group(1) if sig_m else None,
                         in_window=in_win, evidence=[e[1] for e in ev_in[:5]]))
    sections['signatures'] = sigs
    return dict(kind='tdlog', sections=sections)


def parse_report_file(path, win_start=None, win_end=None):
    text = read_report_text(path)
    kind = sniff(text)
    if kind == 'toolbox':
        r = parse_toolbox(text, win_start, win_end)
    elif kind == 'tdlog':
        r = parse_tdlog(text, win_start, win_end)
    else:
        return None
    r['file'] = os.path.basename(path)
    return r


def report_findings(rep):
    """Normalise a parsed report into finding-like dicts for ranking alongside log findings."""
    out = []
    if rep['kind'] == 'toolbox':
        for m in rep['modules']:
            rank = ALERT_RANK.get(m['alert'], 0)
            if rank < 2:
                continue
            out.append(dict(source='GSS Toolbox', id='tb.' + m['module'], title='%s: %s' % (m['module'], m['description']),
                            severity='high' if rank >= 3 else 'medium', topics=[(m['space'] or '').lower()],
                            kb=m['kb'], advice=m['resolution'], stale=m['stale'], detail=m['details'][:1500]))
    else:
        for s in rep['sections']['signatures']:
            out.append(dict(source='TDLog', id='td.%s.%s' % (s['kb'], s['sig']), title='%s: %s' % (s['kb'], s['title'] or s['regex']),
                            severity='high' if (s['weight_gss'] or 0) >= 90 else 'medium', topics=[],
                            kb=s['kb'].replace('KB', ''), advice='Matches in %s on %s' % (s['file'], ', '.join(s['dates'] or [])),
                            stale=not s['in_window'], detail='\n'.join(s['evidence']), count=s['count']))
    return out
