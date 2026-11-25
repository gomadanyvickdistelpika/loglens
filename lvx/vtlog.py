"""VTLog: signature history and certificate report for XCP-ng / Xen Orchestra bundles (the Vates counterpart of TDLog).

The analyzer ranks what happened INSIDE the incident window.  VTLog answers the other question a support engineer asks: "when did each
known problem pattern first appear in this bundle, and how often?"  It scans every log line (window ignored) against the Vates rule
signatures and reports, per signature: matches, days with hits, first/last day, the main file, sample lines, and whether any hit falls
in the incident window.  A signature that only fired days before the incident is a precursor; one that fired only long before is stale.
Certificate expiry comes from the openssl output in the bundle's commands/ folders."""
import re
import time
from collections import Counter
from datetime import datetime, timezone

from .timeparse import parse_ts

BRAND = 'VTLog'
MAX_LINE = 400
# Parts of a line that change on every repeat (timestamp, pid, uuid, hex id, standalone number) - stripped to recognise lines already judged.
# Digits glued to a word (SR_BACKEND_FAILURE_109, status=1/FAILURE) are kept, so rules that depend on them still see the difference.
_VOLATILE = re.compile(r'^\S+\s+\d+\s+[\d:]+\s+\S+\s|\b[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b|\b0x[0-9a-f]+\b|(?<![\w.])\d+(?![\w])')


def _day(ts):
    return time.strftime('%Y-%m-%d', time.gmtime(ts))


def scan(files, rules_for, ref_year, win_start, win_end, max_sig=40):
    """files: [(rel_path, full_path)]; rules_for(rel) -> applicable rule dicts.  Returns a 'vtlog' report dict (signatures only)."""
    agg = {}
    t_min = t_max = None
    for rel, full in files:
        rules = rules_for(rel)
        if not rules:
            continue
        try:
            fh = open(full, 'r', encoding='utf-8', errors='replace')
        except OSError:
            continue
        with fh:
            b0, b1 = _bounds(full, ref_year)                              # bundle time span from the file's first and last dated lines
            if b0:
                t_min = b0 if t_min is None else min(t_min, b0)
                t_max = b1 if t_max is None else max(t_max, b1)
            rules = [r for r in rules if r['files'] is None or r['files'].search(rel)]
            if not rules:
                continue
            kwrx = re.compile('|'.join(re.escape(k) for k in sorted({k for r in rules for k in r['kws']})), re.I)    # one cheap pass rejects almost every line
            last = None
            verdict = {}                                                       # volatile-stripped line -> matching rules (repeats are judged once)
            for line in fh:
                if not kwrx.search(line):
                    continue
                ts = parse_ts(line, ref_year)
                if ts:
                    last = ts
                sig = _VOLATILE.sub('#', line[:300])
                hit_rules = verdict.get(sig)
                if hit_rules is None:
                    low = line.lower()
                    hit_rules = verdict[sig] = [r for r in rules if any(k in low for k in r['kws']) and r['rx'].search(line)]
                    if len(verdict) > 50000:
                        verdict.clear()
                for r in hit_rules:
                    a = agg.setdefault(r['id'], dict(rule=r, count=0, days=Counter(), files=Counter(), first=None, last=None, ev_first=[], ev_last=[]))
                    a['count'] += 1
                    a['files'][rel] += 1
                    t = ts or last
                    if t:
                        a['days'][_day(t)] += 1
                        a['first'] = t if a['first'] is None else min(a['first'], t)
                        a['last'] = t if a['last'] is None else max(a['last'], t)
                    txt = line.rstrip('\n')[:MAX_LINE]
                    if len(a['ev_first']) < 2:
                        a['ev_first'].append(txt)
                    else:
                        a['ev_last'] = (a['ev_last'] + [txt])[-2:]
    span_days = max(1, int((t_max - t_min) // 86400) + 1) if t_min and t_max else 1
    sigs = []
    for rid, a in agg.items():
        r = a['rule']
        in_win = bool(a['last'] and a['first'] and a['last'] >= win_start and a['first'] <= win_end and
                      any(win_start - 86400 <= _ts_of_day(d) <= win_end + 86400 for d in a['days']))
        sigs.append(dict(rule=rid, title=r['title'], severity=r['severity'], count=a['count'], days_hit=len(a['days']), days_total=span_days,
                         dates=sorted(a['days'])[:60], per_day=dict(sorted(a['days'].items())[:60]), file=a['files'].most_common(1)[0][0],
                         files=len(a['files']), first=a['first'] and _iso(a['first']), last=a['last'] and _iso(a['last']),
                         regex=r['rx'].pattern[:200], in_window=in_win, evidence=a['ev_first'] + a['ev_last']))
    sigs.sort(key=lambda s: (not s['in_window'], -{'critical': 3, 'high': 2, 'medium': 1, 'low': 0}.get(s['severity'], 0), -s['count']))
    return dict(kind='vtlog', brand=BRAND, file='signature history', sections=dict(signatures=sigs[:max_sig], certificates=[]),
                meta=dict(span_days=span_days, bundle_start=t_min and _iso(t_min), bundle_end=t_max and _iso(t_max)))


def _bounds(full, year):
    """(first, last) timestamp of a plain-text log: the first dated line among the first 40, the last dated line in the final 64 KiB."""
    first = last = None
    try:
        with open(full, 'rb') as f:
            head = f.read(16384).decode('utf-8', 'replace').splitlines()[:40]
            for ln in head:
                first = parse_ts(ln, year)
                if first:
                    break
            f.seek(0, 2)
            f.seek(max(0, f.tell() - 65536))
            for ln in reversed(f.read().decode('utf-8', 'replace').splitlines()):
                last = parse_ts(ln, year)
                if last:
                    break
    except OSError:
        pass
    return (first, last) if first and last else (None, None)


def _iso(ts):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))


def _ts_of_day(d):
    return int(datetime.strptime(d, '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp())


def certificates(toolbox_reps):
    """Certificate rows taken from the Vates Toolbox 'certificate' modules (one per host/appliance)."""
    rows = []
    for rep in toolbox_reps:
        for m in rep.get('modules', []):
            if m['module'] == 'certificate':
                rows.append(dict(subject=rep['meta'].get('hostname', '?'), description=m['description'], alert=m['alert'], detail=m['details'].splitlines()[0] if m['details'] else ''))
    return rows


def report_findings(rep):
    out = []
    for s in rep['sections']['signatures']:
        out.append(dict(source=BRAND, id='vtl.%s' % s['rule'], title='%s: %s' % (s['rule'], s['title']),
                        severity='high' if s['severity'] in ('critical', 'high') else 'medium', topics=[], kb=None, rule=s['rule'],
                        advice='%d match(es) on %d of %d day(s) in %s (first %s, last %s)' % (s['count'], s['days_hit'], s['days_total'], s['file'], s['first'], s['last']),
                        stale=not s['in_window'], detail='\n'.join(s['evidence']), count=s['count']))
    return out
