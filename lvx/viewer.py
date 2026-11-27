"""Server-side log viewing: paging, search (text/regex), level and time filters."""
import os
import re
import time

from .analyzer import detect_level, LEVEL_NUM
from .bundle import open_text
from .timeparse import parse_ts, fmt_ts

_idx_cache = {}
YEAR = time.gmtime().tm_year
STEP = 2000
MAX_LINE = 4000


def _display_level(lv):
    return 'info' if lv == 'unknown' else lv


def _index(full):
    st = os.stat(full)
    key = (full, st.st_mtime_ns, st.st_size)
    hit = _idx_cache.get(key)
    if hit:
        return hit
    offsets, n, pos = [0], 0, 0
    with open(full, 'rb') as f:
        for raw in f:
            n += 1
            pos += len(raw)
            if n % STEP == 0:
                offsets.append(pos)
    if len(_idx_cache) > 64:
        _idx_cache.clear()
    _idx_cache[key] = (offsets, n)
    return offsets, n


def _mk(n, text, ts, level):
    return dict(n=n, text=text[:MAX_LINE], ts=fmt_ts(ts) if ts else None, level=_display_level(level))


def _matcher(q, regex, case):
    if not q:
        return None
    if regex:
        rx = re.compile(q, 0 if case else re.I)
        return lambda s: rx.search(s) is not None
    if case:
        return lambda s: q in s
    ql = q.lower()
    return lambda s: ql in s.lower()


def view(full, offset=0, limit=500, q='', regex=False, case=False, level=None, start=None, end=None, around=None, year=None):
    YEAR = year or globals()['YEAR']      # year-less syslog lines (XCP-ng) take the incident's year when the caller knows it
    limit = max(1, min(int(limit), 5000))
    match = _matcher(q, regex, case)
    minlv = LEVEL_NUM.get(level or 'debug', 0)
    filtered = bool(match or level not in (None, '', 'all') or start or end)
    gz = full.lower().endswith('.gz')
    if not filtered:
        if around:
            offset = max(0, int(around) - limit // 2 - 1)
        if not gz:
            offsets, total = _index(full)
            blk = min(offset // STEP, len(offsets) - 1)
            skipped = blk * STEP
            lines = []
            with open(full, 'rb') as f:
                f.seek(offsets[blk])
                year = None
                prev_ts, prev_lv = None, 'info'
                for i, raw in enumerate(f, skipped + 1):
                    if i <= offset:
                        continue
                    if len(lines) >= limit:
                        break
                    text = raw.decode('utf-8', 'replace').rstrip('\r\n')
                    ts = parse_ts(text, YEAR)
                    lv = detect_level(text) if ts else (prev_lv if prev_ts else 'info')
                    if ts:
                        prev_ts, prev_lv = ts, lv
                    lines.append(_mk(i, text, ts, lv))
            return dict(lines=lines, total=total, filtered=False, offset=offset)
        lines, total = [], 0
        for i, text in enumerate(open_text(full), 1):
            total = i
            if offset < i <= offset + limit:
                ts = parse_ts(text, YEAR)
                lines.append(_mk(i, text, ts, detect_level(text) if ts else 'info'))
        return dict(lines=lines, total=total, filtered=False, offset=offset)

    lines, matched = [], 0
    total = 0
    prev_ts, prev_lv = None, 'info'
    for i, text in enumerate(open_text(full), 1):
        total = i
        ts = parse_ts(text, YEAR)
        if ts:
            lv = detect_level(text)
            prev_ts, prev_lv = ts, lv
        else:
            ts, lv = prev_ts, prev_lv
        if LEVEL_NUM[lv] < minlv:
            continue
        if (start or end):
            if ts is None or (start and ts < start) or (end and ts > end):
                continue
        if match and not match(text):
            continue
        matched += 1
        if matched > offset and len(lines) < limit:
            lines.append(_mk(i, text, ts, lv))
    return dict(lines=lines, total=total, matched=matched, filtered=True, offset=offset)


def find(full, q, regex=False, case=False, cap=20000):
    match = _matcher(q, regex, case)
    out = []
    if not match:
        return dict(lines=[])
    for i, text in enumerate(open_text(full), 1):
        if match(text):
            out.append(i)
            if len(out) >= cap:
                break
    return dict(lines=out, capped=len(out) >= cap)
