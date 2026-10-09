"""Fast timestamp extraction for ESXi / vCenter log lines."""
import re
from calendar import timegm
from datetime import datetime, timezone

ISO_RE = re.compile(r'^\[?(\d{4})-(\d\d)-(\d\d)[T ](\d\d):(\d\d):(\d\d)')
SYS_RE = re.compile(r'^([A-Z][a-z]{2})\s+(\d{1,2}) (\d\d):(\d\d):(\d\d)')
MONTHS = {m: i + 1 for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
_minute_cache = {}


def parse_ts(line, year=None):
    """Return epoch seconds (UTC) for the timestamp at line start, else None."""
    c = line[:1]
    if c.isdigit() or c == '[':
        m = ISO_RE.match(line)
        if m:
            s = m.group(0)
            key = s[:-3]
            base = _minute_cache.get(key)
            if base is None:
                try:
                    base = timegm((int(m.group(1)), int(m.group(2)), int(m.group(3)),
                                   int(m.group(4)), int(m.group(5)), 0))
                except (ValueError, OverflowError):
                    return None
                if len(_minute_cache) > 200000:
                    _minute_cache.clear()
                _minute_cache[key] = base
            return base + int(s[-2:])
        return None
    if c.isalpha() and year:
        m = SYS_RE.match(line)
        if m and m.group(1) in MONTHS:
            try:
                return timegm((year, MONTHS[m.group(1)], int(m.group(2)),
                               int(m.group(3)), int(m.group(4)), int(m.group(5))))
            except (ValueError, OverflowError):
                return None
    return None


def parse_user_time(text):
    """Parse a user-supplied incident time. Naive values are treated as UTC."""
    if not text:
        return None
    t = text.strip().replace('Z', '+00:00')
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M",
                "%Y/%m/%d %H:%M", "%Y-%m-%d"):
        try:
            d = datetime.fromisoformat(t) if fmt is None else datetime.strptime(t, fmt)
        except ValueError:
            continue
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return int(d.timestamp())
    raise ValueError("Unrecognised time format: %r (use e.g. 2026-02-11T11:05:00Z)" % text)


def fmt_ts(ts):
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
