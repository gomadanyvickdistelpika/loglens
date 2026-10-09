"""Targeted analysis: restrict to the incident window, strip noise, rank by issue relevance."""
import math
import os
import re
import time
from collections import Counter, deque

from . import reports
from .bundle import open_text, looks_binary
from .rules import R
from .timeparse import parse_ts, fmt_ts

# ----------------------------------------------------------------------------- levels
LEVEL_TOKEN = re.compile(r'\b(emerg|alert|crit(?:ical)?|fatal|panic|error|err|warn(?:ing)?|notice|info|verbose|debug|trace)\b', re.I)
LEVEL_MAP = {'emerg': 'critical', 'alert': 'critical', 'crit': 'critical', 'critical': 'critical',
             'fatal': 'critical', 'panic': 'critical', 'error': 'error', 'err': 'error',
             'warn': 'warning', 'warning': 'warning', 'notice': 'info', 'info': 'info',
             'verbose': 'debug', 'debug': 'debug', 'trace': 'debug'}
LEVEL_NUM = {'debug': 0, 'info': 1, 'unknown': 1, 'warning': 2, 'error': 3, 'critical': 4}
INFER = re.compile(r'\b(failed|failure|exception|cannot|unable to|timed out|timeout|lost|denied|refused|unreachable|abort(?:ed)?)\b', re.I)
ERR_RX = re.compile(r'\b(?:error|err|crit(?:ical)?|fatal|panic)\b', re.I)
BENIGN = re.compile(r'\b(0 errors?|no errors?|errors?[=:]\s*0\b|error_?count[=:]\s*0|without errors?|failed[=:]\s*0\b|failures?[=:]\s*0\b|errorcode[=:]\s*0\b|successfully)\b', re.I)


def detect_level(line):
    m = LEVEL_TOKEN.search(line, 0, 150)
    if m:
        return LEVEL_MAP[m.group(1).lower()]
    if INFER.search(line, 0, 300):
        return 'warning'
    return 'unknown'      # no level token (syslog, vobd...): treated as info for noise, but rule hits count as strong


# ----------------------------------------------------------------------------- normalise
_PREFIX = re.compile(r'^\[?\d{4}-\d\d-\d\d[T ][\d:.,]+(?:Z|[+-]\d\d:?\d\d)?\]?:?\s*|^[A-Z][a-z]{2}\s+\d{1,2} [\d:]{8}\s*')
_NORM = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|0x[0-9a-f]+|\d+', re.I)
_CPU = re.compile(r'cpu\d+:\d+\)')


def normalise(line):
    s = _PREFIX.sub('', line, count=1)[:260]
    return _NORM.sub('#', _CPU.sub('', s)).strip()[:160]


# ----------------------------------------------------------------------------- issue topics
TOPIC_WORDS = {
    'storage': 'storage datastore disk lun scsi apd pdl vmfs san hba latency nfs iscsi multipath io slow volume paths datastores',
    'network': 'network nic vmnic link switch vlan mtu uplink packet ping connectivity vds dvs vmkernel',
    'host-connection': 'disconnect disconnected disconnects unresponsive responding "not responding" unreachable connection',
    'crash': 'crash crashed crashes psod purple panic reboot rebooted restart restarted core dump unexpected',
    'hardware': 'hardware dimm memory ecc cpu firmware bios fan psu power sel mce',
    'auth': 'login log-in logon sso sts authentication authenticate password credentials ldap active-directory ad domain token saml access',
    'certificate': 'certificate cert certs expired expiry ssl tls trust',
    'database': 'database db postgres vpostgres vcdb sql',
    'ha': 'ha fdm isolation isolated failover cluster drs partition',
    'vsan': 'vsan congestion',
    'memory': 'memory oom heap swap ballooning',
    'time': 'time ntp clock drift sync',
    'vm': 'vm vms virtual guest poweron power-on snapshot clone vmotion migrate migration backup consolidation deploy',
    'services': 'service services vpxd hostd vpxa 503 upstream unavailable start started stop stopped vmon ui client',
    'upgrade': 'upgrade update patch patching stage install installation',
    'dns': 'dns resolve resolution fqdn hostname',
    'disk-space': 'space full disk-full partition log-partition inode',
    'performance': 'slow slowness performance latency lag hang hung timeout',
    'backup': 'backup snapshot veeam consolidation',
}
STOP = set('the and for with from that this have has was were are not but when after before into than then them they their our out all any can could would should been being there here more some very just also over under about while which what who how why does did done'.split())


def issue_topics(issue):
    if not issue:
        return set(), set()
    low = issue.lower()
    words = set(re.findall(r'[a-z][a-z0-9\-/]{2,}', low))
    topics = set()
    for t, ws in TOPIC_WORDS.items():
        wl = set(w.strip('"') for w in ws.split())
        if words & wl or t in words:
            topics.add(t)
    for phrase, t in (('not responding', 'host-connection'), ('no healthy upstream', 'services'),
                      ('all paths down', 'storage'), ('purple screen', 'crash'), ('log in', 'auth')):
        if phrase in low:
            topics.add(t)
    return topics, set(w for w in words if len(w) > 3 and w not in STOP)


# ----------------------------------------------------------------------------- file selection
_LOGNAME = re.compile(r'(?:\.(?:log|out|err|all|txt)(?:\.\d+)?|\.log\.\d+|messages(?:-\d+)?|syslog(?:\.\d+)?|vmkernel|hostd|vpxa|fdm|vobd|vmkwarning)(?:\.gz)?$', re.I)
_SKIP_DIR = re.compile(r'(?:^|/)(?:commands|etc|proc|sys|usr|lib|bin|sbin|tdlog/cert|reconciled|python|configuration|schema)(?:/|$)', re.I)
_SKIP_NAME = re.compile(r'(?:gsstoolbox|toolbox-results|td[ _-]?log[ _-]?report)', re.I)


def is_log_candidate(rel):
    low = rel.lower()
    if _SKIP_DIR.search(low) and '/log' not in low and not low.startswith('var/'):
        return False
    base = os.path.basename(low)
    if _SKIP_NAME.search(base):
        return False
    return bool(_LOGNAME.search(base))


def classify_product(rel):
    low = rel.lower()
    if re.search(r'vmkernel|vmkwarning|hostd|vpxa|fdm|vobd|esxupdate|storagerm|hostprofile|/var/run/log|nfcd|vmware\.log|shell\.log|vmksummary', low):
        return 'esxi'
    if re.search(r'vpxd|vmware-vpx|vmware-sso|vmdird|vsphere-ui|vmon|postgres|vmware-sts|sts/|lookupsvc|vapi|vpxd-svcs|envoy|rhttpproxy|vsan-health|eam|content-library|certificate-manager|vmafdd|vmcad', low):
        return 'vcenter'
    return 'unknown'


def tail_ts(path, year):
    """Cheap newest-timestamp probe for plain files (reads the last 64 KiB)."""
    try:
        with open(path, 'rb') as f:
            f.seek(0, 2)
            sz = f.tell()
            f.seek(max(0, sz - 65536))
            data = f.read().decode('utf-8', 'replace')
    except OSError:
        return None
    for line in reversed(data.splitlines()):
        ts = parse_ts(line, year)
        if ts:
            return ts
    return None


def _head_ts(path, year):
    try:
        with open(path, 'rt', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                ts = parse_ts(line, year)
                if ts:
                    return ts
                if i > 200:
                    break
    except OSError:
        pass
    return None


# ----------------------------------------------------------------------------- analysis
SEV_BASE = {'critical': 38, 'high': 28, 'medium': 18, 'low': 8}
GEN_BASE = {'critical': 26, 'error': 14, 'warning': 3}
MAX_GENERIC = 4000


class Finding:
    __slots__ = ('rule', 'key', 'strong', 'weak', 'first', 'last', 'nearest', 'files', 'buckets',
                 'variants', 'head', 'tail', 'level_max')

    def __init__(self, rule, key):
        self.rule, self.key = rule, key
        self.strong = self.weak = 0
        self.first = self.last = None
        self.nearest = 1 << 60
        self.files = Counter()
        self.buckets = Counter()
        self.variants = {}
        self.head, self.tail = [], deque(maxlen=2)
        self.level_max = 'info'


class Analyzer:
    def __init__(self, bundle, issue='', anchor=None, before_s=24 * 3600, after_s=3 * 3600,
                 min_level='warning', progress=None, extra_rules=None):
        self.bundle = bundle
        self.issue = issue or ''
        self.anchor_user = anchor
        self.before_s, self.after_s = before_s, after_s
        self.min_level = min_level
        self.progress = progress or (lambda *_: None)
        self.rules = list(R) + list(extra_rules or [])
        self.topics, self.tokens = issue_topics(self.issue)
        self.stats = Counter()
        self.findings = {}
        self.generic = {}
        self.timeline = {}
        self.skipped = []

    # ---- scan helpers
    def _applicable(self, products):
        out = []
        for r in self.rules:
            if r['product'] == 'both' or r['product'] in products or 'unknown' in products:
                out.append(r)
        return out

    def _bucket(self, ts):
        i = int((ts - self.start) // self.bsize)
        return min(max(i, 0), self.nb - 1)

    def run(self):
        t0 = time.time()
        files = [e for e in self.bundle.list_files()]
        cand = [e for e in files if is_log_candidate(e['path'])]
        report_files = [e for e in files if e['path'].lower().endswith(('.txt', '.pdf')) and _SKIP_NAME.search(os.path.basename(e['path']))]
        products = Counter(classify_product(e['path']) for e in cand)
        prod_set = set(p for p in products if p != 'unknown')
        self.products = sorted(prod_set) or ['unknown']

        # reference year + auto anchor from file tails
        tails = []
        for e in cand:
            if not e['path'].lower().endswith('.gz'):
                ts = tail_ts(self.bundle.resolve(e['path']), 2000)
                if ts:
                    tails.append(ts)
        # ISO-only tails are reliable for year inference
        now_year = time.gmtime().tm_year
        ref_year = time.gmtime(max(tails)).tm_year if tails else now_year
        tails = []
        for e in cand:
            if not e['path'].lower().endswith('.gz'):
                ts = tail_ts(self.bundle.resolve(e['path']), ref_year)
                if ts:
                    tails.append(ts)
        tails.sort()
        if self.anchor_user:
            self.anchor = self.anchor_user
            self.anchor_source = 'user'
        elif tails:
            self.anchor = tails[int(0.9 * (len(tails) - 1))]
            self.anchor_source = 'auto (newest operational log timestamp)'
        else:
            self.anchor = int(time.time())
            self.anchor_source = 'none (no dated logs found)'
        self.start = self.anchor - self.before_s
        self.end = self.anchor + (self.after_s if self.anchor_user else min(self.after_s, 3600))
        self.nb = 60
        self.bsize = max(60, (self.end - self.start) // self.nb + 1)
        self.ref_ts = (max(tails) if tails else self.anchor) + 86400

        n = len(cand)
        for i, e in enumerate(cand):
            self.progress(i / max(n, 1) * 0.9, 'Scanning %s' % e['path'])
            try:
                self._scan(e['path'], self._applicable({classify_product(e['path'])} | prod_set))
            except Exception as ex:   # never let one bad file abort the case
                self.skipped.append((e['path'], 'error: %s' % ex))
        reps = []
        for e in report_files:
            try:
                rep = reports.parse_report_file(self.bundle.resolve(e['path']), self.start, self.end)
                if rep:
                    reps.append(rep)
            except Exception as ex:
                self.skipped.append((e['path'], 'report: %s' % ex))
        self.progress(0.95, 'Ranking')
        out = self._build(reps, cand)
        out['stats']['seconds'] = round(time.time() - t0, 2)
        self.progress(1.0, 'Done')
        return out

    def _scan(self, rel, rules):
        full = self.bundle.resolve(rel)
        if looks_binary(full):
            self.skipped.append((rel, 'binary'))
            return
        year = time.gmtime(self.anchor).tm_year
        if not rel.lower().endswith('.gz'):
            head = _head_ts(full, year)
            tail = tail_ts(full, year)
            if head and tail and (tail < self.start or head > self.end):
                self.stats['files_outside_window'] += 1
                self.stats['bytes_skipped_outside_window'] += os.path.getsize(full)
                return
        prev_ts, prev_level = None, 'info'
        ctx = deque(maxlen=2)
        dated = 0
        first_lines = 0
        s_total = s_dated = s_win = 0
        minlv = LEVEL_NUM[self.min_level]
        start, end = self.start, self.end
        ref = self.ref_ts
        for lineno, line in enumerate(open_text(full), 1):
            s_total += 1
            if not line:
                continue
            ts = parse_ts(line, year)
            cont = False
            if ts is not None:
                if ts > ref:                    # year-less syslog from the previous year
                    ts = parse_ts(line, year - 1) or ts
                dated += 1
                s_dated += 1
                if ts < start or ts > end:
                    self.stats['lines_outside_window'] += 1
                    if ERR_RX.search(line, 0, 150):
                        self.stats['errors_outside_window'] += 1
                    prev_ts, prev_level = ts, 'info'
                    ctx.append(line)
                    continue
                level = detect_level(line)
            else:
                first_lines += 1
                if prev_ts is None:
                    if first_lines > 300 and dated == 0:
                        self.skipped.append((rel, 'undated'))
                        self.stats['lines_total'] += s_total
                        return
                    continue
                ts, level, cont = prev_ts, prev_level, True
            prev_ts, prev_level = ts, level
            if cont and (ts < start or ts > end):
                self.stats['lines_outside_window'] += 1
                continue
            s_win += 1
            lnum = LEVEL_NUM[level]
            low = line.lower()
            hit = False
            key = None
            benign = BENIGN.search(line) is not None
            if not benign:
                for r in rules:
                    if r['files'] is not None and not r['files'].search(rel):
                        continue
                    for kw in r['kws']:
                        if kw in low:
                            break
                    else:
                        continue
                    if r['rx'].search(line):
                        hit = True
                        if key is None:
                            key = normalise(line)
                        self._hit_rule(r, rel, lineno, ts, line, level, ctx, key)
            if lnum >= 2:
                b = self._bucket(ts)
                tl = self.timeline.setdefault(b, Counter())
                if not cont:
                    tl[level] += 1
            if not hit and lnum >= minlv and not cont and not benign:
                self._hit_generic(rel, lineno, ts, line, level, ctx, normalise(line))
            ctx.append(line)
        self.stats['lines_total'] += s_total
        self.stats['lines_dated'] += s_dated
        self.stats['lines_in_window'] += s_win
        self.stats['files_scanned'] += 1
        if dated == 0:
            self.skipped.append((rel, 'undated'))

    def _touch(self, f, rel, ts, line, lineno, level, ctx, strong, key):
        if strong:
            f.strong += 1
        else:
            f.weak += 1
        if f.first is None or ts < f.first:
            f.first = ts
        if f.last is None or ts > f.last:
            f.last = ts
        d = abs(ts - self.anchor)
        if d < f.nearest and strong:
            f.nearest = d
        f.files[rel] += 1
        f.buckets[self._bucket(ts)] += 1
        if LEVEL_NUM[level] > LEVEL_NUM[f.level_max]:
            f.level_max = level
        v = f.variants.get(key)
        if v is None:
            if len(f.variants) < 40:
                f.variants[key] = [1, rel, lineno]
        else:
            v[0] += 1
        if len(f.head) < 3:
            f.head.append((rel, lineno, ts, line, list(ctx)))
        else:
            f.tail.append((rel, lineno, ts, line, ()))

    def _hit_rule(self, r, rel, lineno, ts, line, level, ctx, key):
        f = self.findings.get(r['id'])
        if f is None:
            f = self.findings[r['id']] = Finding(r, r['id'])
        strong = LEVEL_NUM[level] >= 2 or level == 'unknown' or r['any_level']
        self._touch(f, rel, ts, line, lineno, level, ctx, strong, key)

    def _hit_generic(self, rel, lineno, ts, line, level, ctx, key):
        f = self.generic.get(key)
        if f is None:
            if len(self.generic) >= MAX_GENERIC:
                self.stats['generic_dropped'] += 1
                return
            f = self.generic[key] = Finding(None, key)
        self._touch(f, rel, ts, line, lineno, level, ctx, True, key)

    # ---- scoring
    def _relevance(self, topics, text):
        rel = 0.0
        if self.topics and topics and (self.topics & set(topics)):
            rel += 25
        if self.tokens:
            hits = sum(1 for t in self.tokens if t in text)
            rel += min(10, hits * 4)
        return rel

    def _score(self, f, base, topics, text):
        n = f.strong + 0.5 * f.weak
        advisory = f.rule is not None and f.rule['any_level']
        cnt = min(3.0 if advisory else 14.0, 3.2 * math.log2(1 + n))
        span = max(self.end - self.start, 1)
        prox = 20.0 * math.exp(-min(f.nearest, 1 << 40) / max(1800.0, 0.35 * span)) if (f.strong and not advisory) else 4.0
        rel = self._relevance(topics, text)
        return min(100.0, base + cnt + prox + rel), rel

    def _finding_dict(self, f, generic=False):
        samples = [dict(file=a, line=b, ts=fmt_ts(c), text=d[:500], context=[x[:300] for x in e])
                   for a, b, c, d, e in list(f.head) + list(f.tail)]
        variants = sorted(f.variants.items(), key=lambda kv: -kv[1][0])[:5]
        text = ' '.join(s['text'].lower() for s in samples) + ' ' + ' '.join(k.lower() for k, _ in variants)
        if generic:
            base = GEN_BASE.get(f.level_max, 3)
            topics = []
            title = f.key if len(f.key) < 140 else f.key[:137] + '...'
            r = None
        else:
            r = f.rule
            base = SEV_BASE[r['severity']]
            topics = r['topics']
            title = r['title']
            text += ' ' + r['title'].lower() + ' ' + ' '.join(topics)
        score, rel = self._score(f, base, topics, text)
        nz = sorted(v for v in f.buckets.values() if v)
        chronic = (f.strong + f.weak) >= 20 and len(nz) >= 0.7 * self.nb and nz[-1] <= 3 * nz[len(nz) // 2]
        if chronic:                     # steady drip across the whole window = background, not the incident
            score *= 0.5 if generic else 0.7
        if not generic and f.strong == 0 and r['severity'] in ('medium', 'low'):
            return None
        return dict(
            id=('gen.' if generic else '') + f.key[:60], title=title, source='logs',
            kind='pattern' if generic else 'rule',
            severity=(f.level_max if generic else r['severity']),
            score=round(score, 1), relevance=round(rel, 1),
            confidence='high' if score >= 65 and not chronic else 'medium' if score >= 40 else 'low',
            chronic=chronic, advisory=bool(not generic and r['any_level']),
            count=f.strong + f.weak, strong=f.strong, weak=f.weak,
            first_seen=fmt_ts(f.first), last_seen=fmt_ts(f.last),
            nearest_to_anchor_s=None if f.nearest >= 1 << 59 else int(f.nearest),
            topics=topics, advice=None if generic else r['advice'],
            kb=None if generic else r['kb'], search=None if generic else r['search'],
            files=[dict(file=k, count=c) for k, c in f.files.most_common(5)],
            variants=[dict(message=k, count=v[0], file=v[1], line=v[2]) for k, v in variants],
            samples=samples,
            spark=[f.buckets.get(i, 0) for i in range(self.nb)],
            _first=f.first or 0)

    def _build(self, reps, cand):
        items, advisories = [], []
        for f in self.findings.values():
            d = self._finding_dict(f)
            if d:
                (advisories if d['advisory'] else items).append(d)
        gen = []
        for f in self.generic.values():
            d = self._finding_dict(f, generic=True)
            if d:
                gen.append(d)
        gen.sort(key=lambda d: -d['score'])
        keep_gen = [g for g in gen if g['severity'] in ('critical', 'error')][:15] + \
                   [g for g in gen if g['severity'] == 'warning'][:10]
        items += keep_gen
        # reports
        report_out, rep_items = [], []
        for rep in reps:
            report_out.append(rep)
            for rf in reports.report_findings(rep):
                if rf['stale']:
                    rf['score'] = 5.0
                else:
                    topics = set(rf['topics'])
                    # map toolbox plugin spaces onto topics
                    sp = {'storage': 'storage', 'host': 'hardware', 'ha': 'ha', 'vsan': 'vsan', 'vm': 'vm'}
                    mapped = {sp.get(t, t) for t in topics}
                    rel = 25 if (mapped & self.topics) else 0
                    rf['score'] = round(SEV_BASE[rf['severity']] + 12 + rel, 1)
                rf['confidence'] = 'low' if rf['stale'] else ('high' if rf['score'] >= 65 else 'medium')
                rep_items.append(rf)
        items.sort(key=lambda d: (-d['score'], d['_first']))
        for d in items:
            d.pop('_first', None)
        # timeline
        tl = []
        for i in range(self.nb):
            c = self.timeline.get(i, Counter())
            tl.append(dict(t=fmt_ts(self.start + i * self.bsize), error=c.get('error', 0) + c.get('critical', 0),
                           warning=c.get('warning', 0)))
        seq = sorted([d for d in items if d['kind'] == 'rule' and d['first_seen']], key=lambda d: d['first_seen'])[:12]
        sequence = [dict(time=d['first_seen'], title=d['title'], id=d['id'], score=d['score']) for d in seq]
        st = dict(self.stats)
        st.setdefault('errors_outside_window', 0)
        st['files_candidate'] = len(cand)
        st['generic_clusters'] = len(self.generic)
        return dict(
            bundle=self.bundle.display, products=self.products,
            issue=self.issue, issue_topics=sorted(self.topics),
            window=dict(start=fmt_ts(self.start), end=fmt_ts(self.end), anchor=fmt_ts(self.anchor),
                        anchor_source=self.anchor_source, before_h=round(self.before_s / 3600, 2),
                        after_h=round(self.after_s / 3600, 2)),
            stats=st, findings=items, advisories=advisories, report_findings=sorted(rep_items, key=lambda d: -d['score']),
            reports=report_out, timeline=dict(bucket_s=int(self.bsize), buckets=tl),
            sequence=sequence, skipped=self.skipped[:50])


def analyze(bundle, **kw):
    return Analyzer(bundle, **kw).run()
