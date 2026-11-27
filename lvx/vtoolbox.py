"""Vates Toolbox: a health check for XCP-ng hosts and Xen Orchestra appliances (the Vates counterpart of the GSS Toolbox).

Input is the *read-only command output* that a support bundle already carries (`<node>/commands/<name>.txt`: df -h, free -m, xe sr-list,
xe pool-list, xe host-list, multipath -ll, chronyc tracking, systemctl is-active, openssl x509 -enddate ...) or that live mode collects over
SSH.  Each module turns that output into an alert level (ok / info / warning / critical), a description, a resolution and the LogLens rule it
relates to (so Vates KB research can be attached).  Nothing here touches any system.

The report can be rendered to a plain-text file (attach it to a ticket) and parsed back: see render() / parse_text()."""
import os
import re
import time
from datetime import datetime, timezone

VERSION = '1.0'
BRAND = 'Vates Toolbox'
ALERT_RANK = {'critical': 3, 'warning': 2, 'info': 1, 'ok': 0}
_UNITS = {'B': 1, 'KIB': 1 << 10, 'MIB': 1 << 20, 'GIB': 1 << 30, 'TIB': 1 << 40, 'PIB': 1 << 50, 'KB': 1000, 'MB': 10 ** 6, 'GB': 10 ** 9, 'TB': 10 ** 12}
_PSEUDO_FS = re.compile(r'^/(?:dev|sys|proc|run|snap|boot/efi)(?:/|$)')
_DF = re.compile(r'(\d{1,3})%\s+(/\S*)\s*$')


def to_bytes(s):
    m = re.match(r'^\s*([\d.]+)\s*([A-Za-z]*)\s*$', s or '')
    if not m:
        return None
    return float(m.group(1)) * _UNITS.get((m.group(2) or 'B').upper(), 1)


def xe_records(text):
    """Parse `xe ... list` output into a list of {key: value} records (a record ends when a key repeats)."""
    out, cur = [], {}
    for ln in (text or '').splitlines():
        m = re.match(r'^\s*([\w-]+)\s*\(\s*\w+\)\s*:\s*(.*)$', ln)
        if not m:
            continue
        k, v = m.group(1), m.group(2).strip()
        if k in cur:
            out.append(cur)
            cur = {}
        cur[k] = v
    if cur:
        out.append(cur)
    return out


def _mod(module, space, alert, description, rule=None, resolution='', details=''):
    return dict(module=module, space=space, alert=alert, description=description, rule=rule, kb=None, resolution=resolution, details=details[:6000], stale=False)


# ------------------------------------------------------------------ the checks: each returns a module dict or None (= not applicable / no data)
def chk_filesystem(raw, ctx):
    t = raw.get('df_-h')
    if t is None:
        return None
    rows = []
    for ln in t.splitlines():
        m = _DF.search(ln)
        if m and not _PSEUDO_FS.match(m.group(2)):
            rows.append((int(m.group(1)), m.group(2), ln.strip()))
    if not rows:
        return _mod('filesystem', 'Host', 'info', 'df output contained no filesystems to evaluate', details=t)
    worst = max(rows)
    xo = ctx['kind'] == 'xo'
    rule = 'xcp.xo_disk_full' if xo else 'xcp.host_disk_full'
    hot = [r for r in rows if r[0] >= 85]
    if worst[0] >= 95:
        return _mod('filesystem', 'Host', 'critical', '%s is %d%% full' % (worst[1], worst[0]), rule,
                    ('Free space before anything else: find what grew (du -xh %s | sort -h | tail), prune old backups/logs, then restart the toolstack/XO service if it stopped. '
                     'A full / or /var/log stops xapi, yum and logging.') % worst[1], '\n'.join(r[2] for r in hot))
    if worst[0] >= 85:
        return _mod('filesystem', 'Host', 'warning', '%s is %d%% full (early warning)' % (worst[1], worst[0]), rule,
                    'Not full yet, but little room is left for logs, updates and snapshots. Find what is growing before it reaches 95%%.', '\n'.join(r[2] for r in hot))
    return _mod('filesystem', 'Host', 'ok', 'all filesystems below 85%% (highest %s at %d%%)' % (worst[1], worst[0]), details='\n'.join(r[2] for r in rows))


def chk_memory(raw, ctx):
    t = raw.get('free_-m')
    if t is None:
        return None
    mem = re.search(r'^Mem:\s+(\d+)\s+(\d+)\s+(\d+)(?:\s+(\d+))?(?:\s+(\d+))?(?:\s+(\d+))?', t, re.M)
    if not mem:
        return None
    total = int(mem.group(1))
    avail = int(mem.group(6)) if mem.group(6) else int(mem.group(3)) + (int(mem.group(5)) if mem.group(5) else 0)
    pct = 100.0 * avail / total if total else 100.0
    sw = re.search(r'^Swap:\s+(\d+)\s+(\d+)', t, re.M)
    swap_pct = 100.0 * int(sw.group(2)) / int(sw.group(1)) if sw and int(sw.group(1)) else 0.0
    desc = '%d MiB available of %d MiB (%.0f%%), swap %.0f%% used' % (avail, total, pct, swap_pct)
    if ctx['kind'] == 'xo':
        rule = None
    else:
        rule = 'xcp.dom0_oom'
    if pct < 5 or swap_pct > 90:
        return _mod('memory', 'Host', 'critical', desc, rule, 'Memory is exhausted: the kernel OOM-killer may kill xapi or storage processes. Raise dom0 memory (/opt/xensource/libexec/xen-cmdline --set-xen dom0_mem=<size>M,max:<size>M) and reboot in a maintenance window; find the process that is growing (ps aux --sort=-rss | head).', t)
    if pct < 10 or swap_pct > 50:
        return _mod('memory', 'Host', 'warning', desc, rule, 'Memory pressure: check which process grows (ps aux --sort=-rss | head) and whether dom0 memory is sized for the number of VMs and SRs.', t)
    return _mod('memory', 'Host', 'ok', desc, details=t)


def chk_sr_space(raw, ctx):
    t = raw.get('xe_sr-list')
    if t is None:
        return None
    rows = []
    for r in xe_records(t):
        used, size = to_bytes(r.get('physical-utilisation')), to_bytes(r.get('physical-size'))
        if used is not None and size:
            rows.append((100.0 * used / size, r.get('name-label', '?'), r.get('physical-utilisation'), r.get('physical-size')))
    if not rows:
        return _mod('sr_space', 'Storage', 'info', 'no SR with a size in xe sr-list output', details=t)
    worst = max(rows)
    det = '\n'.join('%-24s %5.1f%%  (%s of %s)' % (n, p, u, s) for p, n, u, s in sorted(rows, reverse=True))
    if worst[0] >= 95:
        return _mod('sr_space', 'Storage', 'critical', 'SR "%s" is %.0f%% full' % (worst[1], worst[0]), 'xcp.sr_full',
                    'Coalesce and new snapshots need free space: a full SR stops VM starts and backups. Move VMs/disks to another SR, delete old snapshots, keep ~30% free on thick-provisioned LVM SRs.', det)
    if worst[0] >= 85:
        return _mod('sr_space', 'Storage', 'warning', 'SR "%s" is %.0f%% full (early warning)' % (worst[1], worst[0]), 'xcp.sr_full',
                    'Plan capacity now: snapshots and delta backups grow the SR; keep roughly 30% free so coalesce can run.', det)
    return _mod('sr_space', 'Storage', 'ok', 'all SRs below 85%% (highest "%s" at %.0f%%)' % (worst[1], worst[0]), details=det)


def chk_ha(raw, ctx):
    t = raw.get('xe_pool-list')
    if t is None:
        return None
    pools = xe_records(t)
    if not pools:
        return None
    p = pools[0]
    if (p.get('ha-enabled') or '').lower() != 'true':
        return _mod('ha_config', 'HA', 'info', 'HA is not enabled on pool %s' % p.get('name-label', '?'), details=t)
    n = ctx['pool_hosts']
    if n and n < 3:
        return _mod('ha_config', 'HA', 'warning', 'HA is enabled on a pool with only %d host(s)' % n, 'xcp.ha_fence',
                    'HA needs a majority to keep running: with 2 hosts a heartbeat or network failure can fence a healthy host, and the pool cannot tolerate a host failure while HA reserves capacity. Use 3+ hosts, redundant bonded management/heartbeat networks and a dedicated heartbeat SR.', t)
    return _mod('ha_config', 'HA', 'ok', 'HA is enabled on pool %s (%s hosts)' % (p.get('name-label', '?'), n or '?'), details=t)


def chk_versions(raw, ctx):
    vs = ctx['pool_versions']
    if len(vs) < 2:
        return None
    if len(set(vs.values())) > 1:
        det = '\n'.join('%s: %s' % kv for kv in sorted(vs.items()))
        return _mod('version_consistency', 'Host', 'warning', 'hosts in the pool run different XCP-ng versions (%s)' % ', '.join(sorted(set(vs.values()))), 'xcp.update_fail',
                    'A pool should run one version: finish the rolling pool update (XO: Pool > Patches > Rolling update) before adding load; mixed versions limit live migration.', det)
    return _mod('version_consistency', 'Host', 'ok', 'all hosts run XCP-ng %s' % next(iter(vs.values())), details='\n'.join('%s: %s' % kv for kv in sorted(vs.items())))


def chk_multipath(raw, ctx):
    t = raw.get('multipath_-ll')
    if t is None or not t.strip():
        return None
    bad = [ln.strip() for ln in t.splitlines() if re.search(r'\b(failed|faulty|offline|shaky)\b', ln, re.I)]
    maps = len(re.findall(r'^\S+\s+\(?\S+\)?\s*dm-\d+|^\S+ dm-\d+', t, re.M))
    if not maps and not bad:
        return None                                                          # no multipath maps (or the command is not installed)
    ready = len(re.findall(r'active\s+ready|ready\s+running', t))
    if bad:
        return _mod('multipath', 'Storage', 'critical', '%d failed/faulty path(s) in multipath -ll' % len(bad), 'xcp.multipath_fail',
                    'Check the fabric (cable, switch, HBA, target port) and the array; paths that stay failed leave the SR on a single path. Do not rescan the SR until paths are back.', '\n'.join(bad) + '\n\n' + t)
    if maps and ready < 2 * maps:
        return _mod('multipath', 'Storage', 'warning', '%d active path(s) for %d multipath map(s): some map has a single path' % (ready, maps), 'xcp.multipath_fail',
                    'A map with one path has no redundancy. Verify both fabrics are cabled and zoned.', t)
    return _mod('multipath', 'Storage', 'ok', '%d multipath map(s), all paths active' % maps, details=t)


def chk_time(raw, ctx):
    t = raw.get('chronyc_tracking')
    if t is None or not re.search(r'Leap status|System time', t):          # chronyc missing / not running: no verdict
        return None
    if re.search(r'Leap status\s*:\s*Not synchroni[sz]ed|Reference ID\s*:\s*0{8}', t, re.I):
        return _mod('time_sync', 'Host', 'critical', 'host clock is not synchronised', None,
                    'Fix NTP before anything else: skewed clocks break TLS, HA heartbeats and pool joins. Check chronyd/ntpd, firewall to the time source, and that the time source is reachable.', t)
    m = re.search(r'System time\s*:\s*([\d.]+) seconds (fast|slow)', t)
    if m and float(m.group(1)) > 1.0:
        return _mod('time_sync', 'Host', 'warning', 'clock is %.2f s %s of NTP time' % (float(m.group(1)), m.group(2)), None, 'Check chrony sources (chronyc sources -v); a large offset usually means the source is unreachable.', t)
    return _mod('time_sync', 'Host', 'ok', 'clock synchronised', details=t)


def chk_toolstack(raw, ctx):
    for name, svc in (('systemctl_is-active_xapi', 'xapi'), ('systemctl_is-active_xo-server', 'xo-server')):
        t = raw.get(name)
        if t is None:
            continue
        state = t.strip().splitlines()[0].strip() if t.strip() else 'unknown'
        if state not in ('active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'):
            continue                                                         # systemctl missing / error text: no verdict
        if state != 'active':
            return _mod('toolstack', 'Services', 'critical', '%s service is %s' % (svc, state), 'xcp.xapi_down' if svc == 'xapi' else None,
                        'Read the journal (journalctl -u %s -n 200) and the disk/memory modules first: a full disk or OOM is the usual cause. xe-toolstack-restart does not touch running VMs.' % svc, t)
        return _mod('toolstack', 'Services', 'ok', '%s is active' % svc, details=t)
    return None


def chk_certificate(raw, ctx):
    t = raw.get('openssl_x509_enddate')
    if t is None:
        return None
    m = re.search(r'notAfter=(\w{3})\s+(\d{1,2})\s+([\d:]+)\s+(\d{4})', t)
    if not m:
        return None
    try:
        end = datetime.strptime('%s %s %s %s' % (m.group(1), m.group(2), m.group(3), m.group(4)), '%b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None
    days = int((end - ctx['ref']) // 86400)
    rule = 'xcp.xo_tls' if ctx['kind'] == 'xo' else None
    if days < 0:
        return _mod('certificate', 'Security', 'critical', 'TLS certificate expired %d day(s) ago' % -days, rule,
                    'Renew the certificate (XCP-ng: replace the host TLS certificate or use the certificate refresh command for your release; XO: install a valid certificate), then restart the toolstack in a maintenance window.', t)
    if days < 14:
        return _mod('certificate', 'Security', 'critical', 'TLS certificate expires in %d day(s)' % days, rule, 'Renew before it expires: clients, XO and pool joins stop trusting the host when it does.', t)
    if days < 30:
        return _mod('certificate', 'Security', 'warning', 'TLS certificate expires in %d day(s)' % days, rule, 'Schedule the renewal.', t)
    return _mod('certificate', 'Security', 'ok', 'TLS certificate valid for %d more days' % days, details=t)


CHECKS = [chk_filesystem, chk_memory, chk_sr_space, chk_ha, chk_versions, chk_multipath, chk_time, chk_toolstack, chk_certificate]


# ------------------------------------------------------------------ collecting nodes from a bundle
def collect_nodes(bundle, files):
    """{node_dir: {command_name: text}} for every `commands/<name>.txt` in the bundle."""
    nodes = {}
    for e in files:
        parts = e['path'].replace('\\', '/').split('/')
        if len(parts) >= 2 and parts[-2] == 'commands' and parts[-1].endswith('.txt') and e.get('size', 0) < 2_000_000:
            node = '/'.join(parts[:-2])
            try:
                with open(bundle.resolve(e['path']), 'r', encoding='utf-8', errors='replace') as f:
                    nodes.setdefault(node, {})[parts[-1][:-4]] = f.read()
            except OSError:
                continue
    return nodes


def _kind(node, raw):
    if 'xe_sr-list' in raw or 'xe_host-list' in raw or 'xe_pool-list' in raw or 'systemctl_is-active_xapi' in raw or 'multipath_-ll' in raw:
        return 'xcpng'
    if re.search(r'xoa|xo-|orchestra|xo_server', node, re.I) or 'systemctl_is-active_xo-server' in raw:
        return 'xo'
    return None


def evaluate(node, raw, ctx_extra=None, ref=None):  # pool-wide checks (sr_space, ha, versions) run only when ctx primary=True
    kind = _kind(node, raw)
    if not kind:
        return None
    ctx = dict(kind=kind, ref=ref or time.time(), pool_hosts=0, pool_versions={}, primary=True)
    ctx.update(ctx_extra or {})
    mods = []
    for fn in CHECKS:
        if not ctx['primary'] and fn.__name__[4:] in ('sr_space', 'ha', 'versions'):
            continue
        try:
            m = fn(raw, ctx)
        except Exception as ex:                      # one odd command output must never break the report
            m = _mod(fn.__name__[4:], 'Host', 'info', 'check could not parse its input (%s)' % ex)
        if m:
            mods.append(m)
    host = os.path.basename(node.rstrip('/')) or 'host'
    hl = xe_records(raw.get('xe_host-list', ''))
    ver = ''
    for r in hl:
        mm = re.search(r'product_version:\s*([\w.]+)', r.get('software-version', ''))
        if mm:
            ver = mm.group(1)
            break
    up = (raw.get('uptime') or '').strip()
    meta = dict(hostname=host, product='XCP-ng' if kind == 'xcpng' else 'Xen Orchestra', version=ver, uptime=up[:120],
                log_date=time.strftime('%Y-%m-%d', time.gmtime(ctx['ref'])), plugins_run=len(mods),
                plugins_matched=sum(1 for m in mods if ALERT_RANK[m['alert']] >= 2), toolbox_version=VERSION)
    return dict(kind='vtoolbox', brand=BRAND, meta=meta, modules=mods, file='%s (commands)' % host, node=node)


def from_bundle(bundle, files, ref=None):
    """One report per XCP-ng host / XO appliance found in the bundle (pool-level checks use all hosts' outputs)."""
    nodes = collect_nodes(bundle, files)
    hosts = {n: r for n, r in nodes.items() if _kind(n, r) == 'xcpng'}
    pool_hosts, versions = 0, {}
    for n, r in hosts.items():
        names = {x.get('name-label') for x in xe_records(r.get('xe_host-list', '')) if x.get('name-label')}
        pool_hosts = max(pool_hosts, len(names) or 0)
        for x in xe_records(r.get('xe_host-list', '')):
            mm = re.search(r'product_version:\s*([\w.]+)', x.get('software-version', ''))
            if mm and x.get('name-label'):
                versions[x['name-label']] = mm.group(1)
    if not pool_hosts:
        pool_hosts = len(hosts)
    out = []
    first_host = True                                   # pool-wide output (xe sr-list / pool-list / host-list) is reported once, on the first host
    for n in sorted(nodes):
        is_host = n in hosts
        rep = evaluate(n, nodes[n], dict(pool_hosts=pool_hosts, pool_versions=versions, primary=first_host or not is_host), ref)
        if rep:
            out.append(rep)
            first_host = first_host and not is_host
    return out


# ------------------------------------------------------------------ text report: render + parse (so it can be attached to a ticket and re-imported)
def render(rep):
    m = rep['meta']
    L = ['##Vates Toolbox Begin', 'Vates Toolbox Version: %s' % m.get('toolbox_version', VERSION), 'Hostname: %s' % m.get('hostname', ''),
         'Product: %s  Version: %s' % (m.get('product', ''), m.get('version', '')), 'Uptime: %s' % m.get('uptime', ''), 'Log Date: %s' % m.get('log_date', ''),
         'Plugins Run %d. Matched: %d' % (m.get('plugins_run', 0), m.get('plugins_matched', 0)), '']
    for x in rep['modules']:
        L += ['Matched Module: %s' % x['module'], ' Alert Level: %s' % x['alert'].capitalize(), ' Plugin Space: %s' % x['space'], ' Description: %s' % x['description'],
              ' Rule: %s' % (x.get('rule') or ''), ' Resolution:']
        L += ['   ' + ln for ln in (x['resolution'] or '-').splitlines()]
        L += [' Investigation Details:'] + ['   ' + ln for ln in (x['details'] or '-').splitlines()] + ['']
    L.append('##Vates Toolbox End')
    return '\n'.join(L) + '\n'


def sniff(text):
    return '##Vates Toolbox Begin' in text[:2000]


def parse_text(text):
    meta = {}
    for key, rx in (('toolbox_version', r'Vates Toolbox Version:\s*(.+)'), ('hostname', r'Hostname:\s*(.+)'), ('uptime', r'Uptime:[ \t]*(.*)'), ('log_date', r'Log Date:\s*(\S+)')):
        mm = re.search(rx, text)
        if mm:
            meta[key] = mm.group(1).strip()
    mm = re.search(r'Product:\s*(.+?)\s+Version:\s*(.*)', text)
    if mm:
        meta['product'], meta['version'] = mm.group(1).strip(), mm.group(2).strip()
    mm = re.search(r'Plugins Run (\d+)\. Matched: (\d+)', text)
    if mm:
        meta['plugins_run'], meta['plugins_matched'] = int(mm.group(1)), int(mm.group(2))
    mods = []
    for part in re.split(r'^Matched Module:\s*', text, flags=re.M)[1:]:
        lines = part.split('\n')
        body = '\n'.join(lines[1:])
        g = lambda k: (re.search(r'^[ \t]*%s:[ \t]*(.*)$' % k, body, re.M) or [None, ''])[1].strip()      # [ \t], not \s: an empty value must not swallow the next line
        res = re.search(r'Resolution:\s*\n(.*?)\n Investigation Details:', body, re.S)
        det = re.search(r'Investigation Details:\s*\n(.*?)(?:\n##Vates Toolbox End|\Z)', body, re.S)
        un = lambda s: '\n'.join(x[3:] if x.startswith('   ') else x for x in (s or '').splitlines()).strip('-\n ')
        mods.append(dict(module=lines[0].strip(), space=g('Plugin Space'), alert=(g('Alert Level') or 'ok').lower(), description=g('Description'),
                         rule=g('Rule') or None, kb=None, resolution=un(res.group(1) if res else ''), details=un(det.group(1) if det else ''), stale=False))
    return dict(kind='vtoolbox', brand=BRAND, meta=meta, modules=mods)


def report_findings(rep):
    out = []
    for m in rep['modules']:
        if ALERT_RANK.get(m['alert'], 0) < 2:
            continue
        out.append(dict(source=BRAND, id='vtb.%s.%s' % (rep.get('meta', {}).get('hostname', 'host'), m['module']),
                        title='%s: %s' % (m['module'], m['description']), severity='high' if m['alert'] == 'critical' else 'medium',
                        topics=[(m['space'] or '').lower()], kb=None, rule=m.get('rule'), advice=m['resolution'], stale=False, detail=m['details'][:1500],
                        host=rep.get('meta', {}).get('hostname')))
    return out
