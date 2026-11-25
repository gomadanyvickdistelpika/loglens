"""Case pack: turns ranked findings into a risk-classified action plan and ready-to-edit drafts.

Adapted from the vmware-case-agent project (evidence-first, no premature root cause, risky changes need approval and a
rollback).  Pure functions over the analysis result; nothing here touches any system."""
import re

DISRUPTIVE = re.compile(r'\b(restart|reboot|power[- ]?(?:off|cycle)|failover|fail over|maintenance mode|evacuate|emergency|'
                        r'xe-toolstack-restart|service-control --(?:stop|start)|shut ?down)\b', re.I)
RISKY = re.compile(r'\b(replace|regenerate|renew|reset|delete|remove|purge|rm\b|vecs-cli|certificate-manager|vCert|fsck|resize|grow|'
                   r'extend|promote|repair|upgrade|patch|update|reconfigure|re-?create|clean all|revert|rollback|detach|unplug|forget)\b', re.I)

STANDARD_SAFE = {
    'esxi': ['esxcli system version get   (exact ESXi build)', 'vmkchdev -l | head; esxcli storage core path list   (paths and state)',
             'less /var/run/log/vmkernel.log   (correlate the cited lines by timestamp)'],
    'vcenter': ['vami_config / appliancesh: `version.get`, `service-control --status --all`', 'df -h   (every /storage/* volume)',
                'Cross-check the same timestamp in vpxd.log, vmon.log and vpostgres'],
    'xcpng': ['xe host-list; xe pool-list   (versions and pool state)', 'df -h; tail -n 200 /var/log/SMlog',
              'xe sr-list params=name-label,physical-size,physical-utilisation'],
    'xo': ['journalctl -u xo-server --since "-2h" --no-pager', 'df -h on the XO appliance and the backup remote'],
}
ROLLBACK = ['Capture current state first: configuration export / snapshot of the appliance, service status, and the exact command history.',
            'Write down the restore step, the owner, the success criterion and an abort threshold BEFORE changing anything.',
            'Prefer a maintenance window; for ESXi/XCP-ng hosts evacuate VMs first; for vCenter take a VM snapshot or file-based backup.']


def classify(step):
    """READ-ONLY | RISKY | DISRUPTIVE for one sentence of advice."""
    if DISRUPTIVE.search(step):
        return 'DISRUPTIVE'
    if RISKY.search(step):
        return 'RISKY'
    return 'READ-ONLY'


ACTION = re.compile(r'^(?:then |first |also )?(?:run|check|compare|verify|review|look|read|confirm|open|find|inspect|collect|grep|use|'
                    r'restart|replace|regenerate|renew|reset|delete|remove|purge|grow|extend|resize|free|move|clean|re-?create|reconfigure|'
                    r're-?stage|take|capture|export|rescan|rotate|promote|update|upgrade|patch|disable|enable|set|add|align|keep|stop|start|'
                    r'only|if |after |before |prefer|do not|compare|read|identify|establish|find|trace|test|ping|validate|make sure|ensure|clear|'
                    r'power|put|evacuate|raise|lower|schedule|contact|escalate|engage|attach|mount|unmount|list|show|see|try|retry)\b', re.I)


def _sentences(text):
    """Split advice into candidate action sentences; descriptive sentences ('A partition is full.') are dropped."""
    parts = re.split(r'(?<=\.)\s+(?=[A-Z`(])|(?<=;)\s+', text or '')
    return [p.strip() for p in parts if len(p.strip()) > 12 and ACTION.match(p.strip())]


def build(res, product=None, version=None):
    fs = [f for f in res.get('findings', []) if f.get('kind') == 'rule' and not f.get('chronic')][:5] or res.get('findings', [])[:3]
    verdicts = res.get('verdicts') or {}
    prods = res.get('products') or []
    plist = [p for p in prods if p in STANDARD_SAFE] or ['vcenter' if product is None else product]
    safe, risky, seen = [], [], set()
    for f in fs:
        for s in _sentences(f.get('advice') or ''):
            if s in seen:
                continue
            seen.add(s)
            kind = classify(s)
            (safe if kind == 'READ-ONLY' else risky).append(dict(finding=f['title'], text=s, risk=kind))
    for p in plist:
        for c in STANDARD_SAFE.get(p, []):
            safe.append(dict(finding='General', text=c, risk='READ-ONLY'))
    w = res.get('window', {})
    missing = []
    if not version:
        missing.append('Exact product, version and build (KBs are build-specific)')
    if w.get('anchor_source') != 'user':
        missing.append('The customer-reported incident time (the analysis anchored on the newest log line instead)')
    if not res.get('issue'):
        missing.append('A one-line description of the symptom and its business impact')
    if len(res.get('stats', {}).get('files_by_product', {}) or {}) <= 1 and res.get('stats', {}).get('files_scanned', 0) < 3:
        missing.append('Correlated logs from other components at the same timestamp (only %s file(s) scanned)' % res.get('stats', {}).get('files_scanned', 0))
    if res.get('skipped'):
        missing.append('%d file(s) were skipped (see Run info) - check they do not hold the evidence' % len(res['skipped']))
    top = fs[0] if fs else None
    confirmed = bool(top and verdicts.get(top['id'], {}).get('v') == 'confirm')
    if confirmed:
        conf = 'high'
    elif top:
        conf = 'medium' if top['confidence'] == 'high' else top['confidence']   # unconfirmed: never claim 'high'
    else:
        conf = 'low'
    names = '; '.join(f['title'] for f in fs[:3]) or 'no significant findings'
    first = top['first_seen'] if top else 'n/a'
    cause = ('Reviewer confirmed against the raw log: %s.' % top['title']) if confirmed else \
            ('Evidence points to: %s. This is a hypothesis; root cause is not yet confirmed.' % names)
    customer = ('Hello,\n\nWe analysed the supplied logs for the window %s to %s. %s The earliest related event is at %s UTC. '
                'We recommend the read-only checks below before any change; no change has been made to your environment.\n\nRegards,\n[Support engineer]'
                % (w.get('start', '?'), w.get('end', '?'), cause, first))
    internal = ('Observed: %d finding(s), top = %s (score %s). Inferred: %s Unverified: %s. KB applicability: product/version %s - verify before citing.'
                % (len(res.get('findings', [])), top['title'] if top else 'none', top['score'] if top else '-', cause,
                   '; '.join(missing) or 'nothing flagged', version or 'unknown'))
    return dict(confidence=conf, safe_checks=safe, risky_checks=risky, rollback=ROLLBACK if risky else [],
                applicability='Product(s): %s; version/build: %s. Validate both against each KB before applying it.' % (', '.join(prods) or 'unknown', version or 'unknown'),
                missing_evidence=missing, customer_draft=customer, internal_note=internal)


def to_markdown(cp):
    L = ['## Action plan and drafts', '', '**Confidence:** %s' % cp['confidence'], '', '### Safe checks (READ-ONLY)']
    L += ['- %s _(%s)_' % (s['text'], s['finding']) for s in cp['safe_checks']] or ['- none']
    L += ['', '### Risky / disruptive steps - APPROVAL REQUIRED']
    L += ['- **%s:** %s _(%s)_' % (s['risk'], s['text'], s['finding']) for s in cp['risky_checks']] or ['- none proposed']
    if cp['rollback']:
        L += ['', '### Rollback plan'] + ['- ' + r for r in cp['rollback']]
    L += ['', '### KB applicability gate', cp['applicability']]
    if cp['missing_evidence']:
        L += ['', '### Missing evidence'] + ['- ' + m for m in cp['missing_evidence']]
    L += ['', '### Customer-ready draft', '```', cp['customer_draft'], '```', '', '### Internal note', cp['internal_note']]
    return '\n'.join(L) + '\n'
