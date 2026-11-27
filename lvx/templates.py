"""Anonymised case templates: loader, synthetic-bundle builder.

A template is a resolved-support-case pattern (symptom, synthetic log excerpt, expected detections, documented cause,
resolution and the KB links the case cited).  Everything is invented/anonymised - see tools/build_case_templates.py.
`build_bundle` writes a synthetic support bundle (background noise + the template's planted lines) for testing/training."""
import json
import os
import random
import tarfile
import time
from calendar import timegm

from . import packs

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'case_templates.json')
_PATH_VATES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'case_templates_vates.json')
ANCHOR = timegm((2026, 3, 10, 10, 0, 0))     # incident time used by every template bundle
_cache = None

_ESX_NOISE = {
    'var/run/log/vmkernel.log': ['{t} cpu{c}:2097{n})NMP: nmp_ResetDeviceLogThrottling:3569: last error status from device naa.600601604d3f4e00 repeated 2 times',
                                 '{t} cpu{c}:2097{n})vmnic1: NIC Link is Up 10000 Mbps Full Duplex', '{t} cpu{c}:2097{n})Config: 681: "SIOControlFlag2" = 0, Old Value: 0, (Status: 0x0)'],
    'var/run/log/hostd.log': ['{t} info hostd[2{n}] [Originator@6876 sub=Hostsvc opID=hb-{n}] Heartbeat ok, errors: 0', '{t} verbose hostd[2{n}] [Originator@6876 sub=Vimsvc.TaskManager opID=task-{n}] Task Completed successfully'],
    'var/run/log/vpxa.log': ['{t} verbose vpxa[2{n}] [Originator@6876 sub=vpxaMoService opID=hb-{n}] heartbeat sent to vpxd seq {n}'],
}
_VC_NOISE = {
    'var/log/vmware/vpxd/vpxd-1.log': ['{t} info vpxd[0{n}] [Originator@6876 sub=vpxLro opID=op-{n}] [VpxLRO] -- BEGIN task-{n} -- vim.PerformanceManager.queryStats',
                                      '{t} warning vpxd[0{n}] [Originator@6876 sub=Default opID=op-{n}] Failed to read cached config for plugin {n}'],
    'var/log/vmware/rhttpproxy/rhttpproxy.log': ['{t} info rhttpproxy[0{n}] [Originator@6876 sub=Proxy Req {n}] New proxy client 192.0.2.{c}:{n}'],
    'var/log/vmware/sts/sts-runtime.log': ['{t} INFO  [{n}] [sts.audit] Successfully issued token for user svc-{c}@vsphere.local'],
    'var/log/vmware/vpostgres/postgresql.log': ['{t} UTC LOG:  checkpoint complete: wrote {n} buffers (0.{c}%)'],
}


_XCP_NOISE = {
    'var/log/xensource.log': ['{s} xcp01 xapi: [ info|xcp01.lab.example|{n} ||xapi] Event.next completed in 12ms',
                              '{s} xcp01 xenopsd-xc: [debug|xcp01.lab.example|{n} ||xenops] VM {n} state is running',
                              '{s} xcp01 xapi: [ info|xcp01.lab.example|{n} ||pool_db_sync] sync completed'],
    'var/log/SMlog': ['{s} xcp01 SM: [{n}] lock: opening lock file /var/lock/sm/{n}/sr',
                      '{s} xcp01 SMGC: [{n}] Running garbage collector for SR check, nothing to do',
                      '{s} xcp01 SM: [{n}] sr_scan completed'],
    'var/log/daemon.log': ['{s} xcp01 stunnel: LOG5[{n}]: Service [xapi] accepted connection from 192.0.2.{c}'],
}
_XO_NOISE = {
    'xo/journalctl-xo-server.txt': ['{s} xo01 xo-server[771]: {u} xo:main INFO http://[::]:80 listening',
                                    '{s} xo01 xo-server[771]: {u} xo:xo-server INFO new client connected ({n})',
                                    '{s} xo01 xo-server[771]: {u} xo:api INFO xapi event loop ok'],
}


def _load():
    """Combined template set: the VMware case templates plus (when the Vates pack is enabled) the XCP-ng / Xen Orchestra scenarios."""
    global _cache
    if _cache is None:
        d = None
        if packs.enabled('vmware'):
            with open(_PATH, encoding='utf-8') as f:
                d = json.load(f)
        if packs.enabled('vates'):
            with open(_PATH_VATES, encoding='utf-8') as f:
                v = json.load(f)
            if d is None:
                d = v
            else:
                d = dict(d, templates=d['templates'] + v['templates'], source=d['source'] + ' + ' + v['source'])
        _cache = d
    return _cache


def all_templates():
    return _load()['templates']


def get(tid):
    for t in all_templates():
        if t['id'].lower() == str(tid).lower():
            return t
    raise KeyError('unknown template %s' % tid)


def info():
    d = _load()
    return dict(count=len(d['templates']), reviewed_cases=d.get('reviewed_cases'), source=d['source'])


def _iso(ts, ms):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts)) + '.%03dZ' % ms


def _fmt(tmpl, ts, rnd):
    """Substitute only the known placeholders; any other braces in the log text are left alone."""
    iso = _iso(ts, rnd.randint(0, 999))
    for k, v in (('{t}', iso), ('{u}', iso[:-1]), ('{s}', time.strftime('%b %d %H:%M:%S', time.gmtime(ts))),
                 ('{n}', str(rnd.randint(1000, 9999))), ('{c}', str(rnd.randint(0, 15)))):
        tmpl = tmpl.replace(k, v)
    return tmpl


def build_bundle(template, out_dir, days=3, step=120, seed=11, anchor=ANCHOR):
    """Write an extracted synthetic bundle into out_dir. Returns dict(issue, anchor, path)."""
    t = get(template) if isinstance(template, str) else template
    if not t.get('bundle'):
        raise ValueError('template %s has no log evidence (no bundle)' % t['id'])
    rnd = random.Random(seed)
    noise = {}
    if t['product'] in ('esxi', 'both'):
        noise.update(_ESX_NOISE)
    if t['product'] in ('vcenter', 'sddc', 'both'):
        noise.update(_VC_NOISE)
    if t['product'] == 'guest':
        noise.update(_ESX_NOISE)
    if t['product'] in ('xcpng', 'vates'):
        noise.update(_XCP_NOISE)
    if t['product'] in ('xo', 'vates'):
        noise.update(_XO_NOISE)
    files = {}
    ts = anchor - days * 86400
    end = anchor + 3600
    while ts < end:
        for f, tm in noise.items():
            files.setdefault(f, []).append((ts, _fmt(rnd.choice(tm), ts, rnd)))
        ts += step + rnd.randint(-5, 5)
    for off, f, tm, _basis in t['lines']:
        files.setdefault(f, []).append((anchor + off, _fmt(tm, anchor + off, rnd)))
    for f, rows in files.items():
        rows.sort(key=lambda r: r[0])
        p = os.path.join(out_dir, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8', newline='\n') as fh:
            for _ts, ln in rows:
                fh.write(ln + '\n')
    for f, content in t.get('extra_files', {}).items():
        p = os.path.join(out_dir, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(content)
    return dict(issue=t['issue'], anchor=anchor, path=out_dir)


def pack_tgz(src_dir, out_path, inner='bundle'):
    with tarfile.open(out_path, 'w:gz') as tf:
        tf.add(src_dir, arcname=inner)
    return out_path


def pack_templates(pack):
    """Templates belonging to one rule pack ('vmware' or 'vates')."""
    return [t for t in all_templates() if packs.group(t['product']) == pack]
