"""Synthetic VMware support-bundle generator with known ground truth (for accuracy testing)."""
import gzip
import io
import os
import random
import shutil
import tarfile
import time
import zipfile
from calendar import timegm

ANCHOR = timegm((2026, 9, 27, 14, 30, 0))
SPAN_DAYS = 14


def iso(ts, ms=123):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts)) + '.%03dZ' % ms


# ------------------------------------------------------------------ noise templates
ESX_NOISE = {
    'var/run/log/vmkernel.log': [
        '{t} cpu{c}:2097{n})NMP: nmp_ResetDeviceLogThrottling:3569: last error status from device naa.600601604d3f4e00 repeated 2 times',
        '{t} cpu{c}:2097{n})vmnic1: NIC Link is Up 10000 Mbps Full Duplex',
        '{t} cpu{c}:2097{n})VSCSIFs: 1232: handle {n}(vscsi0:0):Destroying Device for world {n}',
        '{t} cpu{c}:2097{n})WARNING: VMKAPI: Heartbeat poll took {n} ms (rare)',
        '{t} cpu{c}:2097{n})Config: 681: "SIOControlFlag2" = 0, Old Value: 0, (Status: 0x0)',
    ],
    'var/run/log/hostd.log': [
        '{t} info hostd[2{n}] [Originator@6876 sub=Hostsvc opID=hb-{n}] Heartbeat ok, errors: 0',
        '{t} verbose hostd[2{n}] [Originator@6876 sub=Vimsvc.TaskManager opID=task-{n}] Task Completed successfully',
        '{t} info hostd[2{n}] [Originator@6876 sub=Libs] SOCKET {n} (127.0.0.1:8307) connection successfully established',
        '{t} warning hostd[2{n}] [Originator@6876 sub=Default] Failed to read cached config for plugin {n}',
    ],
    'var/run/log/vpxa.log': [
        '{t} verbose vpxa[2{n}] [Originator@6876 sub=vpxaMoService opID=hb-{n}] heartbeat sent to vpxd seq {n}',
        '{t} info vpxa[2{n}] [Originator@6876 sub=vpxaVmomi opID=WFU-{n}] [VpxaClientAdapter] Retrieved properties successfully',
    ],
    'var/run/log/fdm.log': [
        '{t} info fdm[2{n}] [Originator@6876 sub=Cluster opID=SWI-{n}] Heartbeat datastore ok, master is 10.0.0.{c}',
        '{t} verbose fdm[2{n}] [Originator@6876 sub=Invt opID=SWI-{n}] Invt refresh complete',
    ],
    'var/run/log/vobd.log': [
        '{t}: [UserLevelCorrelator] {n}ms: [esx.audit.net.firewall.config.changed] Firewall configuration has changed.',
        '{t}: [netCorrelator] {n}ms: [vob.net.vmnic.linkstate.up] vmnic0 linkstate up',
    ],
}
VC_NOISE = {
    'var/log/vmware/vpxd/vpxd-1.log': [
        '{t} info vpxd[0{n}] [Originator@6876 sub=vpxLro opID=op-{n}] [VpxLRO] -- BEGIN task-{n} -- vim.PerformanceManager.queryStats',
        '{t} verbose vpxd[0{n}] [Originator@6876 sub=PropertyProvider opID=op-{n}] RecordOp ASSIGN: latestPage, session[{n}]',
        '{t} warning vpxd[0{n}] [Originator@6876 sub=Default opID=op-{n}] Failed to read cached config for plugin {n}',
        '{t} info vpxd[0{n}] [Originator@6876 sub=Default] Operation finished, errors: 0',
    ],
    'var/log/vmware/rhttpproxy/rhttpproxy.log': [
        '{t} info rhttpproxy[0{n}] [Originator@6876 sub=Proxy Req {n}] New proxy client 10.0.0.{c}:{n}',
        '{t} verbose rhttpproxy[0{n}] [Originator@6876 sub=Default] Connection closed successfully',
    ],
    'var/log/vmware/sts/sts-runtime.log': [
        '{t} INFO  [{n}] [sts.audit] Successfully issued token for user svc-{c}@vsphere.local',
        '{t} DEBUG [{n}] [sts.cache] cache refresh complete',
    ],
    'var/log/vmware/vpostgres/postgresql.log': [
        '{t} UTC LOG:  checkpoint complete: wrote {n} buffers (0.{c}%)',
        '{t} UTC LOG:  connection received: host=127.0.0.1 port={n}',
    ],
    'var/log/vmware/vmdird/vmdird-syslog.log': [
        '{t} info vmdird t@{n}: ACL MODE: Legacy',
    ],
}

# ------------------------------------------------------------------ scenarios
# (offset seconds relative to anchor, file, template).  Offsets mostly negative: precursor -> incident.
S = {}


def scn(name, kind, issue, expect, lines, decoy_file=None, anchor_off=0, min_rank=3):
    S[name] = dict(name=name, kind=kind, issue=issue, expect=expect, lines=lines, anchor_off=anchor_off, min_rank=min_rank)


scn('esx_apd', 'esxi', 'Datastore went offline and VMs froze, storage connectivity lost around 14:30', ['esx.apd'], [
    (-1500, 'var/run/log/vmkernel.log', '{t} cpu4:2097180)WARNING: StorageApdHandler: 1203: APD start for 0x430a1b2c3d40 [naa.600601604d3f4e00]'),
    (-1200, 'var/run/log/vmkernel.log', '{t} cpu4:2097180)StorageApdHandler: 1203: APD timeout event for 0x430a1b2c3d40 [naa.600601604d3f4e00]'),
    (-1190, 'var/run/log/hostd.log', '{t} info hostd[2099] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 421 : Lost access to volume 5f3a1c2b-aaaa-bbbb-cccc-0123456789ab (datastore1) due to connectivity issues.'),
    (-1100, 'var/run/log/vmkernel.log', '{t} cpu6:2097181)WARNING: ScsiDeviceIO: 3449: Cmd(0x45d2c0) 0x28, CmdSN 0x1 from world 0 to dev "naa.600601604d3f4e00" failed H:0x5 D:0x0 P:0x0'),
])
scn('esx_psod', 'esxi', 'Host crashed with a purple screen and rebooted', ['esx.psod'], [
    (-400, 'var/run/log/vmkernel.log', '{t} cpu12:2097234)@BlueScreen: #PF Exception 14 in world 2097234:vmm0:vm1 IP 0x4200123 addr 0x18'),
    (-399, 'var/run/log/vmkernel.log', '{t} cpu12:2097234)Code start: 0x420000000000 VMK uptime: 91:04:12:55'),
])
scn('esx_nic', 'esxi', 'Network flapping on host, VMs lose connectivity intermittently, vmnic3', ['esx.nic_down'], [
    (-900, 'var/run/log/vmkernel.log', '{t} cpu5:2097252)WARNING: vmnic3: NIC Link is Down'),
    (-899, 'var/run/log/vobd.log', '{t}: [netCorrelator] 5000ms: [vob.net.vmnic.linkstate.down] vmnic3 linkstate down'),
    (-898, 'var/run/log/vmkernel.log', '{t} cpu5:2097252)WARNING: Lost uplink redundancy on virtual switch "vSwitch0". Physical NIC vmnic3 is down.'),
    (-700, 'var/run/log/vmkernel.log', '{t} cpu5:2097252)WARNING: vmnic3: NIC Link is Down'),
])
scn('esx_nic_hang', 'esxi', 'Intermittent packet loss on 10G NIC', ['esx.nic_hang'], [
    (-600, 'var/run/log/vmkernel.log', '{t} cpu9:2097300)WARNING: i40en: i40en_TxTimeout:341: vmnic2: TX timeout, resetting adapter'),
    (-590, 'var/run/log/vmkernel.log', '{t} cpu9:2097300)WARNING: netdev watchdog: transmit queue 3 timed out'),
])
scn('esx_hostd_vpxa', 'esxi', 'Host shows not responding in vCenter and disconnects', ['esx.vpxa'], [
    (-1800, 'var/run/log/vpxa.log', '{t} error vpxa[2099] [Originator@6876 sub=vpxaMoService] Failed to send heartbeat to vpxd: Operation timed out'),
    (-1500, 'var/run/log/vpxa.log', '{t} error vpxa[2099] [Originator@6876 sub=vpxaMoService] Failed to send heartbeat to vpxd: Operation timed out'),
    (-1200, 'var/run/log/hostd.log', '{t} error hostd[2111] [Originator@6876 sub=Default] Unable to connect to hostd: connection refused'),
])
scn('esx_scsi_latency', 'esxi', 'VMs very slow, storage latency high on datastore', ['esx.latency', 'esx.scsi_sense'], [
    (-2400, 'var/run/log/vmkernel.log', '{t} cpu7:2097200)WARNING: ScsiDeviceIO: 1204: Device naa.600601604d3f4e00 performance has deteriorated. I/O latency increased from average value of 1500 microseconds to 98000 microseconds.'),
    (-2300, 'var/run/log/vmkernel.log', '{t} cpu7:2097200)ScsiDeviceIO: 3449: Cmd(0x45d2c0) 0x2a, CmdSN 0x8a from world 2097500 to dev "naa.600601604d3f4e00" failed H:0x0 D:0x2 P:0x0 Valid sense data: 0x4 0x44 0x0.'),
    (-2200, 'var/run/log/vmkernel.log', '{t} cpu7:2097200)WARNING: ScsiDeviceIO: 3449: Cmd(0x45d2c1) 0x2a, CmdSN 0x8b from world 2097500 to dev "naa.600601604d3f4e00" failed H:0x0 D:0x2 P:0x0 Valid sense data: 0x4 0x44 0x0.'),
], min_rank=4)
scn('esx_ha_isolation', 'esxi', 'HA restarted VMs, host was isolated from the cluster', ['esx.fdm'], [
    (-1300, 'var/run/log/fdm.log', '{t} error fdm[2200] [Originator@6876 sub=Election opID=SWI-1] Host is isolated from the cluster network'),
    (-1290, 'var/run/log/fdm.log', '{t} warning fdm[2200] [Originator@6876 sub=Cluster] network isolation detected, isolation response is none'),
])
scn('esx_vsan', 'esxi', 'vSAN performance problem, congestion, object inaccessible', ['esx.vsan'], [
    (-2000, 'var/run/log/vmkernel.log', '{t} cpu3:2097400)WARNING: LSOM: LSOMCongestion:1450: Throttled: Congestion {n} on disk 52a1'.replace('{n}', '210')),
    (-1900, 'var/run/log/vmkernel.log', '{t} cpu3:2097400)WARNING: DOM: DOMOwner_ObjectInaccessible: object 5e3c-aaaa inaccessible due to failed components'),
])
scn('esx_ramdisk', 'esxi', 'Cannot log in to host, hostd hangs, operations fail', ['esx.ramdisk'], [
    (-900, 'var/run/log/vmkernel.log', '{t} cpu1:2097100)WARNING: VisorFSRam: 706: Cannot extend visorfs file /var/run/log/hostd.log because its ramdisk (root) is full: No space left on device'),
    (-800, 'var/run/log/hostd.log', '{t} error hostd[2111] [Originator@6876 sub=Default] Failed to write file: No space left on device'),
])
scn('esx_ecc', 'esxi', 'Host rebooted unexpectedly, hardware suspected', ['esx.mce'], [
    (-500, 'var/run/log/vmkernel.log', '{t} cpu0:2097050)WARNING: MCE: 1118: cpu0: Machine Check Exception: Uncorrectable ECC memory error in DIMM B3'),
])

scn('vc_503', 'vcenter', 'vCenter UI login fails with no healthy upstream after upgrade', ['vc.503'], [
    (-1200, 'var/log/vmware/rhttpproxy/rhttpproxy.log', '{t} error rhttpproxy[0123] [Originator@6876 sub=Proxy Req 5521] upstream connect error or disconnect/reset before headers, no healthy upstream'),
    (-1190, 'var/log/vmware/rhttpproxy/rhttpproxy.log', '{t} error rhttpproxy[0123] [Originator@6876 sub=Proxy Req 5522] HTTP/1.1" 503 - no healthy upstream'),
    (-1500, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=LSClient] Caught exception while creating LS client adapter: N7Vmacore9ExceptionE'),
], min_rank=3)
scn('vc_db', 'vcenter', 'vCenter is slow and services crash, database errors', ['vc.db'], [
    (-1800, 'var/log/vmware/vpostgres/postgresql.log', '{t} UTC FATAL:  remaining connection slots are reserved for non-replication superuser connections'),
    (-1700, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=Default] ODBC error: (08001) - could not connect to server: Connection refused'),
    (-1650, 'var/log/vmware/vpostgres/postgresql.log', '{t} UTC PANIC:  could not write to file "pg_wal/xlogtemp.1234": No space left on device'),
])
scn('vc_sso', 'vcenter', 'Users cannot log in to the vSphere Client, SSO authentication fails', ['vc.sso'], [
    (-900, 'var/log/vmware/sts/sts-runtime.log', '{t} ERROR [1234] [sts.auth] Authentication failed: Invalid credentials for user admin@vsphere.local'),
    (-880, 'var/log/vmware/sts/sts-runtime.log', '{t} ERROR [1235] [sts.auth] Failed to acquire token: SAML token signature invalid'),
    (-700, 'var/log/vmware/vmdird/vmdird-syslog.log', '{t} error vmdird t@1234: Unable to authenticate user, sso identity source unreachable'),
])
scn('vc_cert', 'vcenter', 'SSL errors, certificate expired, hosts fail to connect', ['esx.cert'], [
    (-1000, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=SoapAdapter] SSL handshake failed: certificate has expired'),
    (-990, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=Default] CERTIFICATE_VERIFY_FAILED for host esx01'),
])
scn('vc_host_disc', 'vcenter', 'ESXi hosts disconnected from vCenter and show not responding', ['vc.host_disc'], [
    (-1500, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=HostCommunication] Host esx01.lab.local is not responding'),
    (-1490, 'var/log/vmware/vpxd/vpxd-1.log', '{t} warning vpxd[05993] [Originator@6876 sub=HostCommunication] Cannot contact host esx01.lab.local'),
])
scn('vc_vpxd_crash', 'vcenter', 'vpxd service keeps crashing and restarting', ['vc.vpxd_crash'], [
    (-800, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=Default] Panic: Assert Failed: "state != NULL" @ bora/vpx/vpxd/inventory.cpp:442'),
    (-799, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=Default] Backtrace:'),
])
scn('vc_oom', 'vcenter', 'Services stopped, appliance out of memory', ['vc.oom_kill'], [
    (-600, 'var/log/messages', '{s} vcenter kernel: Out of memory: Kill process 4411 (java) score 912 or sacrifice child'),
    (-590, 'var/log/messages', '{s} vcenter kernel: java invoked oom-killer: gfp_mask=0x24201ca'),
])
scn('vc_ntp', 'vcenter', 'Token errors and certificate not yet valid, time on appliance is wrong', ['esx.ntp'], [
    (-900, 'var/log/messages', '{s} vcenter ntpd[441]: no server suitable for synchronization found'),
    (-850, 'var/log/messages', '{s} vcenter chronyd[442]: time has jumped forward by 3604 seconds'),
])
scn('vc_ls_client', 'vcenter', 'vpxd fails to start in stage 2 of upgrade', ['vc.ls_client'], [
    (-700, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=LSClient] Caught exception while creating LS client adapter: N7Vmacore9ExceptionE'),
    (-690, 'var/log/vmware/vpxd/vpxd-1.log', '{t} error vpxd[05993] [Originator@6876 sub=LSClient] Caught exception while creating LS client adapter: N7Vmacore9ExceptionE'),
])


def _noise_for(kind):
    return ESX_NOISE if kind == 'esxi' else VC_NOISE


def build_dir(dest, scenario, seed=7, anchor=ANCHOR, decoys=True, step=60):
    """Write an extracted bundle. Returns ground-truth dict."""
    rnd = random.Random(seed)
    sc = S[scenario] if isinstance(scenario, str) else scenario
    noise = _noise_for(sc['kind'])
    files = {}
    start = anchor - SPAN_DAYS * 86400
    end = anchor + 3600
    ts = start
    while ts < end:
        for f, templates in noise.items():
            t = rnd.choice(templates)
            files.setdefault(f, []).append((ts, t.format(t=iso(ts, rnd.randint(0, 999)), c=rnd.randint(0, 15), n=rnd.randint(1000, 9999))))
        ts += step + rnd.randint(-5, 5)

    def add(ts, f, tmpl):
        stamp = iso(ts, rnd.randint(0, 999))
        files.setdefault(f, []).append((ts, tmpl.format(t=stamp, s=time.strftime('%b %d %H:%M:%S', time.gmtime(ts)), n=rnd.randint(1000, 9999))))

    for off, f, tmpl in sc['lines']:
        add(anchor + off, f, tmpl)
        if decoys:                       # same signature 12 days earlier: must be excluded by the window
            add(anchor + off - 12 * 86400, f, tmpl)
    if sc['kind'] == 'vcenter' and 'var/log/messages' not in files:
        files['var/log/messages'] = []
    if 'var/log/messages' in files:
        # year-less syslog noise
        t2 = start
        while t2 < end:
            files['var/log/messages'].append((t2, '%s vcenter systemd[1]: Started Session %d of user root.' % (time.strftime('%b %d %H:%M:%S', time.gmtime(t2)), rnd.randint(1, 999))))
            t2 += 600
    for f, rows in files.items():
        rows.sort(key=lambda r: r[0])
        p = os.path.join(dest, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8', newline='\n') as fh:
            for _ts, ln in rows:
                fh.write(ln + '\n')
    # a rotated gz copy of an older log (must be readable, must not matter)
    first = next(iter(files))
    old = os.path.join(dest, first + '.1.gz')
    with gzip.open(old, 'wt', encoding='utf-8') as g:
        g.write('%s info old rotated line\n' % iso(start - 86400))
    os.makedirs(os.path.join(dest, 'commands'), exist_ok=True)
    with open(os.path.join(dest, 'commands', 'esxcli_storage.txt'), 'w') as fh:
        fh.write('Device  Status\nnaa.1   on\n')
    return dict(expect=sc['expect'], issue=sc['issue'], anchor=anchor + sc['anchor_off'], min_rank=sc['min_rank'])


def pack(src_dir, out_path, fmt, inner_name='bundle'):
    """fmt: zip | tgz | nested (tgz inside zip) | dir"""
    if fmt == 'dir':
        return src_dir
    if fmt == 'zip':
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z:
            for dp, _d, fns in os.walk(src_dir):
                for fn in fns:
                    full = os.path.join(dp, fn)
                    z.write(full, os.path.join(inner_name, os.path.relpath(full, src_dir)))
        return out_path
    if fmt == 'tgz':
        with tarfile.open(out_path, 'w:gz') as t:
            t.add(src_dir, arcname=inner_name)
        return out_path
    if fmt == 'nested':
        inner = out_path + '.inner.tgz'
        with tarfile.open(inner, 'w:gz') as t:
            t.add(src_dir, arcname=inner_name)
        with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as z:
            z.write(inner, 'support/host-%s.tgz' % inner_name)
        os.remove(inner)
        return out_path
    raise ValueError(fmt)
