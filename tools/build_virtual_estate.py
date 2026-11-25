#!/usr/bin/env python3
"""Virtual client estate: full-size, believable support bundles for an XCP-ng pool + Xen Orchestra, each with ONE planted fault.

Fictional client "Brightwater Logistics Ltd": 2 XCP-ng hosts (xcp-dub-01 pool master, xcp-dub-02), 1 Xen Orchestra appliance (xoa-dub-01),
an iSCSI SAN, an NFS NAS, 6 VMs.  Every address is in a documentation range (192.0.2.0/24, 198.51.100.0/24) and every name ends in .example:
nothing here is real customer data.

    python tools/build_virtual_estate.py OUT_DIR            # writes OUT_DIR/BW-01-....tgz  (+ CASES.md)
    python tools/build_virtual_estate.py OUT_DIR BW-03      # one case

Each bundle holds, per host: var/log/{xensource.log,SMlog,daemon.log,kern.log,messages,xha.log,audit.log,yum.log}, xen/hypervisor.log and
commands/{df_-h,free_-m,uptime,xe_*,multipath_-ll,ip_-br_addr}.txt; for the orchestrator: xo/journalctl-xo-server.txt, xo/xoa-updater.log,
var/log/syslog, commands/{df_-h,free_-m,uptime}.txt; plus NOTES.txt (the customer's ticket).  Two days of normal traffic surround the fault."""
import io
import os
import random
import sys
import tarfile
import time
from calendar import timegm

CLIENT = 'Brightwater Logistics Ltd (fictional)'
H1, H2, XOA = 'xcp-dub-01', 'xcp-dub-02', 'xoa-dub-01'
IP = {H1: '192.0.2.11', H2: '192.0.2.12', XOA: '192.0.2.20'}
NAS, SAN = 'nas01.brightwater.example', 'san01.brightwater.example'
VMS = [('erp-db01', H1), ('erp-app01', H1), ('dc01', H1), ('web-fe01', H2), ('fs01', H2), ('bkp-proxy01', H2)]
SR_ISCSI, SR_NFS, SR_LOCAL = '3b5c1f00-aa11-4b22-8c33-dd44ee55ff66', '7d2e9a10-5c4b-4e3a-9f01-2b6c8d4e7a90', '0f1e2d3c-4b5a-4697-8a9b-c0d1e2f30415'
SR_NAMES = {SR_ISCSI: 'iSCSI-SAN01-LUN3', SR_NFS: 'NFS-NAS01-VMs', SR_LOCAL: 'Local-SSD-01'}
BUILD = '8.2.1'


def stamp(ts):
    t = time.gmtime(ts)
    return '%s %2d %s' % (time.strftime('%b', t), t.tm_mday, time.strftime('%H:%M:%S', t))


def iso(ts, rnd):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts)) + '.%03dZ' % rnd.randint(0, 999)


class Estate:
    def __init__(self, bid, incident, seed):
        self.bid, self.T, self.rnd = bid, incident, random.Random(seed)
        self.files = {}          # (node, relpath) -> [(ts, line)]
        self.cmds = {}           # (node, name) -> text
        self.start, self.end = incident - 30 * 3600, incident + 4 * 3600
        self.pid = lambda: self.rnd.randint(1200, 31000)

    def log(self, node, rel, ts, text):
        self.files.setdefault((node, rel), []).append((ts, '%s %s %s' % (stamp(ts), node, text)))

    def raw(self, node, rel, ts, line):
        self.files.setdefault((node, rel), []).append((ts, line))

    # ---- normal life of the estate
    def background(self):
        r = self.rnd
        for h in (H1, H2):
            ts = self.start
            n = 0
            while ts < self.end:
                n += 1
                self.log(h, 'var/log/xensource.log', ts, 'xapi: [ info|%s|%d |session.login_with_password D:%08x|xapi] Session.create trackid=%08x pool=false uname=root originator=xen-orchestra is_local_superuser=true' % (h, r.randint(100, 9000), r.getrandbits(32), r.getrandbits(32)))
                self.log(h, 'var/log/xensource.log', ts + 3, 'xapi: [debug|%s|%d |Async.VM.snapshot_with_quiesce R:%08x|audit] ' % (h, r.randint(100, 9000), r.getrandbits(32)) if r.random() < .02 else 'xenopsd-xc: [debug|%s|%d ||xenops] Event on VM %s; resident_here = true' % (h, r.randint(100, 9000), r.choice(VMS)[0]))
                self.log(h, 'var/log/SMlog', ts + 5, 'SM: [%d] lock: acquired /var/lock/sm/%s/sr' % (self.pid(), r.choice((SR_ISCSI, SR_NFS, SR_LOCAL))))
                if n % 3 == 0:
                    self.log(h, 'var/log/SMlog', ts + 9, 'SM: [%d] sr_scan {\'sr_uuid\': \'%s\', \'subtask_of\': \'DummyRef:|Async.SR.scan\'}' % (self.pid(), r.choice((SR_ISCSI, SR_NFS))))
                    self.log(h, 'var/log/SMlog', ts + 10, 'SMGC: [%d] Running garbage collector for SR %s: nothing to do' % (self.pid(), r.choice((SR_ISCSI, SR_NFS))))
                if n % 4 == 0:
                    self.log(h, 'var/log/daemon.log', ts + 2, 'stunnel: LOG5[%d:140%d]: Service [xapi] accepted connection from %s:%d' % (self.pid(), r.randint(100, 999), IP[XOA], r.randint(40000, 60000)))
                if n % 5 == 0:
                    self.log(h, 'var/log/messages', ts + 4, 'rsyslogd: -- MARK --')
                    self.log(h, 'var/log/messages', ts + 6, 'CRON[%d]: (root) CMD (/opt/xensource/libexec/xapi-health-check)' % self.pid())
                if n % 7 == 0:
                    self.log(h, 'var/log/kern.log', ts + 1, 'kernel: [%d.%06d] vif%d.0: Guest Rx ready' % (r.randint(100000, 900000), r.randint(0, 999999), r.randint(1, 9)))
                    self.log(h, 'var/log/xha.log', ts + 1, 'xhad: [ info] heartbeat ok on all %d interfaces, statefile slot %d updated' % (2, 0 if h == H1 else 1))
                if n % 11 == 0:                                        # chronic, harmless warning (must be demoted as background noise)
                    self.log(h, 'var/log/xensource.log', ts + 7, 'xapi: [ warn|%s|%d |rrdd_proxy|xapi] RRD update for %s took 1.%ds (slow)' % (h, r.randint(100, 9000), r.choice(VMS)[0], r.randint(2, 9)))
                if n % 20 == 0:
                    self.log(h, 'var/log/audit.log', ts + 1, 'auditd: type=USER_LOGIN msg=audit(%d.%03d:%d): pid=%d uid=0 auid=0 res=success' % (ts, r.randint(0, 999), r.randint(100, 9999), self.pid()))
                ts += 110 + r.randint(-25, 25)
        ts = self.start
        while ts < self.end:
            self.raw(XOA, 'xo/journalctl-xo-server.txt', ts, '%s %s xo-server[772]: %s xo:main INFO new client connected (%s)' % (stamp(ts), XOA, iso(ts, r).replace('Z', 'Z'), IP[XOA]))
            self.raw(XOA, 'xo/journalctl-xo-server.txt', ts + 2, '%s %s xo-server[772]: %s xo:xapi DEBUG xapi event loop ok (%s)' % (stamp(ts + 2), XOA, iso(ts + 2, r), r.choice((H1, H2))))
            self.raw(XOA, 'var/log/syslog', ts + 3, '%s %s CRON[%d]: (xo) CMD (/usr/local/bin/xo-health)' % (stamp(ts + 3), XOA, self.pid()))
            ts += 240 + r.randint(-40, 40)
        for day in range(-1, 3):                                       # nightly backup job succeeds every night
            ts = timegm(time.gmtime(self.T - 12 * 3600)[:3] + (1, 0, 0)) + day * 86400
            if self.start < ts < self.end:
                self.raw(XOA, 'xo/journalctl-xo-server.txt', ts, '%s %s xo-server[772]: %s xo:backups:worker INFO job "nightly-prod" completed: 6/6 VMs backed up, 0 failed' % (stamp(ts), XOA, iso(ts, r)))
        for k in range(2):                                              # a transient disk error ~28 h before the incident: outside the window, a precursor for VTLog
            self.log(H2, 'var/log/kern.log', self.start + 2 * 3600 + k * 30, 'kernel: [3302210.%06d] Buffer I/O error on dev sdc, logical block 1180, async page read' % (114477 + k))
        self.log(XOA, 'xo/xoa-updater.log', self.start + 600, 'xoa-updater: INFO channel stable: xen-orchestra 5.%d is up to date' % 92)
        for h in (H1, H2):
            self.log(h, 'var/log/yum.log', self.start - 86400 * 9, 'Updated: xapi-core-%s-1.xcpng8.2.x86_64' % BUILD)
            self.raw(h, 'xen/hypervisor.log', self.start + 30, '(XEN) Xen version 4.13.5-9.40.2 (mockbuild@xcp-ng.org) debug=n')
        self.default_commands()

    def default_commands(self):
        T = self.T
        for h in (H1, H2):
            self.cmds[(h, 'df_-h')] = ('Filesystem      Size  Used Avail Use% Mounted on\n/dev/md127       18G  6.1G   11G  36% /\n'
                                       '/dev/sda5       3.9G  1.2G  2.5G  33% /var/log\ntmpfs           3.2G     0  3.2G   0% /dev/shm\n')
            self.cmds[(h, 'free_-m')] = '              total        used        free      shared  buff/cache   available\nMem:           4096        1544         410          20        2141        2344\nSwap:          1023           0        1023\n'
            self.cmds[(h, 'uptime')] = ' %s up 41 days,  6:12,  1 user,  load average: 0.31, 0.28, 0.25\n' % time.strftime('%H:%M:%S', time.gmtime(T))
            self.cmds[(h, 'xe_host-list')] = ''.join('uuid ( RO)                : %s\n          name-label ( RW): %s\n    software-version (MRO): product_version: %s; xapi: 1.20\n\n' % (('a1' if x == H1 else 'b2') * 4 + '-0000', x, BUILD) for x in (H1, H2))
            self.cmds[(h, 'xe_pool-list')] = 'uuid ( RO)           : 9c1d2e3f-0a1b-4c2d-8e3f-4a5b6c7d8e9f\n          name-label ( RW): Brightwater-DUB\n    master ( RO): %s\n            ha-enabled ( RO): true\n' % H1
            self.cmds[(h, 'xe_sr-list')] = ''.join('uuid ( RO)                : %s\n          name-label ( RW): %s\n    physical-utilisation ( RO): %s\n         physical-size ( RO): %s\n' % (u, SR_NAMES[u], a, b)
                                                 for u, a, b in ((SR_ISCSI, '1.9TiB', '3.4TiB'), (SR_NFS, '2.2TiB', '5.0TiB'), (SR_LOCAL, '210GiB', '894GiB')))
            self.cmds[(h, 'xe_vm-list')] = ''.join('name-label ( RW): %s\n    power-state ( RO): running\n    resident-on ( RO): %s\n' % (v, vh) for v, vh in VMS)
            self.cmds[(h, 'multipath_-ll')] = '3600601604d3f4e00aa11bb22cc33dd44 dm-3 SAN,PWR-LUN3\nsize=3.4T features=\'1 queue_if_no_path\' hwhandler=\'1 alua\' wp=rw\n|-+- policy=\'service-time 0\' prio=50 status=active\n| `- 3:0:0:3 sdc 8:32 active ready running\n`-+- policy=\'service-time 0\' prio=10 status=enabled\n  `- 4:0:0:3 sdd 8:48 active ready running\n'
            self.cmds[(h, 'chronyc_tracking')] = 'Reference ID    : C0000201 (ntp1.brightwater.example)\nStratum         : 3\nSystem time     : 0.000041 seconds fast of NTP time\nLeap status     : Normal\n'
            self.cmds[(h, 'systemctl_is-active_xapi')] = 'active\n'
            self.cmds[(h, 'openssl_x509_enddate')] = 'notAfter=%s\n' % time.strftime('%b %e %H:%M:%S %Y GMT', time.gmtime(T + 200 * 86400))
            self.cmds[(h, 'ip_-br_addr')] = 'lo UNKNOWN 127.0.0.1/8\nxenbr0 UP %s/24\nbond0 UP\n' % IP[h]
        self.cmds[(XOA, 'df_-h')] = 'Filesystem      Size  Used Avail Use% Mounted on\n/dev/xvda1       30G   11G   18G  38% /\n/dev/xvdb        200G   74G  117G  39% /var/lib/xo-server\n'
        self.cmds[(XOA, 'systemctl_is-active_xo-server')] = 'active\n'
        self.cmds[(XOA, 'free_-m')] = '              total        used        free\nMem:           4096        1822         902\n'
        self.cmds[(XOA, 'uptime')] = ' %s up 12 days,  3:44,  load average: 0.12, 0.10, 0.09\n' % time.strftime('%H:%M:%S', time.gmtime(T))

    # ---- output
    def write(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        path = os.path.join(out_dir, self.bid + '.tgz')
        with tarfile.open(path, 'w:gz') as tf:
            def add(name, data):
                ti = tarfile.TarInfo('%s/%s' % (self.bid, name))
                ti.size = len(data)
                ti.mtime = self.T
                tf.addfile(ti, io.BytesIO(data))
            for (node, rel), rows in sorted(self.files.items()):
                rows.sort(key=lambda x: x[0])
                add('%s/%s' % (node, rel), ('\n'.join(l for _t, l in rows) + '\n').encode())
            for (node, name), text in sorted(self.cmds.items()):
                add('%s/commands/%s.txt' % (node, name), text.encode())
            add('NOTES.txt', self.notes.encode())
        return path


# ================================================================== the six cases
def case_sr_full(e):
    T, r = e.T, e.rnd
    pct = 14
    for ts in range(T - 6 * 3600, T, 1800):                                           # SAN LUN slowly fills
        pct = max(1, pct - 2)
        e.log(H1, 'var/log/SMlog', ts, 'SM: [%d] SR %s: physical utilisation high, %d%% free' % (e.pid(), SR_ISCSI, pct))
    e.log(H1, 'var/log/SMlog', T, 'SM: [18211] ***** LVHDoISCSISR: EXCEPTION <class \'SR.SROSError\'>, Volume group "VG_XenStorage-%s" has insufficient free space (3 extents): 255 required.' % SR_ISCSI)
    e.log(H1, 'var/log/SMlog', T + 4, 'SMGC: [24311] gc: ***** Exception while coalescing: Leaf-coalesce failed, no space left on SR: unable to allocate 4096 MB')
    e.log(H1, 'var/log/SMlog', T + 5, 'SMGC: [24311] gc: UNDO LEAF-COALESCE of 7a1e22c0 failed, giving up for now')
    e.log(H1, 'var/log/SMlog', T + 40, 'SMGC: [24311] gc: ***** Too many VHD in chain (31) for VDI 7a1e22c0; coalesce is stuck')
    e.log(H1, 'var/log/xensource.log', T + 90, 'xapi: [error|%s|5120 |VM.start R:4a2c9e|backtrace] Raised Server_error(SR_BACKEND_FAILURE_44, [ ; Insufficient space; ])' % H1)
    e.log(H1, 'var/log/xensource.log', T + 91, 'xapi: [error|%s|5120 |VM.start R:4a2c9e|xapi] VM.start: failed to start VM erp-db01: SR_BACKEND_FAILURE_44' % H1)
    e.log(H1, 'var/log/xensource.log', T + 900, 'xapi: [error|%s|5321 |VDI.snapshot R:77f1b0|backtrace] SR_BACKEND_FAILURE_109: The snapshot chain is too long' % H1)
    for k, (v, _h) in enumerate(VMS[:3]):
        e.raw(XOA, 'xo/journalctl-xo-server.txt', T + 3000 + k * 20, '%s %s xo-server[772]: %s xo:backups:worker ERROR job "nightly-prod" failed for VM %s: VDI_IO_ERROR(Insufficient space on SR)' % (stamp(T + 3000 + k * 20), XOA, iso(T + 3000, e.rnd), v))
    for h in (H1, H2):
        e.cmds[(h, 'xe_sr-list')] = e.cmds[(h, 'xe_sr-list')].replace('1.9TiB', '3.4TiB')       # LUN 100% used


def case_ha_fence(e):
    T = e.T
    for ts, h, msg in ((T - 20, H2, 'kernel: [3561122.114477] bond0: link status definitely down for interface eth0, disabling it'),
                       (T - 19, H2, 'kernel: [3561122.620312] bond0: link status definitely down for interface eth1, disabling it'),
                       (T - 19, H2, 'kernel: [3561122.620377] bond0: now running without any active interface!'),
                       (T - 18, H2, 'kernel: [3561123.001203] ixgbe 0000:03:00.0 eth0: NIC Link is Down')):
        e.log(h, 'var/log/kern.log', ts, msg)
    e.log(H2, 'var/log/xha.log', T + 3, 'xhad: [ warn] no heartbeat received from host %s for 31 seconds: network heartbeat lost' % H1)
    e.log(H2, 'var/log/xha.log', T + 11, 'xhad: [ warn] statefile heartbeat timed out: cannot reach the heartbeat disk on SR %s' % SR_ISCSI)
    e.log(H2, 'var/log/xha.log', T + 28, 'xhad: [crit] host %s cannot join the liveset: self-fencing now' % H2)
    e.log(H2, 'var/log/messages', T + 29, 'systemd: Starting Reboot (host fenced by xha)...')
    e.log(H1, 'var/log/xensource.log', T + 31, 'xapi: [error|%s|3011 |xapi|xapi] Host %s is not responding (heartbeat lost); marking it dead' % (H1, H2))
    e.log(H2, 'var/log/xensource.log', T + 25, 'xapi: [error|%s|2290 |pool_db_sync|xapi] Cannot contact the pool master %s: Lost connection to the pool master' % (H2, H1))
    for k, (v, h) in enumerate(v for v in VMS if v[1] == H2):
        e.log(H1, 'var/log/xensource.log', T + 60 + k * 7, 'xapi: [ info|%s|3411 |HA|xapi] HA: restarting VM %s on %s after host failure' % (H1, v, H1))
    e.log(H2, 'var/log/kern.log', T + 150, 'kernel: [    0.000000] Linux version 4.19.0+1 (mockbuild@xcp-ng.org) #1 SMP Tue Jul 12 2026')
    e.log(H2, 'var/log/kern.log', T + 171, 'kernel: [   11.480112] bond0: link status definitely up for interface eth0, 10000 Mbps full duplex')
    e.raw(XOA, 'xo/journalctl-xo-server.txt', T + 33, '%s %s xo-server[772]: %s xo:xo-server WARN host %s disconnected: connect ETIMEDOUT %s:443' % (stamp(T + 33), XOA, iso(T + 33, e.rnd), H2, IP[H2]))


def case_host_disk_full(e):
    T = e.T
    for ts, p in ((T - 5 * 3600, 70), (T - 3 * 3600, 85), (T - 3600, 92), (T - 900, 97)):
        e.log(H1, 'var/log/xensource.log', ts, 'xapi: [ warn|%s|4100 |alert|xapi] Disk Usage for Control Domain on %s has reached %d%%' % (H1, H1, p))
    for k in range(60):                                                              # log spam fills /var/log
        e.log(H1, 'var/log/SMlog', T - 2400 + k * 40, 'SM: [%d] ***** vhd-util scan: unexpected output ignored (repeat %d)' % (e.pid(), k))
    e.log(H1, 'var/log/messages', T, 'rsyslogd: file \'/var/log/SMlog\' write error - see https://www.rsyslog.com/e/2027 [v8.24.0] (No space left on device)')
    e.log(H1, 'var/log/kern.log', T + 1, 'kernel: [3601244.220123] EXT4-fs warning (device sda5): ext4_dx_add_entry:2494: Directory index full!')
    e.log(H1, 'var/log/xensource.log', T + 20, 'xapi: [error|%s|4101 |xapi|xapi] Disk Usage for Control Domain on %s has reached 100%%; No space left on device' % (H1, H1))
    e.log(H1, 'var/log/daemon.log', T + 25, 'systemd: xapi.service: main process exited, code=exited, status=1/FAILURE')
    for k in range(5):
        e.log(H1, 'var/log/daemon.log', T + 40 + k * 15, 'systemd: xapi.service: Scheduled restart job, restart counter is at %d.' % (k + 1))
    e.log(H1, 'var/log/daemon.log', T + 120, 'systemd: xapi.service: start request repeated too quickly, refusing to start.')
    e.raw(XOA, 'xo/journalctl-xo-server.txt', T + 45, '%s %s xo-server[772]: %s xo:xo-server WARN host %s disconnected: connect ECONNREFUSED %s:443' % (stamp(T + 45), XOA, iso(T + 45, e.rnd), H1, IP[H1]))
    e.cmds[(H1, 'df_-h')] = e.cmds[(H1, 'df_-h')].replace('/dev/sda5       3.9G  1.2G  2.5G  33%', '/dev/sda5       3.9G  3.9G     0 100%')
    e.cmds[(H1, 'systemctl_is-active_xapi')] = 'failed\n'


def case_nfs_stall(e):
    T = e.T
    e.log(H1, 'var/log/kern.log', T, 'kernel: [3750011.114477] nfs: server %s not responding, still trying' % NAS)
    e.log(H2, 'var/log/kern.log', T + 1, 'kernel: [3750012.221001] nfs: server %s not responding, still trying' % NAS)
    for k, pid in enumerate((14021, 14022, 14040)):
        e.log(H1, 'var/log/kern.log', T + 125 + k, 'kernel: [3750136.110%03d] INFO: task tapdisk:%d blocked for more than 120 seconds.' % (k, pid))
        e.log(H1, 'var/log/kern.log', T + 125 + k, 'kernel: [3750136.111%03d]       Not tainted 4.19.0+1 #1' % k)
        e.log(H1, 'var/log/kern.log', T + 126 + k, 'kernel: [3750136.112%03d] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.' % k)
    e.log(H1, 'var/log/SMlog', T + 140, 'SM: [20311] ***** NFSSR.scan: EXCEPTION <class \'util.CommandException\'>, Stale file handle')
    e.log(H1, 'var/log/xensource.log', T + 150, 'xapi: [error|%s|6011 |PBD.plug R:ab12|xapi] PBD_PLUG_FAILED: SR %s (%s) is not available' % (H1, SR_NFS, SR_NAMES[SR_NFS]))
    e.log(H1, 'var/log/xensource.log', T + 151, 'xapi: [error|%s|6012 |SR.scan|xapi] SR_BACKEND_FAILURE_47: The SR is not available [opterr=no such directory]' % H1)
    for k, (v, h) in enumerate(v for v in VMS if v[1] == H1):
        e.log(H1, 'var/log/xensource.log', T + 200 + k, 'xapi: [error|%s|6100 |VM.pause|xapi] VM %s i/o to NFS-NAS01-VMs is stalled' % (H1, v))
    e.raw(XOA, 'xo/journalctl-xo-server.txt', T + 600, '%s %s xo-server[772]: %s xo:backups:worker ERROR backup job "nightly-prod" failed: remote "nas01-backups" unreachable' % (stamp(T + 600), XOA, iso(T + 600, e.rnd)))
    e.log(H1, 'var/log/kern.log', T + 540, 'kernel: [3750560.000102] nfs: server %s OK' % NAS)
    e.cmds[(H2, 'openssl_x509_enddate')] = 'notAfter=%s\n' % time.strftime('%b %e %H:%M:%S %Y GMT', time.gmtime(T + 9 * 86400))      # unrelated to the outage, but the Toolbox should flag it


def case_dom0_oom(e):
    T = e.T
    for k, ts in enumerate(range(T - 4 * 3600, T, 1200)):
        e.log(H1, 'var/log/messages', ts, 'squeezed: [ warn] dom0 memory pressure: reclaimed %d MiB from guests (target %d MiB)' % (90 + k * 15, 3900 - k * 60))
    e.log(H1, 'var/log/kern.log', T, 'kernel: [3902210.514002] xapi invoked oom-killer: gfp_mask=0x6200ca(GFP_HIGHUSER_MOVABLE), nodemask=(null), order=0, oom_score_adj=0')
    e.log(H1, 'var/log/kern.log', T + 1, 'kernel: [3902210.514921] oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,task_memcg=/,task=xapi,pid=2311,uid=0')
    e.log(H1, 'var/log/kern.log', T + 1, 'kernel: [3902210.515008] Out of memory: Killed process 2311 (xapi) total-vm:3180244kB, anon-rss:1480212kB, file-rss:0kB, shmem-rss:0kB')
    e.log(H1, 'var/log/daemon.log', T + 2, 'systemd: xapi.service: main process exited, code=killed, status=9/KILL')
    e.log(H1, 'var/log/daemon.log', T + 3, 'systemd: xapi.service: Failed with result \'signal\'.')
    e.log(H1, 'var/log/xensource.log', T + 25, 'xapi: [ info|%s|1 ||xapi] xapi starting; toolstack restarted after crash' % H1)
    e.log(H1, 'var/log/xensource.log', T + 60, 'xapi: [error|%s|77 |VM.start R:9c|backtrace] Raised Server_error(HOST_NOT_ENOUGH_FREE_MEMORY, [ 2147483648; 905969664 ])' % H1)
    e.raw(XOA, 'xo/journalctl-xo-server.txt', T + 5, '%s %s xo-server[772]: %s xo:xo-server WARN host %s disconnected: connect ECONNREFUSED %s:443' % (stamp(T + 5), XOA, iso(T + 5, e.rnd), H1, IP[H1]))
    e.cmds[(H1, 'free_-m')] = '              total        used        free      shared  buff/cache   available\nMem:           4096        4021          38           8          37          21\nSwap:          1023         988          35\n'


def case_xoa_disk_full(e):
    T = e.T
    for ts, p in ((T - 20 * 3600, 71), (T - 10 * 3600, 83), (T - 3 * 3600, 94)):
        e.log(XOA, 'var/log/syslog', ts, 'xo-health[%d]: filesystem /var/lib/xo-server at %d%%' % (e.pid(), p))
    e.raw(XOA, 'xo/journalctl-xo-server.txt', T, '%s %s xo-server[772]: %s xo:backups:worker ERROR ENOSPC: no space left on device, write \'/var/lib/xo-server/backups/xo-vm-backups/erp-db01/20261117T030000Z.vhd\'' % (stamp(T), XOA, iso(T, e.rnd)))
    e.raw(XOA, 'xo/journalctl-xo-server.txt', T + 2, '%s %s xo-server[772]: %s xo:backups:worker ERROR job "nightly-prod" failed for VM erp-db01: Backup failed: no space left on device' % (stamp(T + 2), XOA, iso(T + 2, e.rnd)))
    e.raw(XOA, 'xo/journalctl-xo-server.txt', T + 9, '%s %s xo-server[772]: %s xo:backups:worker ERROR remote local-backups is full: only 0 bytes available' % (stamp(T + 9), XOA, iso(T + 9, e.rnd)))
    e.log(XOA, 'xo/xoa-updater.log', T + 3600, 'xoa-updater: ERROR Cannot write update: ENOSPC no space left on device')
    e.log(XOA, 'var/log/syslog', T + 30, 'systemd[1]: xo-server.service: Failed to write journal: No space left on device')
    e.cmds[(XOA, 'df_-h')] = e.cmds[(XOA, 'df_-h')].replace('/dev/xvdb        200G   74G  117G  39%', '/dev/xvdb        200G  200G     0 100%')
    e.cmds[(XOA, 'systemctl_is-active_xo-server')] = 'failed\n'


CASES = [
    dict(id='BW-01', slug='sr-full', fn=case_sr_full, incident=timegm((2026, 11, 12, 2, 14, 0)), ticket='BW-0001',
         issue='ERP database VM erp-db01 will not start after last night\'s backup, and the nightly backup failed for several VMs',
         expect='xcp.sr_full', also=['xcp.coalesce_stuck', 'xcp.vm_start_fail', 'xcp.sr_chain', 'xcp.xo_backup'],
         hand=['grep -h "insufficient free space\\|SMGC\\|SR_BACKEND" xcp-dub-01/var/log/SMlog xcp-dub-01/var/log/xensource.log | sort',
               'grep -h "physical utilisation high" xcp-dub-01/var/log/SMlog   # the SAN LUN has been filling for 6 hours',
               'grep -h "VDI_IO_ERROR" xoa-dub-01/xo/journalctl-xo-server.txt   # backups fail because of the SR, not XO'],
         cause='The iSCSI SAN LUN (iSCSI-SAN01-LUN3) reached 100%. Coalesce cannot run without free space, so the VHD chain grows and VM.start / backups fail.'),
    dict(id='BW-02', slug='ha-fence', fn=case_ha_fence, incident=timegm((2026, 11, 13, 14, 31, 0)), ticket='BW-0002',
         issue='Host xcp-dub-02 rebooted by itself at about 14:31 and its VMs were restarted on the other host',
         expect='xcp.ha_fence', also=['xcp.master_unreachable'],
         hand=['grep -h "bond0\\|NIC Link" xcp-dub-02/var/log/kern.log   # both uplinks dropped first',
               'grep -h xhad xcp-dub-02/var/log/xha.log   # heartbeat lost -> self-fencing',
               'grep -h "not responding\\|HA: restarting" xcp-dub-01/var/log/xensource.log'],
         cause='Both bond0 uplinks of xcp-dub-02 went down (switch/cable). XCP-ng HA lost network and storage heartbeat and fenced the host, as designed; VMs restarted on xcp-dub-01.'),
    dict(id='BW-03', slug='dom0-disk-full', fn=case_host_disk_full, incident=timegm((2026, 11, 14, 22, 50, 0)), ticket='BW-0003',
         issue='Xen Orchestra shows host xcp-dub-01 as disconnected and xe commands hang',
         expect='xcp.host_disk_full', also=['xcp.xapi_down'],
         hand=['grep -h "Disk Usage for Control Domain\\|No space left" xcp-dub-01/var/log/xensource.log xcp-dub-01/var/log/messages',
               'grep -h "xapi.service" xcp-dub-01/var/log/daemon.log   # restart loop, then refuses to start',
               'cat xcp-dub-01/commands/df_-h.txt   # /var/log is 100%'],
         cause='/var/log on xcp-dub-01 filled (SM log spam), so xapi cannot write and keeps crashing; XO sees ECONNREFUSED. Free space, then restart the toolstack.'),
    dict(id='BW-04', slug='nfs-outage', fn=case_nfs_stall, incident=timegm((2026, 11, 15, 11, 7, 0)), ticket='BW-0004',
         issue='All VMs on the NFS storage froze around 11:07 and the NAS SR shows as unplugged',
         expect='xcp.sr_unplugged', also=['xcp.mount_stall', 'xcp.xo_backup'],     # the earliest evidence ("nfs: server not responding") is also the root event
         hand=['grep -h "nfs: server\\|blocked for more than" xcp-dub-01/var/log/kern.log',
               'grep -h "Stale file handle\\|PBD_PLUG_FAILED\\|SR_BACKEND_FAILURE_47" xcp-dub-01/var/log/SMlog xcp-dub-01/var/log/xensource.log',
               'grep -h "unreachable" xoa-dub-01/xo/journalctl-xo-server.txt'],
         cause='The NAS (nas01) stopped answering NFS for ~9 minutes. tapdisk tasks hung in the kernel, the SR PBD failed to plug and backups to the NAS remote failed.'),
    dict(id='BW-05', slug='dom0-oom', fn=case_dom0_oom, incident=timegm((2026, 11, 16, 5, 40, 0)), ticket='BW-0005',
         issue='xcp-dub-01 dropped out of Xen Orchestra at 05:40 and a VM could not be started afterwards',
         expect='xcp.dom0_oom', also=['xcp.xapi_down', 'xcp.vm_no_memory'],
         hand=['grep -h "oom-killer\\|Out of memory\\|Killed process" xcp-dub-01/var/log/kern.log',
               'grep -h squeezed xcp-dub-01/var/log/messages   # dom0 memory pressure for hours',
               'cat xcp-dub-01/commands/free_-m.txt   # 38 MB free, swap exhausted'],
         cause='dom0 ran out of memory; the kernel OOM-killer killed xapi. The toolstack restarted but memory is still exhausted, so later VM.start fails with HOST_NOT_ENOUGH_FREE_MEMORY. Raise dom0 memory.'),
    dict(id='BW-06', slug='xoa-disk-full', fn=case_xoa_disk_full, incident=timegm((2026, 11, 17, 3, 15, 0)), ticket='BW-0006',
         issue='Nightly backups failed on the Xen Orchestra appliance and the appliance cannot update itself',
         expect='xcp.xo_disk_full', also=['xcp.xo_backup', 'xcp.xoa_update'],
         hand=['grep -h "ENOSPC\\|no space\\|is full" xoa-dub-01/xo/journalctl-xo-server.txt xoa-dub-01/xo/xoa-updater.log',
               'cat xoa-dub-01/commands/df_-h.txt   # /var/lib/xo-server is 100%',
               'grep -h "filesystem /var/lib/xo-server" xoa-dub-01/var/log/syslog   # 71% -> 83% -> 94% earlier'],
         cause='The XO appliance\'s own backup/data volume is full, so backup writes (ENOSPC) and the updater fail. Not a host or storage problem: prune old backups or grow the volume.'),
]


def notes(c):
    t = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(c['incident']))
    return ('SUPPORT CASE %s   (FICTIONAL - synthetic data for testing)\nClient : %s\nPool   : Brightwater-DUB  hosts %s (master), %s;  Xen Orchestra %s\n'
            'Product: XCP-ng %s, Xen Orchestra 5.92\nReported: %s\nIssue  : %s\n' % (c['ticket'], CLIENT, H1, H2, XOA, BUILD, t, c['issue']))


def build(c, out_dir):
    e = Estate(c['id'] + '-' + c['slug'], c['incident'], seed=hash(c['id']) & 0xffff if False else int(c['id'][-2:]) * 101)
    e.notes = notes(c)
    e.background()
    c['fn'](e)
    return e.write(out_dir)


def cases_md():
    L = ['# Virtual estate: six fault-injected support bundles', '',
         'Fictional client **%s**: XCP-ng pool Brightwater-DUB (%s master, %s) + Xen Orchestra %s, an iSCSI SAN and an NFS NAS. All data is synthetic (documentation IP ranges, `.example` names).' % (CLIENT, H1, H2, XOA), '',
         'Rebuild: `python tools/build_virtual_estate.py examples/virtual-estate`. Analyse: `python -m lvx analyze BW-01-sr-full.tgz --issue "<issue>" --time <time> --format html -o r.html`.', '']
    for c in CASES:
        t = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(c['incident']))
        L += ['## %s-%s  (%s)' % (c['id'], c['slug'], c['ticket']), '', '- **Customer issue:** %s' % c['issue'], '- **Incident time:** `%s`' % t,
              '- **LogLens should rank first:** `%s`' % c['expect'], '- **Also expected:** %s' % ', '.join('`%s`' % x for x in c['also']),
              '- **Confirmed cause:** %s' % c['cause'], '- **Confirm it by hand** (from the extracted bundle folder):', '', '```sh'] + c['hand'] + ['```', '']
    return '\n'.join(L)


def main(argv):
    out = argv[1] if len(argv) > 1 else 'virtual-estate'
    only = set(argv[2:])
    for c in CASES:
        if not only or c['id'] in only:
            print('built', build(c, out))
    if not only:
        with open(os.path.join(out, 'CASES.md'), 'w', encoding='utf-8', newline='\n') as f:
            f.write(cases_md())


if __name__ == '__main__':
    main(sys.argv)
