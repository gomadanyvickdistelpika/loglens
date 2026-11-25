"""Build 3 independent fault-injected log bundles (hand-written formats, NOT taken from the repos' generators)."""
import io, os, random, sys, tarfile, datetime as dt

OUT = os.environ.get('FB_OUT') or (sys.argv[1] if len(sys.argv) > 1 else 'fault_out')
os.makedirs(OUT, exist_ok=True)
rnd = random.Random(42)


def iso(t):
    return t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % rnd.randint(0, 999)


def sysl(t, host):
    return '%s %2d %s ' % (t.strftime('%b'), t.day, t.strftime('%H:%M:%S')) + host + ' '


def build(name, files):
    p = os.path.join(OUT, name + '.tgz')
    with tarfile.open(p, 'w:gz') as tf:
        for path, lines in files.items():
            data = ('\n'.join(lines) + '\n').encode()
            ti = tarfile.TarInfo(f'{name}/{path}')
            ti.size = len(data)
            ti.mtime = 1700000000
            tf.addfile(ti, io.BytesIO(data))
    print('built', p)


def ticks(start, end, step_s, jitter=20):
    t = start
    while t < end:
        yield t
        t += dt.timedelta(seconds=step_s + rnd.randint(-jitter, jitter))


# ---------------------------------------------------------------- 1. ESXi: storage path loss -> APD -> VMs hung
def esxi():
    s = dt.datetime(2026, 11, 20, 6, 0)
    e = dt.datetime(2026, 11, 20, 12, 0)
    inc = dt.datetime(2026, 11, 20, 9, 14, 2)
    dev = 'naa.60060160a1b22c004f5d6e7f8a9b0c11'
    vmk, hostd, warn = [], [], []
    for t in ticks(s, e, 40):
        vmk.append(f'{iso(t)} cpu{rnd.randint(0,15)}:{rnd.randint(2097000,2098000)})vmnic1: NIC Link is Up 10000 Mbps Full Duplex')
        if rnd.random() < .3:
            vmk.append(f'{iso(t)} cpu3:2097600)Config: 681: "SIOControlFlag2" = 0, Old Value: 0, (Status: 0x0)')
        hostd.append(f'{iso(t)} info hostd[2099{rnd.randint(100,999)}] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event {rnd.randint(1000,9999)} : User root@127.0.0.1 logged in as pyvmomi')
    # decoy: harmless NTP warning, whole window (chronic)
    for t in ticks(s, e, 900):
        warn.append(f'{iso(t)} cpu1:2097100)WARNING: NTP: 1457: ntpd: time sync is slightly off by 38 ms')
    # fault: fabric path flap then all paths dead then APD
    t0 = inc
    seq = [
        (0, vmk, f'cpu4:2097411)ScsiPath: 4394: Path vmhba64:C0:T1:L12 is now dead (Fabric link down)'),
        (1, vmk, f'cpu4:2097411)ScsiPath: 4394: Path vmhba65:C0:T1:L12 is now dead (Fabric link down)'),
        (3, vmk, f'cpu7:2097330)NMP: nmp_ThrottleLogForDevice:3872: Cmd 0x2a (0x45d9c0c1a1c0, 2100874) to dev "{dev}" on path "vmhba64:C0:T1:L12" Failed: H:0x5 D:0x0 P:0x0 Invalid sense data: 0x0 0x0 0x0. Act:EVAL'),
        (4, vmk, f'cpu7:2097330)WARNING: NMP: nmpDeviceAttemptFailover:640: Retry world failover device "{dev}" - failed to issue command due to Not found (APD), try again...'),
        (9, vmk, f'cpu2:2097167)StorageApdHandler: 1203: APD Timer started for ident [{dev}]'),
        (10, warn, f'cpu2:2097167)WARNING: ScsiDevice: 5812: Device {dev} has been removed or is permanently inaccessible'),
        (35, vmk, f'cpu2:2097167)StorageApdHandler: 1315: APD Timer expired for ident [{dev}]'),
        (36, vmk, f'cpu2:2097167)StorageApdHandler: 1389: Device or filesystem with identifier [{dev}] has entered the All Paths Down Timeout state after being in the All Paths Down state for 140 seconds. I/Os will now be fast failed.'),
    ]
    for off, tgt, msg in seq:
        tgt.append(f'{iso(t0 + dt.timedelta(seconds=off))} ' + msg)
        if tgt is vmk and 'Path' in msg:
            warn.append(f'{iso(t0 + dt.timedelta(seconds=off))} ' + msg.replace('cpu4', 'cpu4', 1))
    hostd.append(f'{iso(t0 + dt.timedelta(seconds=11))} warning hostd[2099455] [Originator@6876 sub=Hostsvc.VmkVprobSource] Lost access to volume 5f3a1c2e-1b2c3d4e-aa55-0050568e1111 (PROD-DS01) due to connectivity issues. Recovery attempt is in progress and outcome will be reported shortly.')
    hostd.append(f'{iso(t0 + dt.timedelta(seconds=40))} error hostd[2099456] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/5f3a1c2e/web01/web01.vmx] Failed to read from file: I/O error (vm hung, no heartbeat)')
    hostd.append(f'{iso(t0 + dt.timedelta(seconds=41))} info hostd[2099457] [Originator@6876 sub=Vimsvc.ha-eventmgr] Event 9120 : Virtual machine web01 is not responding')
    # recovery 20 min later
    tr = t0 + dt.timedelta(minutes=21)
    vmk.append(f'{iso(tr)} cpu5:2097411)ScsiPath: 4394: Path vmhba64:C0:T1:L12 is now active')
    hostd.append(f'{iso(tr + dt.timedelta(seconds=3))} info hostd[2099460] [Originator@6876 sub=Hostsvc.VmkVprobSource] Successfully restored access to volume 5f3a1c2e-1b2c3d4e-aa55-0050568e1111 (PROD-DS01) following connectivity issues.')
    for l in (vmk, hostd, warn):
        l.sort()
    build('ESX-APD-01', {'var/run/log/vmkernel.log': vmk, 'var/run/log/hostd.log': hostd, 'var/run/log/vmkwarning.log': warn})
    return inc


# ---------------------------------------------------------------- 2. VCSA: /storage/log filled -> services fail
def vcsa():
    s = dt.datetime(2026, 11, 18, 0, 0)
    e = dt.datetime(2026, 11, 19, 12, 0)
    inc = dt.datetime(2026, 11, 19, 3, 42, 11)
    vpxd, vmon, pg, df = [], [], [], []
    for t in ticks(s, e, 120):
        vpxd.append(f'{iso(t)} info vpxd[07{rnd.randint(100,999)}] [Originator@6876 sub=vpxLro opID=sess-{rnd.randint(1000,9999)}] [VpxLRO] -- BEGIN task-{rnd.randint(100,999)} -- vpxd -- vim.PerformanceManager.queryStats')
    for t in ticks(s, e, 3000):
        vmon.append(f'{iso(t)} vmon[1204]  Service vpxd health check passed')
    for t in ticks(s, inc, 7200):
        vpxd.append(f'{iso(t)} warning vpxd[07701] [Originator@6876 sub=vpxUtil] Slow query warning: 1.2s')
    t0 = inc
    pg.append(f'{iso(t0)} 2026-11-19 03:42:11.201 UTC [11873] PANIC:  could not write to file "pg_wal/xlogtemp.11873": No space left on device')
    pg.append(f'{iso(t0 + dt.timedelta(seconds=1))} 2026-11-19 03:42:12.002 UTC [3101] LOG:  server process (PID 11873) was terminated by signal 6: Aborted')
    pg.append(f'{iso(t0 + dt.timedelta(seconds=2))} 2026-11-19 03:42:12.003 UTC [3101] LOG:  terminating any other active server processes')
    vpxd.append(f'{iso(t0 + dt.timedelta(seconds=3))} error vpxd[07701] [Originator@6876 sub=vpxdVdb] [VpxdVdb::Query] SQL execution failed: could not write block to temporary file: No space left on device')
    vpxd.append(f'{iso(t0 + dt.timedelta(seconds=5))} error vpxd[07701] [Originator@6876 sub=Default] Unable to write to /var/log/vmware/vpxd/vpxd-4.log: No space left on device')
    vpxd.append(f'{iso(t0 + dt.timedelta(seconds=9))} error vpxd[07701] [Originator@6876 sub=vpxdVdb] Lost connection to the database: Backend failure. Shutting down vpxd')
    vmon.append(f'{iso(t0 + dt.timedelta(seconds=12))} vmon[1204] <vpxd> Service exited unexpectedly with exit code 1 (signal 0)')
    vmon.append(f'{iso(t0 + dt.timedelta(seconds=13))} vmon[1204] <vpxd> Service entered failed state, restart attempt 1 of 5 in 5s')
    vmon.append(f'{iso(t0 + dt.timedelta(seconds=40))} vmon[1204] <vpxd> Service has failed 5 times in the last 5 minutes. Giving up restarts; service stopped')
    # df snapshot taken at support time
    df += ['Filesystem                                  Size  Used Avail Use% Mounted on',
           '/dev/mapper/log_vg-log                       25G   25G     0 100% /storage/log',
           '/dev/mapper/core_vg-core                     25G  1.1G   23G   5% /storage/core',
           '/dev/mapper/db_vg-db                        9.8G  3.1G  6.2G  34% /storage/db']
    for l in (vpxd, vmon, pg):
        l.sort()
    build('VCSA-DISKFULL-01', {'var/log/vmware/vpxd/vpxd.log': vpxd, 'var/log/vmware/vmon/vmon.log': vmon,
                               'var/log/vmware/vpostgres/postgresql.log': pg, 'commands/df_-h.txt': df})
    return inc


# ---------------------------------------------------------------- 3. XCP-ng: SR full -> coalesce fail -> VM won't start + XO backup fail
def xcp():
    s = dt.datetime(2026, 11, 19, 0, 0)
    e = dt.datetime(2026, 11, 21, 0, 0)
    inc = dt.datetime(2026, 11, 20, 8, 5, 30)
    h = 'xcp-host01'
    sm, xs, xo = [], [], []
    for t in ticks(s, e, 60):
        sm.append(sysl(t, h) + f'SM: [{rnd.randint(2000,30000)}] lock: acquired /var/lock/sm/00000000-0000-0000-0000-000000000000/sr')
        xs.append(sysl(t, h) + f'xapi: [ info||{rnd.randint(10,900)} |session.login_with_password D:{rnd.randint(1000,9999)}|xapi] Session.create trackid=abc pool=false uname=root')
    # slow fill: early warning
    for t in ticks(dt.datetime(2026, 11, 20, 6, 0), inc, 900):
        sm.append(sysl(t, h) + f'SM: [9120] SR 3b5c1f00-aa11-bb22-cc33-dd44ee55ff66: free space is getting low ({rnd.randint(2,6)}% free)')
    t0 = inc
    sm.append(sysl(t0, h) + 'SM: [18211] ***** LVHDoISCSISR.create: EXCEPTION <class \'SR.SROSError\'>, Insufficient space on SR (no space left in volume group VG_XenStorage-3b5c1f00)')
    sm.append(sysl(t0 + dt.timedelta(seconds=4), h) + 'SMGC: [24311] gc: ***** Exception while coalescing: Unable to allocate 4096 MB for coalesce, SR has 0 MB free')
    sm.append(sysl(t0 + dt.timedelta(seconds=5), h) + 'SMGC: [24311] gc: UNDO LEAF-COALESCE of 7a1e22c0 failed, giving up for now')
    sm.append(sysl(t0 + dt.timedelta(seconds=30), h) + 'SMGC: [24311] gc: ***** Too many VHD in chain (31) for VDI 7a1e22c0; coalesce is stuck')
    xs.append(sysl(t0 + dt.timedelta(seconds=45), h) + 'xapi: [error||5120 |VM.start R:4a2c|backtrace] Raised Server_error(SR_BACKEND_FAILURE_44, [ ; Insufficient space; ])')
    xs.append(sysl(t0 + dt.timedelta(seconds=46), h) + 'xapi: [error||5120 |VM.start R:4a2c|xapi] VM.start: failed to start VM db02: SR_BACKEND_FAILURE_44')
    xs.append(sysl(t0 + dt.timedelta(minutes=12), h) + 'xapi: [error||5321 |VDI.snapshot R:77f1|backtrace] SR_BACKEND_FAILURE_109: The snapshot chain is too long')
    xo.append((t0 + dt.timedelta(hours=1)).strftime('%b %d %H:%M:%S ') + 'xoa xo-server[455]: 2026-11-20T09:05:44.100Z xo:backups:worker ERROR job "nightly-prod" failed for VM db02: VDI_IO_ERROR(Insufficient space on SR)')
    xo.append((t0 + dt.timedelta(hours=1)).strftime('%b %d %H:%M:%S ') + 'xoa xo-server[455]: 2026-11-20T09:05:45.200Z xo:backups:worker ERROR backup run failed: Backup fell back to a full')
    build('XCP-SRFULL-01', {'var/log/SMlog': sm, 'var/log/xensource.log': xs, 'xo/journalctl-xo-server.txt': xo})
    return inc


if __name__ == '__main__':
    for fn in (esxi, vcsa, xcp):
        print(fn.__name__, fn())
