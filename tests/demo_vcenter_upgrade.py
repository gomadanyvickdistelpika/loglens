"""Build a SYNTHETIC support bundle for a failed VCSA upgrade (7.0 U3 -> 8.0 U3, Stage 2 'Import data').
Story: the customer upgraded, Stage 2 died during data import, they rolled back to the old appliance but
exported a log bundle from the NEW (target) appliance first.  Nothing here is real customer data.

Usage: python tests/demo_vcenter_upgrade.py OUT_DIR   -> writes OUT_DIR/vcsa-upgrade-failed/ and OUT_DIR/vcsa-upgrade-failed.tgz
"""
import os
import sys
import tarfile
from calendar import timegm

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen  # noqa: E402

FAIL = timegm((2026, 10, 7, 10, 2, 14))     # moment Stage 2 reported failure (UTC)
UPG = 'var/log/vmware/upgrade/upgrade-runner.log'
FB = 'var/log/firstboot/vpxd_firstboot.py_4412_stderr.log'
PG = 'var/log/vmware/vpostgres/postgresql.log'
VPXD = 'var/log/vmware/vpxd/vpxd-1.log'
PROXY = 'var/log/vmware/rhttpproxy/rhttpproxy.log'
H = 3600

LINES = [
    # --- Stage 1 / pre-checks (an hour before): warnings that LOOK scary but are mostly benign
    (-3900, UPG, '{t} INFO  upgrade-runner Pre-upgrade checks started for source 10.20.30.40 (vCenter Server 7.0.3.01700, build 21784236)'),
    (-3880, UPG, '{t} WARN  upgrade-runner Reverse DNS lookup for source appliance vc01.lab.example failed; continuing (forward lookup OK)'),
    (-3870, UPG, '{t} WARN  upgrade-runner Machine SSL certificate on source expires in 28 days'),
    (-3860, UPG, '{t} WARN  upgrade-runner Plugin com.vendor.backup is not compatible with target version; it will be disabled after upgrade'),
    (-3850, UPG, '{t} WARN  upgrade-runner Target deployment size is Tiny with storage size Default: /storage/seat is 10 GB but estimated requirement for Stats, Events, Tasks and Alarms (SEAT) data is 38 GB'),
    (-3840, UPG, '{t} INFO  upgrade-runner Pre-upgrade checks completed with 4 warnings, 0 errors. User acknowledged warnings.'),
    # --- Stage 2 start + export (fine)
    (-2400, UPG, '{t} INFO  upgrade-runner Stage 2 started: copy data from source vCenter Server'),
    (-2380, UPG, '{t} INFO  upgrade-runner Exporting configuration data from source ... done'),
    (-2000, UPG, '{t} INFO  upgrade-runner Exporting SEAT data from source (36.1 GB) ... done'),
    (-1900, UPG, '{t} INFO  upgrade-runner Transferring export bundle to target appliance ... done'),
    # --- import: database fills the partition
    (-1800, UPG, '{t} INFO  upgrade-runner Importing data on target (progress 61%)'),
    (-1500, PG,  '{t} UTC LOG:  checkpoints are occurring too frequently (14 seconds apart)'),
    (-1500, PG,  '{t} UTC HINT:  Consider increasing the configuration parameter "max_wal_size".'),
    (-900,  UPG, '{t} INFO  upgrade-runner Importing data on target (progress 78%)'),
    (-420,  PG,  '{t} UTC ERROR:  could not extend file "base/16385/24611": No space left on device'),
    (-420,  PG,  '{t} UTC HINT:  Check free disk space.'),
    (-419,  PG,  '{t} UTC STATEMENT:  COPY vpx_event (event_id, create_time, event_type, username, vm_id, host_id) FROM STDIN'),
    (-418,  PG,  '{t} UTC ERROR:  could not extend file "base/16385/24611": No space left on device'),
    (-417,  PG,  '{t} UTC FATAL:  terminating connection due to administrator command'),
    (-400,  FB,  '{t} ERROR vpxd_firstboot Import of SEAT data failed: psycopg2.errors.DiskFull: could not extend file "base/16385/24611": No space left on device'),
    (-399,  FB,  '{t} ERROR vpxd_firstboot Traceback (most recent call last): File "/usr/lib/vmware-vpx/firstboot/vpxd_firstboot.py", line 1184, in importSeat'),
    (-380,  FB,  '{t} ERROR vpxd_firstboot Firstboot script vpxd_firstboot.py exited with code 1'),
    (-370,  UPG, '{t} ERROR upgrade-runner Stage 2 failed at 83% during step "Import data": Failed to import configuration data (vpxd_firstboot exit code 1)'),
    # --- cascade (symptoms, not cause)
    (-300,  VPXD, '{t} error vpxd[05993] [Originator@6876 sub=Default] Unable to start vpxd: database connection failed: FATAL: the database system is in recovery mode'),
    (-290,  VPXD, '{t} error vpxd[05993] [Originator@6876 sub=Default] Failed to initialize database layer; shutting down'),
    (-250,  PROXY, '{t} error rhttpproxy[04120] [Originator@6876 sub=Proxy Req 00191] 503 Service Unavailable: no healthy upstream for /ui'),
    (-120,  'var/log/messages', '{s} vcenter systemd[1]: vmware-vpxd.service: Failed with result \'exit-code\'.'),
    (-60,   UPG, '{t} ERROR upgrade-runner Upgrade failed. Rollback: power on source appliance, discard target. Bundle collected via vc-support before rollback.'),
    # --- after: customer rolls back
    (1500,  UPG, '{t} INFO  upgrade-runner Target appliance powered off by user'),
]

# unrelated old noise well before the incident (must NOT be blamed)
OLD = [
    (-9 * 86400, 'var/log/messages', '{s} vcenter chronyd[442]: Selected source 10.20.30.1'),
    (-9 * 86400, VPXD, '{t} error vpxd[05993] [Originator@6876 sub=Default] Failed to read cached config for plugin 4821'),
    (-8 * 86400, PROXY, '{t} error rhttpproxy[04120] [Originator@6876 sub=Proxy Req 00007] 503 Service Unavailable: no healthy upstream for /ui'),
]

SCENARIO = dict(name='vcsa_upgrade_failed', kind='vcenter',
                issue='vCenter upgrade from 7.0 U3 to 8.0 U3 failed in stage 2 at import data; customer reverted to the old version',
                expect=['vc.disk_full', 'vc.upg_sizing', 'vc.upg_fail'], lines=LINES + OLD, anchor_off=0, min_rank=3)


def main(out):
    src = os.path.join(out, 'vcsa-upgrade-failed')
    truth = gen.build_dir(src, SCENARIO, anchor=FAIL, decoys=False)
    os.makedirs(os.path.join(src, 'commands'), exist_ok=True)
    with open(os.path.join(src, 'commands', 'df_h.txt'), 'w') as f:
        f.write('Filesystem                       Size  Used Avail Use% Mounted on\n'
                '/dev/sda3                         11G  4.1G  6.2G  40% /\n'
                '/dev/mapper/seat_vg-seat          10G   10G     0 100% /storage/seat\n'
                '/dev/mapper/log_vg-log           9.8G  2.2G  7.1G  24% /storage/log\n'
                '/dev/mapper/core_vg-core          25G   45M   24G   1% /storage/core\n')
    os.makedirs(os.path.join(src, 'var/log/firstboot'), exist_ok=True)
    with open(os.path.join(src, 'var/log/firstboot/firstbootStatus.json'), 'w') as f:
        f.write('{"firstboot": {"vpxd_firstboot.py": {"status": "failed", "exitCode": 1}, "vmware-vpostgres": {"status": "success"}}}\n')
    tgz = src + '.tgz'
    with tarfile.open(tgz, 'w:gz') as t:
        t.add(src, arcname='vcsa-upgrade-failed')
    print('bundle:', tgz)
    print('issue :', truth['issue'])
    print('time  : 2026-10-07T10:02:14Z')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else '.')
