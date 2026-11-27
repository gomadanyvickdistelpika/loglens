"""Synthetic XCP-ng / Xen Orchestra bundle generator with known ground truth (Vates counterpart of tests/gen.py).

Scenario lines are written in the style of real syslog-format XCP-ng / XO output but with phrasing that is deliberately NOT a copy of the
rule regexes or of the CT-50..CT-62 templates.  They are still my own approximation of real logs (see README caveats): results are in-sample.
Each scenario:  (offset seconds from the incident, file, template)   {s}=syslog stamp  {n}=random int  {u}=ISO stamp without Z
`expect` lists acceptable rank-1 rules.  Negative bundles (expect=[]) must raise no high/critical rule finding.
"""
import gzip
import os
import random
import tarfile
import time
import zipfile
from calendar import timegm

ANCHOR = timegm((2026, 9, 27, 14, 30, 0))
SPAN_DAYS = 14
STEP = 300

# ------------------------------------------------------------------ noise
XCP_NOISE = {
    'var/log/xensource.log': [
        '{s} xcp01 xapi: [ info|xcp01|{n} ||xapi_event] Event.next completed in 12ms',
        '{s} xcp01 xapi: [debug|xcp01|{n} /var/lib/xcp/xapi|session.login_with_password D:{n}|xapi] Session.create trackid={n} pool=false uname=root',
        '{s} xcp01 xenopsd-xc: [debug|xcp01|{n} |events|xenops] VM {n} state is running',
        '{s} xcp01 xapi: [ info|xcp01|{n} ||pool_db_sync] Synchronising the pool database completed',
        '{s} xcp01 xcp-rrdd: [ info|xcp01|{n} ||rrdd_main] Updated stats for {n} VMs',
        '{s} xcp01 xapi: [ info|xcp01|{n} ||xapi] host memory-free = {n} MiB',
    ],
    'var/log/SMlog': [
        '{s} xcp01 SM: [{n}] lock: opening lock file /var/lock/sm/{n}/sr',
        '{s} xcp01 SM: [{n}] sr_scan completed, found {c} VDIs',
        '{s} xcp01 SMGC: [{n}] Running the garbage collector for SR: nothing to do',
        '{s} xcp01 SMGC: [{n}] Coalesced size = 2.0G',
        '{s} xcp01 SM: [{n}] ***** lvhd: VDI_ATTACH succeeded',
    ],
    'var/log/daemon.log': [
        '{s} xcp01 stunnel: LOG5[{n}]: Service [xapi] accepted connection from 192.0.2.{c}',
        '{s} xcp01 systemd[1]: Started Session {n} of user root.',
        '{s} xcp01 xenstored: {n} watches registered',
    ],
    'var/log/kern.log': [
        '{s} xcp01 kernel: [{n}.{c}] vif vif-{c}-0 vif{c}.0: Guest Rx ready',
        '{s} xcp01 kernel: [{n}.{c}] device vif{c}.0 entered promiscuous mode',
    ],
}
XO_NOISE = {
    'xo/journalctl-xo-server.txt': [
        '{s} xo01 xo-server[771]: {u} xo:main INFO http://[::]:80 listening',
        '{s} xo01 xo-server[771]: {u} xo:xo-server INFO new client connected ({n})',
        '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers INFO server 192.0.2.{c} connected',
        '{s} xo01 xo-server[771]: {u} xo:backups:worker INFO job nightly started',
    ],
}
# extra realistic noise: warnings/errors/keyword near-misses that are NOT the incident
NOISY_XCP = {
    'var/log/xensource.log': [
        '{s} xcp01 xapi: [ warn|xcp01|{n} ||xapi] Failed to contact NTP peer 192.0.2.123 (will retry)',
        '{s} xcp01 xapi: [error|xcp01|{n} ||audit] Async.VM.snapshot D:{n} completed successfully',
        '{s} xcp01 xapi: [ warn|xcp01|{n} ||xapi_vm] VM tools out of date on VM app{c}',
        '{s} xcp01 xapi: [ info|xcp01|{n} ||xapi_ha] HA is disabled on this pool; heartbeat checks skipped',
        '{s} xcp01 xapi: [ info|xcp01|{n} ||xapi_vm_migrate] migrate precheck for VM app{c} passed',
    ],
    'var/log/SMlog': [
        '{s} xcp01 SMGC: [{n}] Coalesce of {n} finished successfully, SR has 45% free',
        '{s} xcp01 SM: [{n}] ***** iscsi session 192.0.2.50:3260 re-established (pbd already plugged)',
        '{s} xcp01 SM: [{n}] nfs: mount of 192.0.2.60:/export/sr completed successfully',
        '{s} xcp01 SM: [{n}] VDI {n} snapshot chain length is {c}, below the limit',
    ],
    'var/log/daemon.log': [
        '{s} xcp01 yum[{n}]: Nothing to do, system is up to date',
        '{s} xcp01 ntpd[{n}]: 192.0.2.123 reachable again',
        '{s} xcp01 chronyd[{n}]: Source 192.0.2.123 online',
        '{s} xcp01 rsyslogd: action 7 resumed (module builtin:omfile)',
    ],
    'var/log/kern.log': [
        '{s} xcp01 kernel: [{n}.{c}] xen: grant table gnttab_max_frames reached, retry ok',
        '{s} xcp01 kernel: [{n}.{c}] nfs: server 192.0.2.60 OK',
        '{s} xcp01 kernel: [{n}.{c}] device-mapper: multipath: path 8:16 is now active',
        '{s} xcp01 kernel: [{n}.{c}] megaraid_sas 0000:03:00.0: firmware crash dump: disabled',
        '{s} xcp01 kernel: [{n}.{c}] oom_score_adj of xapi set to -1000',
        '{s} xcp01 kernel: [{n}.{c}] tapdisk[{n}]: tap-ctl list reports 3 tapdisks, all running',
    ],
    'var/log/xha.log': [
        '{s} xcp01 multipathd[812]: mpatha: remaining active paths: 2',
    ],
}
NOISY_XO = {
    'xo/journalctl-xo-server.txt': [
        '{s} xo01 xo-server[771]: {u} xo:backups:worker INFO Backup job nightly completed successfully in 12m',
        '{s} xo01 xo-server[771]: {u} xo:backups:worker INFO snapshot {n} deleted from VM app{c}',
        '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.{c} reconnecting after 1 retry',
        '{s} xo01 xo-server[771]: {u} xo:main WARN HTTP request took {n} ms',
        '{s} xo01 xo-server[771]: {u} xo:api ERROR user session expired: please sign in again',
        '{s} xo01 xo-server[771]: {u} xo:main INFO certificate for xo01.lab.example is valid for 245 days',
    ],
}

X = 'var/log/xensource.log'
SM = 'var/log/SMlog'
DM = 'var/log/daemon.log'
KN = 'var/log/kern.log'
HA = 'var/log/xha.log'
XJ = 'xo/journalctl-xo-server.txt'
XU = 'xo/journalctl-xoa-updater.txt'
XI = 'xo/xo-install.log'

S = {}


def scn(name, kind, issue, expect, lines, min_rank=1):
    S[name] = dict(name=name, kind=kind, issue=issue, expect=expect, lines=lines, min_rank=min_rank)


# ============================================================ host
scn('host_enospc_rsyslog', 'xcpng', 'Host xcp01 is slow and Xen Orchestra shows a control domain disk usage alarm', ['xcp.host_disk_full'], [
    (-1500, DM, "{s} xcp01 rsyslogd: file '/var/log/messages' write error - discarding message: No space left on device"),
    (-1400, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Unix.Unix_error(Unix.ENOSPC, "write", "")'),
])
scn('host_var_log_full', 'xcpng', 'Logs partition is full on the pool master, backups and SR scans misbehave', ['xcp.host_disk_full'], [
    (-2000, DM, '{s} xcp01 logrotate: error: error writing to /var/log/xensource.log.1: No space left on device'),
    (-1990, DM, "{s} xcp01 xcp-ng-alarm: Disk Usage for Control Domain on server 'xcp01' has reached 99%"),
])
scn('host_xapi_service_died', 'xcpng', 'xe commands fail and the host appears disconnected in Xen Orchestra', ['xcp.xapi_down'], [
    (-1200, DM, '{s} xcp01 systemd[1]: xapi.service: main process exited, code=exited, status=1/FAILURE'),
    (-1199, DM, '{s} xcp01 systemd[1]: Unit xapi.service entered failed state.'),
    (-1100, X, '{s} xcp01 xe: Connection refused (calling connect )'),
])
scn('host_toolstack_restart_failed', 'xcpng', 'After a toolstack restart the host does not come back in the pool', ['xcp.xapi_down'], [
    (-900, DM, '{s} xcp01 xe-toolstack-restart: failed to restart xapi, see /var/log/daemon.log'),
    (-880, DM, '{s} xcp01 xapi: toolstack is not responding after 120 seconds'),
])
scn('host_disk_full_then_xapi', 'xcpng', 'Host unreachable, xapi will not start, disk is full', ['xcp.host_disk_full'], [
    (-2400, X, '{s} xcp01 xapi: [error|xcp01|{n} ||db_write] Could not write database file: No space left on device'),
    (-1800, DM, '{s} xcp01 systemd[1]: xapi.service: main process exited, code=exited, status=1/FAILURE'),
    (-1700, X, '{s} xcp01 xe: Connection refused (calling connect )'),
])
scn('host_yum_metadata', 'xcpng', 'Patching the host with yum fails', ['xcp.update_fail'], [
    (-1500, DM, '{s} xcp01 yum[{n}]: Error: Cannot retrieve repository metadata (repomd.xml) for repository: xcp-ng-base. Please verify its path and try again'),
    (-1490, DM, '{s} xcp01 yum[{n}]: urlgrabber: [Errno 14] HTTP Error 404 - Not Found'),
])
scn('host_rpu_evacuate', 'xcpng', 'Rolling Pool Update from XO stops while evacuating a host', ['xcp.update_fail'], [
    (-1300, X, '{s} xcp01 xapi: [error|xcp01|{n} |Async.host.evacuate R:{n}|xapi] host.evacuate failed: CANNOT_EVACUATE_HOST (VM app02 cannot be migrated)'),
    (-1290, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Rolling pool update: task failed, update aborted on host xcp02'),
])
scn('host_yum_transaction', 'xcpng', 'yum update leaves the host half updated', ['xcp.update_fail'], [
    (-1000, DM, '{s} xcp01 yum[{n}]: Transaction check error: file /opt/xensource/sm/cleanup.py from install conflicts'),
    (-990, DM, '{s} xcp01 yum[{n}]: Error: incomplete transactions found, run yum-complete-transaction'),
])

# ============================================================ pool / HA
scn('pool_master_cannot_connect', 'xcpng', 'Member host xcp02 lost the pool and shows pool master unreachable', ['xcp.master_unreachable'], [
    (-1800, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] Cannot connect to the pool master 192.0.2.11: Connection timed out'),
    (-1790, X, '{s} xcp02 xapi: [ warn|xcp02|{n} ||xapi] Unable to contact the coordinator, retrying in 10s'),
])
scn('pool_member_emergency', 'xcpng', 'After rebooting the master, slaves show emergency mode in XenCenter', ['xcp.master_unreachable'], [
    (-1500, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] Lost connection to the master; this host is entering emergency mode'),
    (-1400, DM, '{s} xcp02 xapi: HOST_IS_SLAVE: this host cannot execute the request'),
])
scn('pool_reset_master_run', 'xcpng', 'Pool master died; promoted a member by hand', ['xcp.master_unreachable'], [
    (-1200, DM, '{s} xcp02 xapi: pool-emergency-transition-to-master requested on host xcp02'),
    (-1190, X, '{s} xcp02 xapi: [ info|xcp02|{n} ||xapi] pool master is unreachable, running emergency reset of master address'),
])
scn('pool_ha_self_fence', 'xcpng', 'HA pool: hosts rebooted at the same time, VMs restarted', ['xcp.ha_fence'], [
    (-1500, HA, '{s} xcp03 xhad[{n}]: HA daemon lost the heartbeat of host xcp01 on the management network'),
    (-1490, HA, '{s} xcp03 xhad[{n}]: host xcp03 will self-fence in 60 seconds'),
    (-1430, HA, '{s} xcp03 xhad[{n}]: fencing: hard reset of this host'),
])
scn('pool_ha_statefile', 'xcpng', 'One host rebooted after the storage network flapped, HA enabled', ['xcp.ha_fence'], [
    (-1300, HA, '{s} xcp03 xhad[{n}]: cannot access the statefile on the heartbeat SR (I/O error)'),
    (-1290, HA, '{s} xcp03 xhad[{n}]: heartbeat disk not reachable, leaving the liveset'),
])
scn('pool_ha_fence_then_master', 'xcpng', 'HA reboot storm: hosts fenced and then lost the master', ['xcp.ha_fence'], [
    (-1800, HA, '{s} xcp03 xhad[{n}]: statefile access failed, host xcp03 self-fenced'),
    (-1500, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] Cannot connect to the pool master 192.0.2.11'),
    (-1490, DM, '{s} xcp02 xapi: Lost connection to the master; entering emergency mode'),
])

# ============================================================ storage / SR
scn('sr_insufficient_space', 'xcpng', 'Cannot create snapshot, SR reports insufficient space', ['xcp.sr_full'], [
    (-1500, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] VDI.snapshot failed: SR_BACKEND_FAILURE_44(, Insufficient space, )'),
    (-1490, SM, '{s} xcp01 SM: [{n}] Raising exception [44, Insufficient space]'),
])
scn('sr_lvm_vg_full', 'xcpng', 'Local LVM SR is full, VM disks cannot grow', ['xcp.sr_full'], [
    (-1800, SM, '{s} xcp01 SM: [{n}] lvcreate: Volume group "VG_XenStorage-0a1b2c3d" has insufficient free space (512 extents): 1024 required.'),
    (-1790, SM, '{s} xcp01 SM: [{n}] SR is full, unable to create the logical volume'),
])
scn('sr_coalesce_timeout', 'xcpng', 'Backups slow, coalesce never finishes', ['xcp.coalesce_stuck'], [
    (-2400, SM, '{s} xcp01 SMGC: [{n}] ***** Leaf-coalesce failed: timed out waiting for the VM to be quiesced'),
    (-2300, SM, '{s} xcp01 SMGC: [{n}] UNDO LEAF-COALESCE of 5c4d3e2f'),
    (-2000, SM, '{s} xcp01 SMGC: [{n}] UNDO LEAF-COALESCE of 5c4d3e2f'),
])
scn('sr_gc_exception', 'xcpng', 'Garbage collector keeps failing on the NFS SR', ['xcp.coalesce_stuck'], [
    (-2000, SM, '{s} xcp01 SMGC: [{n}] Exception in garbage collector: VHD parent not found, giving up'),
    (-1900, SM, '{s} xcp01 SMGC: [{n}] GC process aborted, will retry on the next rescan'),
])
scn('sr_full_then_coalesce', 'xcpng', 'SR is nearly full and coalesce does not run', ['xcp.sr_full'], [
    (-3600, SM, '{s} xcp01 SM: [{n}] Raising exception [44, Insufficient space on SR]'),
    (-3000, SM, '{s} xcp01 SMGC: [{n}] Unable to coalesce 5c4d3e2f: no space left for the coalesce'),
    (-2900, SM, '{s} xcp01 SMGC: [{n}] UNDO LEAF-COALESCE of 5c4d3e2f'),
])
scn('sr_full_coalesce_chain_vmfail', 'xcpng', 'VM will not start; SR is full and coalesce is stuck', ['xcp.sr_full'], [
    (-5400, SM, '{s} xcp01 SM: [{n}] Raising exception [44, Insufficient space]'),
    (-4800, SM, '{s} xcp01 SMGC: [{n}] Leaf-coalesce failed: not enough free space'),
    (-3600, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] SR_BACKEND_FAILURE_109(, The snapshot chain is too long, )'),
    (-600, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xenops] Async.VM.start failed: HVM_BOOT_FAILED for VM app01'),
])
scn('sr_chain_alone', 'xcpng', 'Snapshot job fails with chain too long', ['xcp.sr_chain'], [
    (-1200, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] VDI.snapshot failed: SR_BACKEND_FAILURE_109(, The snapshot chain is too long, )'),
    (-1190, SM, '{s} xcp01 SM: [{n}] Raising exception [109, The snapshot chain is too long]'),
])
scn('sr_chain_with_coalesce', 'xcpng', 'Delta backups fail, VDI chain too long, coalesce count rising', ['xcp.coalesce_stuck'], [
    (-4000, SM, '{s} xcp01 SMGC: [{n}] Coalesce failed on 9a8b7c6d: exception while reading the VHD footer'),
    (-3000, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] SR_BACKEND_FAILURE_109(, The snapshot chain is too long, )'),
])
scn('sr_iscsi_login_failed', 'xcpng', 'iSCSI SR is not plugged after the host reboot', ['xcp.sr_unplugged'], [
    (-1500, DM, '{s} xcp02 iscsid: Connection1:0 to [target: iqn.2026-03.example.lab:sr01, portal: 192.0.2.50,3260] login failed'),
    (-1490, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] PBD.plug failed: the SR is not available'),
])
scn('sr_nfs_not_responding', 'xcpng', 'NFS storage repository hangs and VMs freeze', ['xcp.sr_unplugged'], [
    (-1500, KN, '{s} xcp01 kernel: nfs: server 192.0.2.60 not responding, still trying'),
    (-1400, SM, '{s} xcp01 SM: [{n}] mount.nfs: Connection timed out'),
])
scn('sr_stale_nfs_handle', 'xcpng', 'After the NAS was rebuilt the SR cannot be reattached', ['xcp.sr_unplugged'], [
    (-1200, SM, '{s} xcp01 SM: [{n}] Stale file handle on /run/sr-mount/0a1b2c3d'),
    (-1190, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] pbd-plug failed for SR nfs-sr01'),
])
scn('sr_by_scsid_missing', 'xcpng', 'Local SR missing after reboot', ['xcp.sr_unplugged'], [
    (-1000, SM, '{s} xcp01 SM: [{n}] SR device /dev/disk/by-scsid/3600508b1001c9f2e not found: No such file or directory'),
    (-990, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] PBD_PLUG_FAILED for SR local-sr'),
])

# ============================================================ VM
scn('vm_no_memory_start', 'xcpng', 'Large VM will not start on host xcp02', ['xcp.vm_no_memory'], [
    (-1500, X, '{s} xcp02 xapi: [error|xcp02|{n} |Async.VM.start R:{n}|xapi] Async.VM.start failed: HOST_NOT_ENOUGH_FREE_MEMORY(17179869184, 12884901888)'),
    (-1490, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] Failed to start the VM db01'),
], min_rank=1)
scn('vm_no_memory_xenguest', 'xcpng', 'VM fails to start with memory errors', ['xcp.vm_no_memory'], [
    (-1200, X, '{s} xcp02 xenguest-{n}: xc_domain_populate_physmap_exact: Cannot allocate memory for the domain'),
    (-1190, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xenops] Unable to start the guest: not enough host memory'),
])
scn('vm_emulator_failed', 'xcpng', 'VM start fails after the latest patches', ['xcp.vm_start_fail'], [
    (-900, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xenops] The emulator required to run this VM failed to start'),
    (-890, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Async.VM.start failed: FAILED_TO_START_EMULATOR'),
])
scn('vm_bootloader_failed', 'xcpng', 'Migrated PV VM no longer boots', ['xcp.vm_start_fail'], [
    (-900, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Async.VM.start failed: BOOTLOADER_FAILED(no kernel found)'),
])
scn('vm_bad_power_state', 'xcpng', 'VM cannot be started or stopped, stuck state after host crash', ['xcp.vm_start_fail'], [
    (-800, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Async.VM.hard_shutdown failed: VM_BAD_POWER_STATE(running, halted)'),
    (-790, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Failed to start the VM web03: VM_BAD_POWER_STATE'),
])
scn('vm_hvm_boot_failed', 'xcpng', 'Windows VM does not boot', ['xcp.vm_start_fail'], [
    (-700, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Async.VM.start failed: HVM_BOOT_FAILED'),
])
scn('vm_migrate_mirror_failed', 'xcpng', 'Storage migration of a database VM keeps failing', ['xcp.migrate_fail'], [
    (-1500, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Storage_migrate: MIRROR_FAILED while copying disk'),
    (-1490, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] VM.migrate_send failed'),
])
scn('vm_migrate_generic', 'xcpng', 'Live migration between hosts fails', ['xcp.migrate_fail'], [
    (-1100, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi_vm_migrate] Xapi_vm_migrate: migration of VM app01 to xcp02 failed: connection closed'),
    (-1090, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Async.VM.pool_migrate failed: VM_MIGRATE_FAILED'),
])
scn('vm_no_mem_evacuate', 'xcpng', 'Cannot put host in maintenance, evacuation fails', ['xcp.vm_no_memory', 'xcp.update_fail'], [
    (-1300, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] host.evacuate: HOST_NOT_ENOUGH_FREE_MEMORY for VM db01'),
    (-1290, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] CANNOT_EVACUATE_HOST'),
])

# ============================================================ Xen Orchestra
scn('xo_backup_vdi_io', 'xo', 'Nightly backups fail with VDI_IO_ERROR', ['xcp.xo_backup'], [
    (-28000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job nightly failed: VDI_IO_ERROR(Device I/O errors)'),
    (-27990, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR VM app01 export interrupted: VDI_IO_ERROR'),
])
scn('xo_backup_job_failed', 'xo', 'Backup jobs fail for several VMs', ['xcp.xo_backup'], [
    (-20000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job weekly failed: HTTP connection has been closed'),
    (-19990, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR delta backup of VM web01 aborted'),
])
scn('xo_backup_remote_estale', 'xo', 'Backup repository on NFS keeps disconnecting', ['xcp.xo_backup'], [
    (-15000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR remote nfs-backup01 was disconnected: ESTALE'),
    (-14990, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job nightly failed on remote nfs-backup01'),
])
scn('xo_backup_chain_skip', 'xo', 'Backups skipped for one VM', ['xcp.sr_chain', 'xcp.xo_backup'], [
    (-10000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker WARN Backup skipped to protect VDI chain for VM db01'),
    (-9990, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR unhealthy VDI chain on SR nfs-sr01'),
])
scn('xo_tls_selfsigned', 'xo', 'Pool shows as disconnected in Xen Orchestra after the certificate was replaced', ['xcp.xo_tls'], [
    (-1500, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.21 connection failed: self signed certificate in certificate chain'),
    (-1490, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.21 connection failed: SELF_SIGNED_CERT_IN_CHAIN'),
])
scn('xo_tls_expired', 'xo', 'Cannot log in to XO, browser shows certificate errors', ['xcp.xo_tls'], [
    (-1200, XJ, '{s} xo01 xo-server[771]: {u} xo:main ERROR TLS handshake failed: certificate has expired'),
    (-1190, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.21 error: CERT_HAS_EXPIRED'),
])
scn('xo_tls_altname', 'xo', 'XO cannot connect to the pool by hostname', ['xcp.xo_tls'], [
    (-900, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server xcp01.lab.example connection failed: ERR_TLS_CERT_ALTNAME_INVALID'),
])
scn('xo_build_node_engine', 'xo', 'XO from sources no longer builds', ['xcp.xo_build'], [
    (-2000, XI, '{s} xo01 xo-install[1201]: error xo-web: The engine "node" is incompatible with this module. Expected version ">=18". Got "16.20.2"'),
    (-1990, XI, '{s} xo01 xo-install[1201]: error Found incompatible module.'),
])
scn('xo_build_gyp', 'xo', 'yarn install fails compiling native modules', ['xcp.xo_build'], [
    (-1800, XI, '{s} xo01 xo-install[1201]: gyp ERR! build error'),
    (-1790, XI, '{s} xo01 xo-install[1201]: error Command failed with exit code 1.'),
])
scn('xo_build_missing_module', 'xo', 'xo-server does not start after update from sources', ['xcp.xo_build'], [
    (-1600, XJ, "{s} xo01 xo-server[771]: Error: Cannot find module '/opt/xo/xo-builds/xen-orchestra/packages/xo-server/dist/loader.js'"),
    (-1590, XJ, '{s} xo01 systemd[1]: xo-server.service: Main process exited, code=exited, status=1/FAILURE'),
])
scn('xoa_update_proxy', 'xo', 'XOA update fails behind the proxy', ['xcp.xoa_update'], [
    (-1500, XU, '{s} xoa xoa-updater[412]: ERROR unable to reach xen-orchestra.com: unable to get local issuer certificate'),
    (-1490, XU, '{s} xoa xoa-updater[412]: ERROR upgrade failed'),
])
scn('xoa_update_json', 'xo', 'XOA updater reports a broken update file', ['xcp.xoa_update'], [
    (-1200, XU, '{s} xoa xoa-updater[412]: ERROR /var/lib/xoa-updater/update.json is corrupt: unexpected token'),
    (-1190, XU, '{s} xoa xoa-updater[412]: ERROR xoa-updater failed to parse the update list'),
])
scn('xoa_update_registration', 'xo', 'Updates page says the appliance cannot update', ['xcp.xoa_update'], [
    (-1000, XU, '{s} xoa xoa-updater[412]: ERROR this XOA is not registered, cannot upgrade'),
])


# ============================================================ held-out phrasings (written after the first harness run, before rule fixes)
scn('host_log_fs_usage', 'xcpng', 'Root partition of the pool master keeps filling', ['xcp.host_disk_full'], [
    (-1500, X, '{s} xcp01 xapi: [ warn|xcp01|{n} ||xapi] log_fs_usage: / is at 97% of its capacity'),
    (-1400, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] write failed on /var/lib/xcp/state.db: ENOSPC'),
])
scn('host_xapi_holdoff', 'xcpng', 'xapi restarts every minute', ['xcp.xapi_down'], [
    (-1500, DM, '{s} xcp01 systemd[1]: xapi.service holdoff time over, scheduling restart.'),
    (-1440, DM, '{s} xcp01 systemd[1]: xapi.service start request repeated too quickly, refusing to start.'),
])
scn('host_yum_mirrorlist', 'xcpng', 'Cannot install updates on the host', ['xcp.update_fail'], [
    (-1500, DM, '{s} xcp01 yum[{n}]: Could not retrieve mirrorlist http://mirrors.lab.example/xcp-ng/8/updates error was 14: curl#6 - "Could not resolve host"'),
    (-1490, DM, '{s} xcp01 yum[{n}]: Error downloading packages: xen-hypervisor-4.17: [Errno 256] No more mirrors to try.'),
])
scn('pool_ha_statefile_code', 'xcpng', 'HA cannot be enabled / hosts leave the pool liveset', ['xcp.ha_fence'], [
    (-1500, X, '{s} xcp03 xapi: [error|xcp03|{n} ||xapi] HA_HOST_CANNOT_ACCESS_STATEFILE'),
    (-1490, HA, '{s} xcp03 xhad[{n}]: xha_lc: lost access to the statefile, fencing this host'),
])
scn('sr_gc_errors', 'xcpng', 'Space on the SR is never reclaimed', ['xcp.coalesce_stuck'], [
    (-2500, SM, '{s} xcp01 SMGC: [{n}] *** ERROR: GC child process completed with errors'),
    (-2400, SM, '{s} xcp01 SMGC: [{n}] garbage collection of SR nfs-sr01 failed, will retry later'),
])
scn('vm_enough_memory', 'xcpng', 'VM start refused, host reports low memory', ['xcp.vm_no_memory'], [
    (-1500, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] The host does not have enough free memory to start VM web05'),
    (-1490, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] Unable to start the guest web05'),
])
scn('xo_tls_first_cert', 'xo', 'XO refuses to connect to a new pool master', ['xcp.xo_tls'], [
    (-1500, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.21 connection failed: unable to verify the first certificate'),
    (-1490, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.21 connection failed: Error: unable to verify the first certificate'),
])
scn('xoa_update_enotfound', 'xo', 'XOA cannot fetch updates', ['xcp.xoa_update'], [
    (-1500, XU, '{s} xoa xoa-updater[412]: ERROR request to https://xen-orchestra.com/api failed: getaddrinfo ENOTFOUND xen-orchestra.com'),
    (-1490, XU, '{s} xoa xoa-updater[412]: ERROR cannot check for updates'),
])
scn('xo_backup_no_space', 'xo', 'Backups fail because the remote ran out of space', ['xcp.xo_disk_full'], [
    (-9000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job nightly failed: ENOSPC: no space left on device, write'),
    (-8990, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR remote nfs-backup01 is full'),
])

# ============================================================ negative bundles: must NOT raise high/critical rule findings
scn('neg_host', 'xcpng', 'Host xcp01 looks slow, please check', [], [
    (-1500, DM, '{s} xcp01 yum[{n}]: Nothing to do, system is up to date'),
    (-1400, X, '{s} xcp01 xapi: [ warn|xcp01|{n} ||xapi] VM tools out of date on VM app03'),
    (-1300, SM, '{s} xcp01 SMGC: [{n}] Coalesce of 7a6b5c4d finished successfully, SR has 62% free'),
])
scn('neg_pool', 'xcpng', 'Checking the pool after the weekend', [], [
    (-1500, X, '{s} xcp02 xapi: [ info|xcp02|{n} ||xapi] pool master is xcp01 (192.0.2.11), connection ok'),
    (-1400, HA, '{s} xcp02 xhad[{n}]: heartbeat ok, all hosts in the liveset'),
    (-1300, X, '{s} xcp02 xapi: [ info|xcp02|{n} ||xapi] HA is enabled: 3 hosts, plan exists for 1 failure'),
])
scn('neg_storage', 'xcpng', 'Review of storage health', [], [
    (-1500, SM, '{s} xcp01 SM: [{n}] mount.nfs completed successfully for 192.0.2.60:/export/sr'),
    (-1400, SM, '{s} xcp01 SM: [{n}] VDI snapshot chain length is 3'),
    (-1300, KN, '{s} xcp01 kernel: [{n}.1] nfs: server 192.0.2.60 OK'),
])
scn('neg_xo', 'xo', 'Checking the backup report', [], [
    (-15000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker INFO Backup job nightly completed successfully in 9m'),
    (-14990, XJ, '{s} xo01 xo-server[771]: {u} xo:main INFO certificate for xo01.lab.example is valid for 300 days'),
    (-14980, XU, '{s} xoa xoa-updater[412]: INFO the appliance is up to date'),
])



# ============================================================ storage / kernel signals (second round, written after reviewing a public health-check tool)
scn('mp_failing_path', 'xcpng', 'Storage paths flapping on host xcp02', ['xcp.multipath_fail'], [
    (-1500, KN, '{s} xcp02 kernel: device-mapper: multipath: Failing path 8:48.'),
    (-1490, KN, '{s} xcp02 kernel: device-mapper: multipath: Failing path 8:64.'),
])
scn('mp_remaining_zero', 'xcpng', 'All storage paths lost on one host', ['xcp.multipath_fail'], [
    (-1500, DM, '{s} xcp02 multipathd[812]: mpathb: remaining active paths: 0'),
    (-1490, DM, '{s} xcp02 multipathd[812]: checker failed path 8:16 in map mpathb'),
])
scn('mp_path_down', 'xcpng', 'Intermittent storage disconnects', ['xcp.multipath_fail'], [
    (-1200, DM, '{s} xcp02 multipathd[812]: sdc: tur checker reports path is down'),
])
scn('lun_changed', 'xcpng', 'Array was reconfigured and a host complains about LUNs', ['xcp.lun_change'], [
    (-1500, KN, '{s} xcp02 kernel: scsi 6:0:0:2: Warning! Received an indication that the LUN assignments on this target have changed. The Linux SCSI layer does not automatically remap LUN assignments.'),
])
scn('lun_then_sr_unplug', 'xcpng', 'SR missing after the storage team changed the mapping', ['xcp.lun_change'], [
    (-3000, KN, '{s} xcp02 kernel: scsi 6:0:0:2: Warning! Received an indication that the LUN assignments on this target have changed.'),
    (-2000, SM, '{s} xcp02 SM: [{n}] SR device /dev/disk/by-scsid/3600508b1001c9f2e not found: No such file or directory'),
    (-1990, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] PBD_PLUG_FAILED for SR iscsi-sr01'),
])
scn('cifs_stall', 'xcpng', 'ISO library mount hangs the host console', ['xcp.mount_stall'], [
    (-1500, KN, '{s} xcp01 kernel: CIFS: VFS: Server 192.0.2.70 has not responded in 180 seconds. Reconnecting...'),
    (-1400, KN, '{s} xcp01 kernel: CIFS: VFS: Server 192.0.2.70 has not responded in 180 seconds. Reconnecting...'),
])
scn('hung_task', 'xcpng', 'Host becomes unresponsive, processes stuck', ['xcp.mount_stall'], [
    (-1500, KN, '{s} xcp01 kernel: INFO: task tapdisk:2210 blocked for more than 120 seconds.'),
    (-1499, KN, '{s} xcp01 kernel: "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.'),
])
scn('oom_killer', 'xcpng', 'A process died on the host without explanation', ['xcp.dom0_oom'], [
    (-1500, KN, '{s} xcp01 kernel: python invoked oom-killer: gfp_mask=0x24201ca, order=0, oom_score_adj=0'),
    (-1499, KN, '{s} xcp01 kernel: Out of memory: Killed process 4123 (python) total-vm:2104576kB, anon-rss:1048576kB, file-rss:0kB'),
])
scn('oom_cgroup', 'xcpng', 'A VM process disappeared', ['xcp.dom0_oom'], [
    (-1500, KN, '{s} xcp01 kernel: Memory cgroup out of memory: Killed process 777 (qemu-dm) total-vm:812345kB, anon-rss:700000kB, file-rss:0kB'),
])
scn('oom_then_xapi_exit', 'xcpng', 'xe commands time out, host disconnected in XO', ['xcp.dom0_oom'], [
    (-2400, KN, '{s} xcp01 kernel: xapi invoked oom-killer: gfp_mask=0x24201ca, order=0'),
    (-2399, KN, '{s} xcp01 kernel: Out of memory: Killed process 3321 (xapi) total-vm:2104576kB, anon-rss:1048576kB, file-rss:0kB'),
    (-2300, DM, '{s} xcp01 systemd[1]: xapi.service: main process exited, code=killed, status=9/KILL'),
    (-2290, X, '{s} xcp01 xe: Connection refused (calling connect )'),
])
scn('tapdisk_not_running', 'xcpng', 'A VM disk cannot be attached', ['xcp.tapdisk_dead'], [
    (-1500, SM, '{s} xcp01 SM: [{n}] Raising exception [46, The VDI is not available [opterr=TapdiskNotRunning: Tapdisk(vhd:/dev/VG_XenStorage-0a1b/VHD-6b5a) minor=2]]'),
])
scn('tapdisk_segfault', 'xcpng', 'VM froze, disk process crashed', ['xcp.tapdisk_dead'], [
    (-1500, KN, '{s} xcp01 kernel: tapdisk[3321]: segfault at 0 ip 00007f3a2b3c4d5e sp 00007ffd1c2b3a40 error 4 in tapdisk[400000+12000]'),
])
scn('tapdisk_dumped_core', 'xcpng', 'Storage process crashed overnight', ['xcp.tapdisk_dead'], [
    (-1500, DM, '{s} xcp01 systemd-coredump[5521]: Process 3321 (tapdisk) of user 0 dumped core.'),
])
scn('datapath_not_detached', 'xcpng', 'Backup fails and the disk cannot be unplugged', ['xcp.datapath_leak'], [
    (-1500, SM, '{s} xcp01 SM: [{n}] VDI 6b5a4c3d is not detached cleanly'),
    (-1490, SM, '{s} xcp01 SM: [{n}] vdi_detach: the VDI is still open on host xcp01'),
])
scn('datapath_blocked_pid', 'xcpng', 'SR operations are slow and some fail with lock errors', ['xcp.datapath_leak'], [
    (-1500, SM, '{s} xcp01 SM: [{n}] Failed to lock /var/lock/sm/0a1b2c3d/sr on first attempt, blocked by PID 4411'),
])
scn('datapath_resume_failed', 'xcpng', 'VM paused after a snapshot and will not resume', ['xcp.datapath_leak'], [
    (-1500, SM, '{s} xcp01 SM: [{n}] tap-ctl: tapdisk 5521 state RESUME_FAILED, still paused'),
])
scn('datapath_illegal_transition', 'xcpng', 'Every attach of one disk fails on host xcp01', ['xcp.datapath_leak'], [
    (-1500, X, '{s} xcp01 xapi: [error|xcp01|{n} ||storage_access] Illegal_transition: Attached -> Activated'),
    (-1490, X, '{s} xcp01 xapi: [ warn|xcp01|{n} ||storage_access] datapath vbd/0/xvdb leaked on SR 0a1b2c3d'),
])
scn('datapath_chain_backup_vmfail', 'xcpng', 'Backups fail and a VM cannot start after a failed export', ['xcp.datapath_leak'], [
    (-3000, SM, '{s} xcp01 SM: [{n}] VDI 6b5a4c3d is not detached cleanly'),
    (-2990, SM, '{s} xcp01 SM: [{n}] tap.deactivate: Warning, No such Tapdisk(minor=5)'),
    (-2000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job nightly failed: VDI_IO_ERROR(Device I/O errors)'),
    (-600, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Failed to start the VM web07: the VDI cannot be attached'),
])
scn('io_error_sm', 'xcpng', 'Storage errors in the SM log', ['xcp.io_error'], [
    (-1500, SM, '{s} xcp01 SM: [{n}] Error: [Errno 5] Input/output error: /var/run/sr-mount/0a1b2c3d/6b5a4c3d.vhd'),
])
scn('io_error_blk', 'xcpng', 'Disk errors in the kernel log', ['xcp.io_error'], [
    (-1500, KN, '{s} xcp01 kernel: blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0'),
    (-1490, KN, '{s} xcp01 kernel: blk_update_request: I/O error, dev sdb, sector 123464 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0'),
])
scn('kernel_panic', 'xcpng', 'Host rebooted by itself', ['xcp.kernel_fault'], [
    (-900, KN, '{s} xcp01 kernel: Kernel panic - not syncing: Fatal exception in interrupt'),
    (-899, KN, '{s} xcp01 kernel: Call Trace:'),
])
scn('kernel_soft_lockup', 'xcpng', 'Host very slow, CPU stuck messages', ['xcp.kernel_fault'], [
    (-900, KN, '{s} xcp01 kernel: watchdog: BUG: soft lockup - CPU#3 stuck for 23s! [kworker/3:1:221]'),
])
scn('kernel_oops', 'xcpng', 'Kernel error then VMs hung', ['xcp.kernel_fault'], [
    (-900, KN, '{s} xcp01 kernel: BUG: unable to handle kernel NULL pointer dereference at 0000000000000008'),
])
scn('neg_kernel', 'xcpng', 'Checking dom0 health after the maintenance window', [], [
    (-1500, KN, '{s} xcp01 kernel: megaraid_sas 0000:03:00.0: firmware crash dump: disabled'),
    (-1400, KN, '{s} xcp01 kernel: device-mapper: multipath: path 8:16 is now active'),
    (-1300, DM, '{s} xcp01 multipathd[812]: mpatha: remaining active paths: 2'),
    (-1200, KN, '{s} xcp01 kernel: oom_score_adj of xapi set to -1000'),
    (-1100, KN, '{s} xcp01 kernel: tapdisk[3321]: tap-ctl list reports 3 tapdisks, all running'),
])


def _noise(kind, noisy):
    n = {}
    if kind in ('xcpng', 'vates'):
        n.update(XCP_NOISE)
    if kind in ('xo', 'vates'):
        n.update(XO_NOISE)
    extra = {}
    if noisy:
        if kind in ('xcpng', 'vates'):
            extra.update(NOISY_XCP)
        if kind in ('xo', 'vates'):
            extra.update(NOISY_XO)
    return n, extra


def build_dir(dest, scenario, seed=7, anchor=ANCHOR, decoys=True, noisy=False):
    rnd = random.Random(seed)
    sc = S[scenario] if isinstance(scenario, str) else scenario
    noise, extra = _noise(sc['kind'], noisy)
    files = {}
    start = anchor - SPAN_DAYS * 86400
    end = anchor + 3600

    def fmt(tm, ts):
        return tm.format(s=time.strftime('%b %d %H:%M:%S', time.gmtime(ts)), u=time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts)) + '.%03d' % rnd.randint(0, 999),
                         c=rnd.randint(0, 15), n=rnd.randint(1000, 9999))

    ts = start
    while ts < end:
        for f, tms in noise.items():
            files.setdefault(f, []).append((ts, fmt(rnd.choice(tms), ts)))
        ts += STEP + rnd.randint(-5, 5)
    if extra:                                    # unrelated warnings / errors / keyword near-misses, thick during the incident window
        ts = start
        while ts < end:
            dense = abs(ts - anchor) < 86400
            f = rnd.choice(list(extra))
            files.setdefault(f, []).append((ts, fmt(rnd.choice(extra[f]), ts)))
            ts += (150 if dense else 900) + rnd.randint(-5, 5)

    def add(ts, f, tmpl):
        files.setdefault(f, []).append((ts, fmt(tmpl, ts)))

    for off, f, tmpl in sc['lines']:
        add(anchor + off, f, tmpl)
        if decoys:                               # same signature 12 days earlier: the window must exclude it
            add(anchor + off - 12 * 86400, f, tmpl)
    for f, rows in files.items():
        rows.sort(key=lambda r: r[0])
        p = os.path.join(dest, f)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, 'w', encoding='utf-8', newline='\n') as fh:
            for _ts, ln in rows:
                fh.write(ln + '\n')
    first = next(iter(files))
    with gzip.open(os.path.join(dest, first + '.1.gz'), 'wt', encoding='utf-8') as g:
        g.write('%s xcp01 info old rotated line\n' % time.strftime('%b %d %H:%M:%S', time.gmtime(start - 86400)))
    os.makedirs(os.path.join(dest, 'commands'), exist_ok=True)
    with open(os.path.join(dest, 'commands', 'xe_sr_list.txt'), 'w') as fh:
        fh.write('uuid ( RO)   : 0a1b2c3d\nname-label ( RW): Local storage\n')
    return dict(expect=sc['expect'], issue=sc['issue'], anchor=anchor, min_rank=sc['min_rank'])


def iso(ts, ms=123):
    return time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts)) + '.%03dZ' % ms


def pack(src_dir, out_path, fmt, inner_name='bundle'):
    """fmt: dir | zip | tgz | nested (tgz inside zip)"""
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
