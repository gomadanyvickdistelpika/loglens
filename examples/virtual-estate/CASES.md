# Virtual estate: six fault-injected support bundles

Fictional client **Brightwater Logistics Ltd (fictional)**: XCP-ng pool Brightwater-DUB (xcp-dub-01 master, xcp-dub-02) + Xen Orchestra xoa-dub-01, an iSCSI SAN and an NFS NAS. All data is synthetic (documentation IP ranges, `.example` names).

Rebuild: `python tools/build_virtual_estate.py examples/virtual-estate`. Analyse: `python -m lvx analyze BW-01-sr-full.tgz --issue "<issue>" --time <time> --format html -o r.html`.

## BW-01-sr-full  (BW-0001)

- **Customer issue:** ERP database VM erp-db01 will not start after last night's backup, and the nightly backup failed for several VMs
- **Incident time:** `2026-11-12T02:14:00Z`
- **LogLens should rank first:** `xcp.sr_full`
- **Also expected:** `xcp.coalesce_stuck`, `xcp.vm_start_fail`, `xcp.sr_chain`, `xcp.xo_backup`
- **Confirmed cause:** The iSCSI SAN LUN (iSCSI-SAN01-LUN3) reached 100%. Coalesce cannot run without free space, so the VHD chain grows and VM.start / backups fail.
- **Confirm it by hand** (from the extracted bundle folder):

```sh
grep -h "insufficient free space\|SMGC\|SR_BACKEND" xcp-dub-01/var/log/SMlog xcp-dub-01/var/log/xensource.log | sort
grep -h "physical utilisation high" xcp-dub-01/var/log/SMlog   # the SAN LUN has been filling for 6 hours
grep -h "VDI_IO_ERROR" xoa-dub-01/xo/journalctl-xo-server.txt   # backups fail because of the SR, not XO
```

## BW-02-ha-fence  (BW-0002)

- **Customer issue:** Host xcp-dub-02 rebooted by itself at about 14:31 and its VMs were restarted on the other host
- **Incident time:** `2026-11-13T14:31:00Z`
- **LogLens should rank first:** `xcp.ha_fence`
- **Also expected:** `xcp.master_unreachable`
- **Confirmed cause:** Both bond0 uplinks of xcp-dub-02 went down (switch/cable). XCP-ng HA lost network and storage heartbeat and fenced the host, as designed; VMs restarted on xcp-dub-01.
- **Confirm it by hand** (from the extracted bundle folder):

```sh
grep -h "bond0\|NIC Link" xcp-dub-02/var/log/kern.log   # both uplinks dropped first
grep -h xhad xcp-dub-02/var/log/xha.log   # heartbeat lost -> self-fencing
grep -h "not responding\|HA: restarting" xcp-dub-01/var/log/xensource.log
```

## BW-03-dom0-disk-full  (BW-0003)

- **Customer issue:** Xen Orchestra shows host xcp-dub-01 as disconnected and xe commands hang
- **Incident time:** `2026-11-14T22:50:00Z`
- **LogLens should rank first:** `xcp.host_disk_full`
- **Also expected:** `xcp.xapi_down`
- **Confirmed cause:** /var/log on xcp-dub-01 filled (SM log spam), so xapi cannot write and keeps crashing; XO sees ECONNREFUSED. Free space, then restart the toolstack.
- **Confirm it by hand** (from the extracted bundle folder):

```sh
grep -h "Disk Usage for Control Domain\|No space left" xcp-dub-01/var/log/xensource.log xcp-dub-01/var/log/messages
grep -h "xapi.service" xcp-dub-01/var/log/daemon.log   # restart loop, then refuses to start
cat xcp-dub-01/commands/df_-h.txt   # /var/log is 100%
```

## BW-04-nfs-outage  (BW-0004)

- **Customer issue:** All VMs on the NFS storage froze around 11:07 and the NAS SR shows as unplugged
- **Incident time:** `2026-11-15T11:07:00Z`
- **LogLens should rank first:** `xcp.sr_unplugged`
- **Also expected:** `xcp.mount_stall`, `xcp.xo_backup`
- **Confirmed cause:** The NAS (nas01) stopped answering NFS for ~9 minutes. tapdisk tasks hung in the kernel, the SR PBD failed to plug and backups to the NAS remote failed.
- **Confirm it by hand** (from the extracted bundle folder):

```sh
grep -h "nfs: server\|blocked for more than" xcp-dub-01/var/log/kern.log
grep -h "Stale file handle\|PBD_PLUG_FAILED\|SR_BACKEND_FAILURE_47" xcp-dub-01/var/log/SMlog xcp-dub-01/var/log/xensource.log
grep -h "unreachable" xoa-dub-01/xo/journalctl-xo-server.txt
```

## BW-05-dom0-oom  (BW-0005)

- **Customer issue:** xcp-dub-01 dropped out of Xen Orchestra at 05:40 and a VM could not be started afterwards
- **Incident time:** `2026-11-16T05:40:00Z`
- **LogLens should rank first:** `xcp.dom0_oom`
- **Also expected:** `xcp.xapi_down`, `xcp.vm_no_memory`
- **Confirmed cause:** dom0 ran out of memory; the kernel OOM-killer killed xapi. The toolstack restarted but memory is still exhausted, so later VM.start fails with HOST_NOT_ENOUGH_FREE_MEMORY. Raise dom0 memory.
- **Confirm it by hand** (from the extracted bundle folder):

```sh
grep -h "oom-killer\|Out of memory\|Killed process" xcp-dub-01/var/log/kern.log
grep -h squeezed xcp-dub-01/var/log/messages   # dom0 memory pressure for hours
cat xcp-dub-01/commands/free_-m.txt   # 38 MB free, swap exhausted
```

## BW-06-xoa-disk-full  (BW-0006)

- **Customer issue:** Nightly backups failed on the Xen Orchestra appliance and the appliance cannot update itself
- **Incident time:** `2026-11-17T03:15:00Z`
- **LogLens should rank first:** `xcp.xo_disk_full`
- **Also expected:** `xcp.xo_backup`, `xcp.xoa_update`
- **Confirmed cause:** The XO appliance's own backup/data volume is full, so backup writes (ENOSPC) and the updater fail. Not a host or storage problem: prune old backups or grow the volume.
- **Confirm it by hand** (from the extracted bundle folder):

```sh
grep -h "ENOSPC\|no space\|is full" xoa-dub-01/xo/journalctl-xo-server.txt xoa-dub-01/xo/xoa-updater.log
cat xoa-dub-01/commands/df_-h.txt   # /var/lib/xo-server is 100%
grep -h "filesystem /var/lib/xo-server" xoa-dub-01/var/log/syslog   # 71% -> 83% -> 94% earlier
```
