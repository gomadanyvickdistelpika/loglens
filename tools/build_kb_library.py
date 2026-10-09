"""Regenerates lvx/kb_library.json.  The library is a SNAPSHOT of Broadcom KB research (summaries of knowledge.broadcom.com
search results), NOT article text.  Edit the data below (or add entries through LVX_KB_FILE) and re-run:
    python tools/build_kb_library.py
Rules: only put in `resolution` what a KB summary actually stated.  If only the title is known, leave `resolution` empty."""
import json
import os

RESEARCHED = '2026-10-09'


def A(i, title):
    return dict(id=str(i), title=title)


E = []


def kb(topic, rules, articles, cause='', resolution=(), match=None, notes='', basis='summary', priority=0):
    E.append(dict(topic=topic, priority=priority, rules=list(rules), match=match, articles=articles, cause=cause,
                  resolution=list(resolution), notes=notes, basis=basis))


# ----------------------------------------------------------------------------- ESXi: crashes / hardware
kb('PSOD in VMFS operations (#PF Exception 14, ESXi 8.0.1)', ['esx.psod'], [A(381540, 'ESXi 8.0.1 Host Experiences Purple Screen of Death (PSOD) with Page Fault Exception During VMFS Operations')],
   'Race condition in VMFS resource management under intensive I/O on VMFS-6 volumes.',
   ['Update to ESXi 7.0 Update 3o or 8.0 Update 2 or later.', 'If you cannot patch yet, reduce concurrent I/O on the affected volumes.'], match=r'vmfs')
kb('PSOD with nfnic driver in the backtrace', ['esx.psod'], [A(317954, 'ESXi experiences PSOD (purple screen of death) due to nfnic driver')],
   'Storage driver (nfnic) defect, seen on ESXi 6.7.', ['Upgrade the nfnic driver to 4.0.0.24 (from the hardware vendor).', 'Workaround: put initiators in different zones.'], match=r'nfnic')
kb('PSOD in the usbus world (USB passthrough)', ['esx.psod'], [A(420938, 'ESXi host is failing with a Purple Diagnostic Screen (PSOD) displaying "PF Exception 14" within the usbus world while utilizing USB passthrough')],
   'A USB device failing or timing out during passthrough.', ['Identify the faulty USB device (VM settings) and replace it.'], match=r'usbus')
kb('PSOD with NMI on HPE ProLiant Gen8', ['esx.psod'], [A(317547, 'ESXi host fails with intermittent NMI PSOD (purple screen of death) on HP ProLiant Gen8 servers')],
   'Intel IOMMU interrupt remapper change in certain 5.5/6.0/6.5 builds; may also be a hardware problem.',
   ['Move the high-performance PCIe card to a different slot, or re-enable the remapper: esxcli system settings kernel set --setting=iovDisableIR -v FALSE, then reboot.', 'Contact the hardware vendor if it persists.'], match=r'\bNMI\b')
kb('PSOD during PXE boot (boot.cfg module order)', ['esx.psod'], [A(398530, 'ESXi encounters a purple screen of death (PSOD) during PXE boot. #PF Exception 14 in world #####:bootstrap')],
   'Modified boot.cfg with module order different from the official ISO.', ['Make the modules= order in the PXE image boot.cfg match the official ESXi ISO.'], match=r'bootstrap')
kb('PSOD with UEFI secure boot and a wrong clock', ['esx.psod'], [A(382784, 'ESXi PSOD (purple screen of death) when UEFI secure boot is enabled and system time is incorrect')],
   'Wrong system time with secure boot enabled.', ['Set the same, correct time in UEFI/BIOS and in ESXi, then re-enable secure boot.'], match=r'secure ?boot')
kb('PSOD NUMASched_PageNum2PhysicalDomain / vMotionRecv_ReadCompletePages', ['esx.psod'], [A(318449, 'ESXi 7.0 and 8.0 host fails with a purple diagnostic screen that includes "NUMASched_PageNum2PhysicalDomain" and "vMotionRecv_ReadCompletePages" in the backtrace')],
   match=r'NUMASched_PageNum2PhysicalDomain|vMotionRecv_ReadCompletePages', basis='title')
kb('Machine Check Exception (MCE) PSOD - hardware fault', ['esx.mce', 'esx.psod'],
   [A(372284, 'Host halts with a purple diagnostic screen (PSOD) referencing Machine Check Exception (MCE)'), A(367928, 'Machine Check Error (MCE) output decoding after ESXi panic'),
    A(336323, 'Hardware faults on ESXi hosts'), A(414451, 'Machine Check Exception (MCE) causing PSOD on ESXi 8.x')],
   'ESXi treats a critical/uncorrectable machine check as unrecoverable; Broadcom guidance is that an MCE that reaches the purple screen points to hardware, not software.',
   ['Capture the purple-screen output, then reboot.', 'Pull the BMC (iLO/iDRAC/CIMC) System Event Log and look for uncorrectable memory or CPU bank errors; identify the failing DIMM/CPU.',
    'Contact the server vendor with the MCE data and IPMI/SEL logs; confirm BIOS/firmware match the VMware Compatibility Guide.', 'A reboot only helps if the trigger was transient; a recurring MCE needs part replacement or firmware work.'],
   match=r'machine check|\bMCE\b|uncorrectable|hardware error')
kb('PSOD from a hardware memory error (ApeiPageRetire)', ['esx.mce', 'esx.psod'], [A(441389, 'ESXi Host Experiences PSOD - NMI IPI: Panic requested by another PCPU due to Hardware Memory Error (ApeiPageRetire)')],
   match=r'Apei|PageRetire', basis='title')

# ----------------------------------------------------------------------------- ESXi: storage
kb('Permanent Device Loss / All Paths Down', ['esx.apd'],
   [A('legacy:2004684', 'Permanent Device Loss (PDL) and All-Paths-Down (APD) on host'), A(413706, 'vCenter is inaccessible and datastores have size of 0'),
    A(342615, 'Restarting management agents in an All-Paths-Down condition in ESXi fails with the error: Not all VMFS volumes were updated; the error encountered was No connection')],
   'Host lost all paths to a device. The fix belongs at the array / fabric / HBA layer; sense 0x5 0x25 0x0 signals PDL (ESXi stops retrying).',
   ['Restore stable connectivity at the hardware level first (array, FC zoning/switch, cabling, HBA).', 'Then reboot each affected host to clear leftover references to the APD device.',
    'Before rebooting you can try to free the device: list the worlds holding it open, force-kill VM processes, run a dead-path rescan. A core system process holding the volume cannot be stopped, so a reboot is the only option then.'])
kb('APD not triggered / recurring APD behind IBM SVC', ['esx.apd'], [A(338053, 'All Paths Down (APD) is not triggered for LUNs behind IBM SAN Volume Controller (SVC)')],
   'APD condition not detected for LUNs behind IBM SVC.', ['Set /Scsi/ExtendAPDCondition to 1 (off by default; added in ESXi 6.5 P03 and 6.7 U1), or apply the IBM APAR HU01839 fix.'], match=r'SVC|IBM')
kb('Interpreting SCSI sense codes (H:/D:/P: and sense triplets)', ['esx.scsi_sense'], [A(337796, 'Interpreting SCSI sense codes in VMware ESXi'), A(413628, 'Frequent ScsiDeviceIO failed logs on vmkernel logs of ESXi')],
   'H: = host status (0x1 lost connection to LUN, 0x5 reset, 0x8 HBA driver aborted I/O); D:0x2 = CHECK CONDITION; "Valid sense data" is sense key / ASC / ASCQ.',
   ['Decode the triplet against the T10 SCSI standard; 0x4 0x44 0x0 is a hardware error (internal target failure) - involve the storage vendor.',
    '0x5 0x20 0x0 (invalid command opcode) can be informational from the SAN, per Broadcom.', '0x5 0x25 0x0 (logical unit not supported) means PDL.'])
kb('Device latency "performance has deteriorated"', ['esx.latency'], [A(318927, 'ESXi device latency with "performance has deteriorated" messages in ESXi host logs'), A(394192, 'High VM I/O workload and IOPS latency validation on ESXi hosts'),
                                                                     A(392787, 'The ESXi host experiencing latency and intermittent APDs on NFS datastores')],
   'ESXi only reports the latency (DAVG in esxtop); typical causes are target changes, disk/media failure, device overload, failover, or scheduled backups/replication.',
   ['Use esxtop (DAVG vs KAVG) to see whether the delay is on the device or in the host.', 'Check the longer the gap between "deteriorated" and "improved" entries, the larger the VM impact.',
    'If sustained, check array logs and engage the storage vendor; if it lines up with scheduled jobs, reschedule that load.'])
kb('Lost access to volume / VMFS heartbeat timeouts', ['esx.vmfs_lock', 'esx.apd'],
   [A(318897, 'Understanding lost access to volume messages in ESXi'), A(326437, 'ESXi host loses connectivity to a VMFS datastore'), A(396366, 'Lost access to volumes correlated with FC driver aborts'),
    A(410368, 'VM Unresponsive Due to Datastore Connectivity and I/O Stalls')],
   'A host writes a VMFS heartbeat about every 3 s; if it does not complete within ~16 s the datastore is taken offline and "Lost access to volume" is logged. It returns when a heartbeat completes.',
   ['Check hostd.log, vobd.log and vmkernel.log around the time of the event.', 'Verify path/fabric health: for FC confirm driver and firmware are supported; for iSCSI check MTU consistency and the network path.',
    'Engage the storage/fabric vendor for I/O aborts or array-side faults; VMFS recovers automatically once heartbeats succeed.'],
   notes='Related KB results also describe ATS-heartbeat false miscompares fixed by setting /VMFS3/UseATSForHBOnVMFS5 to 0 on all hosts sharing the datastore (not on vSAN) - confirm in the article before applying.')
kb('NFS datastore connectivity / mount problems', ['esx.nfs', 'esx.apd'],
   [A(323107, 'Troubleshooting NFS datastore connectivity issues'), A(310920, 'NFS Datastore Fails to Mount with error "The NFS server denied the mount request"'), A(344470, 'Remounting a disconnected NFS datastore from the ESXi host'),
    A(377606, 'NFSv3 datastores fail to mount following reboot of ESXi 8.0 U2 hosts')],
   'Network path, host firewall, export permissions or stale state after an APD.',
   ['Check MTU on the NFS VMkernel port group and test with vmkping (-s for jumbo); confirm TCP 2049 with nc.', 'Check the host nfsClient firewall rule; check export permissions allow the host IP/subnet.',
    'Stale after APD ("name already exists"): unmount, reboot affected hosts, remount. Same IP on a replacement NFS server also needs a host reboot.',
    'Remove/re-add: esxcli storage nfs list / remove -v <name> / add; fallback esxcfg-nas -d if busy.', 'ESXi 8.0 U2 NFSv3 mount-after-reboot issue is resolved in 8.0 U3.'])

# ----------------------------------------------------------------------------- ESXi: network
kb('Uplink redundancy lost / vmnic link down', ['esx.nic_down'],
   [A(426494, 'Network uplink redundancy lost due to vmnic# down'), A(410676, 'ESXi host displays "Uplink redundancy lost" alert in vCenter due to CRC errors on the NIC'), A(413302, 'ESXi host reports repeated vmnic linkstate down/up events for a physical uplink'),
    A(324496, 'Setting link state up or down for a vmnic interface on ESXi')],
   'vobd "Failed criteria: 128" = driver reports link down: unplugged cable, shut switchport (or loop protection such as Cisco EDPL), or if unintended a driver/firmware/SFP/cable/port fault.',
   ['If flapping, check CRC errors: esxcli network nic stats get -n vmnicX; inspect SFP seating, optics, cable path and switch port counters.',
    'Test stability: esxcli network nic down -n vmnicX then up; if still down, contact the hardware vendor.', 'Verify NIC driver and firmware against the VMware Compatibility Guide.'])
kb('Intel X710 (i40en) NIC flapping', ['esx.nic_down', 'esx.nic_hang'], [A(436585, 'NIC Flapping and "Lost Uplink Redundancy" on ESXi nodes with Intel X710 (i40en)')],
   'Driver/firmware interoperability conflict (cable swaps did not help).', ['Verify i40en driver and NIC firmware against the HCL and align them.'], match=r'i40en')
kb('qedentv (QLogic/Marvell) NIC resets / redundancy lost', ['esx.nic_down', 'esx.nic_hang'], [A(443561, 'vCenter Server and ESXi hosts report "Network redundancy lost" on adapters using the qedentv driver')],
   'NIC firmware resets (uplink-reset and firmware-dump entries in vmkernel.log).', ['Align driver and firmware with the latest certified releases and engage the hardware vendor.', 'Workaround: set en_periodic_stats=0 on the qedentv module and reboot.'], match=r'qedentv')
kb('bnxtnet (Broadcom NIC) TX timeout / PSOD', ['esx.nic_hang', 'esx.nic_down', 'esx.psod'], [A(429581, 'vmnic flaps and Tx Timeout observed on Broadcom bnxtnet driver.'), A(427648, 'ESXi Purple Screen of Death (PSOD)/network connectivity loss on Broadcom NICs due to bnxtnet driver TX timeout')],
   'bnxtnet 230.0.136.0 TX-timeout defect; bnxtnet older than 234.x with newer firmware can PSOD.', ['Upgrade the bnxtnet driver and firmware together to a compatible supported pair.', 'Check versions: esxcli software vib list | grep bnxtnet; esxcli network nic get -n vmnicX.'], match=r'bnxtnet')
kb('Intel ixgben TX hang / link down', ['esx.nic_hang', 'esx.nic_down'], [A(407843, 'WARNING: ixgben: ixgben_CheckTxHang: TX hang detected on TX queue ESXi 8.0'), A(411106, 'Intel NIC occasionally experiences link down issues after upgrading ixgben driver to version 1.19.3.0 or 1.20.2.0')],
   'TX hang is a NIC hardware condition the driver can only work around with a reset; ixgben 1.19.3.0 / 1.20.2.0 were linked to TX hangs and link-downs.', ['Upgrade to ixgben 1.22.1.0.', 'For persistent cases work with the driver/firmware vendor and verify against the VMware Compatibility Guide.'], match=r'ixgben')
kb('"Queue 0 of device vmnicX stuck, resetting the device"', ['esx.nic_hang'], [A(387420, 'ESXi vmnic link state flapping with the error - "Queue 0 of device vmnicX stuck, resetting the device"')], match=r'stuck, resetting', basis='title')

# ----------------------------------------------------------------------------- ESXi: management / HA / vSAN
kb('Restarting ESXi management agents', ['esx.hostd', 'esx.vpxa', 'vc.host_disc'], [A(320280, 'Restarting Management Agents in ESXi'), A(344682, 'ESXi host not responding or disconnected - VMware vSphere')],
   'Standard first action when hostd/vpxa are hung - but check for a storage or third-party cause first or the hang returns.',
   ['Restart via the Host Client (Manage > Services) or SSH: /etc/init.d/hostd restart then /etc/init.d/vpxa restart; wait 1-2 minutes, confirm the host returns to Connected.',
    'Do not use services.sh restart / the DCUI option on hosts with shared graphics (vGPU/vDGA/vSGA).', 'Before restarting check vSAN (esxcli vsan cluster get), LACP status and NSX VIBs.',
    'If SSH is unavailable or services keep hanging, cold reboot via iLO/iDRAC (avoid force reboot on vSAN hosts if a graceful shutdown is possible).'])
kb('hostd/vpxd "Panic: Memory exceeds hard limit"', ['esx.hostd', 'esx.oom', 'vc.vpxd_crash', 'vc.oom_kill'],
   [A(318440, 'ESXi host goes not responding in vCenter and hostd crashes with error "Panic: Memory exceeds hard limit"'), A(318013, 'ESXi 7.0 host goes not responding in vCenter and hostd.log reports "SetVigorNotificationTime: Not connected"'),
    A(379179, 'vpxd Crashes with a "Panic: Memory exceeds hard limit."'), A(369160, 'VPXD service crashes unexpectedly - panic: memory exceeds hard limit')],
   'ESXi 6.5/6.7: failed hash check on the VMware Tools ISO leaks memory (fixed in 6.5 P05 / 6.7 P02). ESXi 7.0: race between VM power-off and Vigor callbacks. vpxd: monitoring/backup tools create ContainerViews/filters and never destroy them.',
   ['ESXi 6.5/6.7: patch to 6.5 P05 / 6.7 P02, or replace /productLocker/vmtools/ with a copy from a healthy host on the same build (verify checksums) and restart management agents.',
    'ESXi 7.0: restarting hostd clears it temporarily but high CPU returns - check the article for the fixed build.', 'vCenter: increase vpxd heap as a workaround and find/stop the tool leaking sessions/views (e.g. a vROps NSX-vSphere adapter, which has no permanent fix).'],
   match=r'hard limit|Memory exceeds|Vigor')
kb('hostd "Too many open files"', ['esx.hostd'], [A(414769, 'ESXi host was not responding as "Too many open files" with hostd')],
   'A backup or vCenter task holding many VMDK handles.', ['Restart management agents to restore access, and find/stop the task holding the files.'], match=r'Too many open files')
kb('hostd hung after storage outage / FCoE timeouts', ['esx.hostd', 'esx.vpxa'], [A(434836, 'ESXi Host Hangs and Disconnects from vCenter Due to FCoE Storage Timeouts'), A(391818, 'ESXi host is not responding while VMs are running following a recovery from a storage outage')],
   'Severe storage latency/connectivity loss blocks hostd threads indefinitely.', ['Fix the storage path first, then restart the management agents.'], match=r'FCoE|APD|storage|Lost access')
kb('Host "Not Responding" in vCenter - heartbeat / vpxa binding', ['esx.vpxa', 'vc.host_disc'],
   [A(318647, 'ESXi host disconnects intermittently from vCenter Server'), A(399108, 'ESXi hosts intermittently show as "Not Responding" in vCenter Server due to vpxa heartbeat binding errors'),
    A(414524, 'ESXi Hosts Entering "Not Responding" State Every 60 Seconds Due to Incorrect UDP Port Configuration in vpxd.cfg'), A(306918, "ESXi host disconnects from vCenter Server with the error: Agent can't send heartbeats because socket address structure initialization is failing")],
   'vCenter expects a UDP 902 heartbeat from each host (about every 10 s, 60 s window). Causes: stale management IP in the vCenter DB (vpxa bind Error 99), wrong VirtualCenterManagedIP, lost UDP 902 (firewall/ACL), wrong heartbeat port in vpxd.cfg (120 instead of 902), switch reboot, DNS failure.',
   ['Wrong IP in VCDB: stop vpxd, correct the host entry in the database, start vpxd (use Broadcom guidance/support).', 'Trace heartbeats: pktcap-uw on the host and tcpdump on vCenter to see where UDP 902 stops; check firewalls/ACLs.',
    'Check udp-port in vpxd.cfg is 902 (fix is on the vCenter side).', 'Verify the host can resolve the vCenter name (getaddrinfo errors in vpxa logs).', 'Last resort: remove the host from inventory and re-add it.'])
kb('vSphere HA stuck in "Election" / HA agent unreachable', ['esx.fdm', 'vc.drs_ha'],
   [A(334269, 'vSphere HA Configuration stuck in "Election" state, fails with "HA Agent Unreachable" or "Operation Timed out" in vCenter Server'), A(345414, 'HA configuration is stuck at the "Election" state and doesn\'t proceed further for a set of hosts.'),
    A(438412, 'vSphere HA configuration fails with host state stuck in Election'), A(324992, 'Determining if your VMware vSphere HA cluster has experienced a host failure')],
   'Causes reported: MTU mismatch between VMkernel adapter and vSwitch; changed host certificate/thumbprint not refreshed in vCenter; a staged patch/pending reboot blocking FDM agent replacement; an unresponsive host; missing HA network path on vSAN.',
   ['Check /var/log/fdm.log on the host and the master for election errors; an isolated host elects itself master and pings isolation addresses.', 'MTU: match switch MTU to the VMkernel adapter, validate with jumbo vmkping, then Reconfigure for vSphere HA.',
    'Thumbprint: disconnect and reconnect the affected hosts (a reboot or service restart does not refresh it).', 'Pending reboot: reboot affected hosts, exit maintenance mode, re-enable HA.', 'Fix any "Not Responding" host first; confirm DNS and NTP; Reconfigure HA; toggling HA off/on is the last resort.'])
kb('"Cannot find vSphere HA master agent" after vCenter upgrade / revert', ['esx.fdm', 'vc.drs_ha'], [A(444836, 'Error: "Cannot find vSphere HA master agent" and Looping HA Configuration Tasks After vCenter Server Upgrade'),
   A(449121, '"vCenter Server is unable to find a master vSphere HA agent" for cluster after vCenter upgrade or snapshot revert'), A(434999, 'After vCenter 8.0 U3i Patch: "Unable to find a master vSphere HA agent in cluster"')], match=r'master', basis='title')
kb('vSphere HA agent configuration errors (VIB / image-based clusters)', ['vc.drs_ha'],
   [A(324583, 'Cannot complete the configuration of the vSphere HA agent on the host. "Applying HA VIB\'s on the cluster encountered a failure"'), A(384913, '"Cannot complete the configuration of the vSphere HA agent on the host. Setting desired image spec for cluster failed"'),
    A(318765, 'Enabling vSphere HA might fail or never complete on hosts with ESXi 7.0u2c/u2d and 7.0u3/u3a'), A(422190, 'HA configuration fails after vCenter upgrade')],
   'Variants: vsphere-fdm listed as a Component instead of a Solution in a vLCM image; Hardware Support Manager not configured; slow datastore enumeration hitting vpxd 15-min limit; LUN not presented to every host; duplicate i40en/i40enu VIBs (ESXi 7.0 U2c-U3a); failing boot disk.',
   ['Image-based cluster: export the cluster image as JSON, remove the FDM component and reimport (no reboot needed).', 'Configure the Hardware Support Manager or remove the firmware/driver add-on, then re-run compliance.',
    'Timeouts: set HA advanced option das.remediateHATaskTimeoutSecs=1800; check time esxcli storage filesystem list.', 'ESXi 7.0 U2c-U3a: upgrade to 7.0 U3c or remove the obsolete i40enu VIB (HA disabled, maintenance mode).'], match=r'VIB|image spec|Applying HA|configuration of the vSphere HA agent')
kb('vSAN disk group unhealthy / log congestion (DDH)', ['esx.vsan'],
   [A(418349, 'Virtual machines in the vSAN cluster are reporting as invalid - log congestion reported on vSAN diskgroup'), A(318127, 'vSAN IO operations buildup leading to LogCongestion'), A(438445, 'vSAN Disk Group shows as unhealthy and cache disk shows as evacuated'),
    A(326878, 'Dying Disk Handling (DDH) in vSAN'), A(318125, 'vSAN nodes experience LSOM Memory congestion due to high "Number of elements in commit tables"')],
   'Dying Disk Handling marks a disk group unhealthy on sustained high latency or maximum log congestion and starts evacuating it.',
   ['Log-congested disk group: remove it from the vSAN cluster and add it back; or maintenance mode (Ensure Accessibility), reboot, rebuild; if it stays unhealthy treat as hardware failure and replace.',
    'If removal hangs because DDH is also unmounting the disk, reboot the host, then remove it.', 'LSOM memory congestion (high commit-table counts): unmount/remount each affected disk group host by host, highest counts first (review scrubber settings in the KB).',
    'Check inaccessible swap objects before assuming the disk is the only problem; review vobd and vsandevicemonitord logs.'])
kb('vSAN ramdisk "vsantraces" full', ['esx.ramdisk'], [A(326990, "vSAN -- Error: The ramdisk 'vsantraces' is full on ESXi")], 'No persistent scratch location: traces exhaust the 300 MB ramdisk.',
   ['Check esxcli system visorfs ramdisk list.', 'Limit trace size or redirect traces to a datastore.'], match=r'vsantraces')
kb('ESXi upgrade/patch "No space left on device" (stagebootbank / locker)', ['esx.ramdisk'],
   [A(318663, 'No space left on device while upgrading ESXi with esxcli'), A(322322, 'Error 28: No space on device, While upgrading ESXi host'), A(313531, 'ESXi upgrade failure due to insufficient memory available to create ramdisk stagebootbank'),
    A(373343, 'An error occurred during host configuration: /usr/sbin/esxupdate returned with exit status: 15')], 'Staging ramdisk or /locker out of space during an ESXi update.',
   ['Free space in the staging ramdisk / locker, put the host in maintenance mode and retry (see the article for your update method).'], match=r'upgrad|stagebootbank|esxupdate|bootloader|locker', basis='summary')

# ----------------------------------------------------------------------------- common: time, DNS, certs, auth
kb('NTP / time synchronisation (host and vCenter)', ['esx.ntp'],
   [A(312204, 'Troubleshooting NTP on ESX and the ESXi 7.x / 8.x.'), A(384769, 'Unable to add ESXi host to vCenter with error: "Unable to push signed certificate to host"'), A(321371, 'Firstboot fails when upgrading vCenter Server Appliance due to time synchronization issue')],
   'A wrong clock makes vCenter-pushed certificates look "not yet valid" and breaks certificate/SSO/AD operations and upgrade firstboot.',
   ['Compare the host clock (date) with network time; use the same NTP servers on all hosts and vCenter (Configure > System > Time Configuration); a manual set first can help.', 'Allow 1-15 minutes to converge; confirm the NTP service is running and UDP 123/DNS/firewall are open.',
    'NTPv3 source vs ESXi NTPv4 default: set the version in /etc/ntp.conf.', 'For upgrade firstboot failures ensure the target ESXi host is NTP-synchronised, then retry.'])
kb('vCenter / AD join failures from clock skew', ['esx.ntp', 'vc.sso'], [A(373032, 'vCenter Appliance fails to join AD domain due to clock skew'), A(430310, 'vCenter disconnects from Active Directory following a reboot due to host time skew'), A(336021, 'Detected system clock skew between this node and the vCenter Single Sign-On')],
   'Host time skew (including VM-level tools time sync at start-up) breaks AD/SSO authentication.', ['Correct host time/NTP; if DRS moves vCenter between hosts with different time, set automation to Manual for that cluster; check VM Tools time sync settings.'], match=r'Active Directory|\bAD\b|skew|domain')
kb('Name resolution failures (DNS)', ['esx.dns'],
   [A(404851, 'vCenter Shows Host Status is Unknown During NSX Prep with vLCM'), A(322317, '"Host cannot download files from VMware vSphere Update Manager patch store." on an ESXi host'), A(401175, 'Error fetching certificate(s) in vCenter UI Certificate Manager after replacing certificate'),
    A(398402, 'VDT logs for vCenter show [FAIL] SSL Connectivity - Investigate error: [vc:443]:[Errno -2] Name or service not known')],
   'Faulty/missing DNS on the host, or missing forward/reverse records for vCenter.',
   ['Run nslookup for the vCenter FQDN and IP from both vCenter and the affected host: a failure on the host = host DNS settings; on vCenter = resolver config or missing records.', 'Verify the DNS server in the host management network settings, restart the management network.',
    'Add any missing A/PTR records (forward and reverse are required), then restart vCenter services.', 'vCenter resolv.conf with no search domain: set via vami_config_net (VAMI only exposes DNS servers).'])
kb('Expired / invalid vCenter and ESXi certificates', ['esx.cert', 'vc.503', 'vc.sso'],
   [A(344201, 'Error: "no healthy upstream" or "503 Service Unavailable" when accessing vCenter Server (verify and resolve expired vCenter certificates)'), A(413685, 'vSphere Client reports "no healthy upstream" due to expired certificates'),
    A(396907, 'Machine SSL certificate replacement and auto-renewal in vCenter Server 8.x'), A(440277, 'vCenter certificate replacement fails at 85% with rollback using certificate-manager')],
   'MACHINE_SSL, STS or Solution User certificate (or an issuer) is past its validity.',
   ['Confirm expiry: list each VECS store with vecs-cli and read the Not After dates.', 'Replace with vCert.py (Option 3 Manage certificates > Option 1 Machine SSL, VMCA-signed) or Certificate Manager; take a snapshot first (all nodes in Enhanced Linked Mode); restart services.',
    'ESXi host cert: Configure > Certificates > Renew; for HA clusters set vpxd.certmgmt.mode=vmca.', 'vCenter 8.0 U3h+ with vpxd.certmgmt.mode=vmca renews Machine SSL automatically 5 days before expiry.',
    'If replacement fails at 85%, check the PNID vs certificate FQDN (case-sensitive). A thumbprint mismatch with no expiry can be an SSL-inspecting firewall.'], match=r'expire|certificate|ssl|verify failed|not valid')
kb('ESXi root lockout / "Cannot login user root@127.0.0.1: no permission"', ['esx.auth'],
   [A(340038, "ERROR: Remote access for ESXi local user account 'root' has been locked for 120 seconds"), A(424130, 'ESXi Root Account Lockouts and Configuration Alerts in HPE Alletra/Nimble Environments'),
    A(319996, '"Cannot login user root@127.0.0.1: no permission" in ESXi host events when lockdown mode is enabled on ESXi'), A(378651, 'ESXi Displays Repeated "Cannot Login User root@127.0.0.1: No Permission" Events After Upgrading to Version 8.0 U3 with Lockdown Mode Enabled')],
   'Two different problems: (1) real lockout from repeated bad root logins (often a third-party service/array with stale credentials); (2) Lockdown Mode denying root@127.0.0.1 sessions - events only, not a lockout.',
   ['Lockout: find the source in hostd.log ("Rejected password for user root" shows the IP) and fix that client; temporary workaround Security.AccountLockFailures=0 weakens protection - restore after.',
    'HPE Alletra/Nimble: apply the vendor patch, make the stored root credential match, clear with pam_tally2 --user root --reset.', 'Lockdown events: add root to the Lockdown Mode Exception Users list; resolved in ESXi 8.0 U3e.'])

# ----------------------------------------------------------------------------- VM level
kb('VM crash / unexpected power-off (vmx signal)', ['esx.vmx_crash'], [A(339691, 'Determining Why a Virtual Machine was Unexpectedly Powered Off, Restarted, or Rebooted'), A(432273, 'Unexpected shut down or crash of the Virtual Machine due to I/O Blockage and Resets.')],
   'Find the evidence in the VM vmware.log ("Caught signal" / "Unexpected signal"); I/O blockage with repeated hard resets is one documented cause.',
   ['Locate the VM working directory (VM Options) and read vmware.log; collect the vmx-zdump core and, if needed, convert a suspended state with vmss2core.', 'If none of the known cases below match, open a Broadcom case with vmx-zdump, vmware.log and an ESXi support bundle.'])
kb('vmx crash during Storage vMotion after guest reboot', ['esx.vmx_crash'], [A(312828, 'Guest OS reset request (reboot) when Storage vMotion task is running may cause the virtual machine to PANIC, and Storage vMotion fails')],
   'Guest reboot during Storage vMotion (signal 11).', ['Power off the VM before starting Storage vMotion.'], match=r'storage vmotion|svmotion')
kb('vmx crash with backup (TSDM / LWD, signal 6/11)', ['esx.vmx_crash'], [A(434693, "Transparent Snapshot Data Mover (TSDM) With LWD causing VM system crash 'Caught signal 6/11 on LWD unstun disk'")],
   'Known issue; Broadcom engineering is aware and a fix is planned. No workaround listed in the summary.', match=r'LWD|TSDM')
kb('vmx PANIC in MKS (VERIFY pollVMX.c)', ['esx.vmx_crash'], [A(394512, 'VM vmx Crash fails with mks - PANIC: VERIFY bora/vmx/main/pollVMX.c:4348')],
   'Fixed in ESX 9.0 / VMRC 13.0.', ['Interim: add ticket.webmks.timeout.seconds = 10 to the VM and restart it.'], match=r'pollVMX|mks')
kb('Snapshot consolidation: "Failed to lock the file"', ['esx.snapshot'],
   [A(374141, 'Snapshot consolidation failure: Failed to lock the file error'), A(372336, '"Virtual machine Consolidation Needed Status" "Unable to access file since it is locked" "Failed to lock the file"'),
    A(313833, 'VMware virtual machine file lock on VMFS datastore'), A(418718, 'Third party backup fail to consolidate snapshot files'), A(402937, 'Virtual machines on NFSv3 datastores might fail due to a failed snapshot consolidation during backup')],
   'Usually a backup proxy (hot-add) still holding the disk; also stale hostd/vpxa descriptors or a lock held by another host after vMotion/HA.',
   ['Find the lock owner: vmfsfilelockinfo -p <vmdk> (vSAN: lsof).', 'Detach the VMDKs from the backup proxy VM - "Remove from virtual machine only", NOT "Delete files from datastore" - outside the backup window; power-cycle the proxy if the lock persists.',
    'If hostd holds the lock, restart hostd/vpxa on that host; host reboot is the last resort.', 'Retry Consolidate. NFSv3 on ESXi 8.0: known race fixed in 8.0 U3e. 255+ redo logs in one branch blocks new snapshots.'])
kb('vMotion "Timed out waiting for migration data"', ['esx.vmotion'],
   [A(324526, 'vMotion of VM fails with error: "Timed out waiting for migration data"'), A(426222, 'Storage vmotion tasks fails with the error "The source detected that the destination failed to resume ...Timed out waiting for migration data."'),
    A(421571, 'VMs using Nvidia Grid vGPU hitting Xids and failing to migrate at 68%')],
   'The destination received no data from the source for the default 120 s.',
   ['Check IP conflicts on the vMotion vmknics; run vmkping for the whole migration (use -s with jumbo frames); verify matching port-group security settings (e.g. promiscuous mode).',
    'Storage vMotion: a PDL on the source datastore needs a host reboot in a maintenance window. vGPU Xid case: fixed from ESXi 8.0 U3h.', 'Look for PDL, Xid or NIC TX-hang messages in vmkernel and vmware.log on both hosts.'])

# ----------------------------------------------------------------------------- vCenter
kb('"No healthy upstream" / 503 - find the real cause', ['vc.503'],
   [A(344201, 'Error: "no healthy upstream" or "503 Service Unavailable" when accessing vCenter Server'), A(405611, '"No Healthy Upstream" Error When Accessing vSphere Client in vCenter Server Due to Datastore Space Constraints'),
    A(416676, 'vCenter UI shows error "No healthy upstream", due to memory contention'), A(407484, 'vCenter Server UI displays "no healthy upstream" due to vpxd service failing to start'), A(423625, 'The vSphere UI is not accessible, displaying "No healthy upstream" and vmware-sps and vmware-vpxd failed to start'),
    A(422821, 'vCenter Server UI unavailable with "No healthy upstream" error and it complains about missing key (__MACHINE_CERT) in STS_INTERNAL_SSL_CERT store')],
   'A generic symptom - the reverse proxy has no healthy backend. Broadcom documents several distinct causes.',
   ['Check vmon/vpxd/sps service status and certificate expiry first.', 'Expired Machine SSL / STS / Solution User certificates: replace with vCert, restart services.', 'Host memory exhausted where vCenter runs: free memory or migrate workloads, then restart.',
    'Full datastore / Photon file-system damage (emergency mode): expand datastore, run fsck.', 'Bad /etc/hosts: re-enter hostname/IP with vami_config_net. Duplicate "useSSL" in vpxd.cfg: remove duplicate. Stale STS_INTERNAL_SSL_CERT store: remove from VECS.',
    'If it persists collect a vc-support bundle and contact Broadcom Support.'])
kb('vpxd crashes (core.vpxd-worker)', ['vc.vpxd_crash'],
   [A(367750, 'vpxd service intermittently crashes with core dump (core.vpxd-worker), causing vCenter server UI will display blank inventory on vSphere 8.0 U1'), A(408747, 'vmware-vpxd service crash with core dump "core.vpxd-worker.#######" on vCenter Server'),
    A(418943, 'vmware-vpxd service crash with core dump "core.vpxd-worker.xxxxxxx" on vCenter Server'), A(318750, '/storage/core Partition Full Due to Core Files in vCenter Server Appliance')],
   'Several documented causes; match the backtrace/log to one.',
   ['Heap exhaustion: add heap (KB 320871) and find monitoring/backup tools making excess sessions/API calls (workaround only).', 'vSphere 8.0 U1 HTTP/2 flaw crash: resolved in 8.0u1c - patch to the latest 8.0u3 build.',
    'Corrupt Host Profile table entries (snapshot first, remove the offending profiles; may recur on another).', 'Duplicate <enabled> tags in vpxd.cfg: back up, remove duplicate, restart.', 'Full /storage/core: df -h /storage/core, remove old core files, restart services.',
    'Check /var/log/vmware/vpxd/vpxd.log for panic/backtrace and vmon.log for core notices; if nothing matches open a Broadcom case with logs.'])
kb('vpxd "Too many outstanding operations" / duplicate VM after Storage vMotion / NVMe disk expand', ['vc.vpxd_crash'],
   [A(318208, 'vCenter Server vpxd service crashes due to "Too many outstanding operations"'), A(401096, 'vmware-vpxd crash after incomplete storage vMotion leaves duplicate, inaccessible VM in vCenter inventory'), A(372225, 'VPXD crashes with core.vpxd-worker after expanding disk size which is configured with NVMe controller on vCenter Server 8.0 U3')],
   'LRO queue overflow fixed in 7.0 U3i; duplicate inaccessible VM left in inventory; NVMe disk-expansion bug fixed in 8.0 U3b.', ['Patch to the fixed build, or remove the stale duplicate VM (contact Broadcom support) and restart services.'],
   match=r'outstanding operations|duplicate|nvme')
kb('vPostgres: "remaining connection slots are reserved"', ['vc.db'], [A(344930, 'Some vCenter Server services fail to start with the error: FATAL: remaining connection slots are reserved for non-replication superuser connections')],
   'All 100 default connection slots in use.', ['Back up /storage/db/vpostgres/postgresql.conf, set max_connections=250, reboot (each slot uses ~400 bytes of shared memory).'], match=r'connection slots|too many (clients|connections)')
kb('VCDB / vPostgres out of disk space', ['vc.db', 'vc.disk_full'],
   [A(410118, 'Error: "No space left on device" when running VCDB commands such as reindex, truncate, and vacuumdb. The vCenter /storage/seat partition is 100% full'), A(318931, '/storage/seat disk 100% full on vCenter Server Appliance 6.x/7.x/8.x'),
    A(387607, '/storage/seat partition filled 100% and unable to perform vacuumdb or truncate the table in vCenter 8.0U3'), A(318880, 'VCSA database storage "/storage/db" is full or nearly full'), A(318134, '"Insufficient free space for the Database" error causes vpxd services to shut down during upgrade failure')],
   'At 95%+ full, vPostgres refuses to create/extend files and vpxd is not allowed to run. Usual /storage/seat trigger is an event flood (e.g. hardware-health alarms from a host).',
   ['Find the noisy source: query VCDB for the largest event/task tables; investigate the host generating the events.', 'Stop vpxd and content library, then truncate the large event/task tables one at a time; use the "Delete old tasks, events and statistics" script (KB 2110031) if needed.',
    'If 100% full, vacuumdb/reindex/TRUNCATE fail for lack of temp space: move old vpostgres table folders to a temp location with symlinks (KB 410118 workaround) or extend the disk first.', 'Last resort: power off, grow the VMDK (no snapshot attached), power on, run /usr/lib/applmgmt/support/scripts/autogrow.sh.',
    '/storage/db full: extend first (cleanup needs overhead), then reclaim bloat with vacuum full (services stopped).', 'Snapshot guidance per 410118: take offline snapshots of linked vCenters (online for standalone) before the first two steps, but not before growing a disk.'],
   match=r'seat|extend file|vpx_|vacuum|/storage/db|database')
kb('VCSA partition full - how to grow a disk', ['vc.disk_full'],
   [A(316602, 'Increasing the disk space for the vCenter Server Appliance in vSphere 6.5, 6.7, 7.0 and 8.0'), A(318953, 'vCenter Server Appliance disk space is full'), A(313077, 'vCenter log disk exhaustion or /storage/log full'), A(409413, 'The log partition size on this vCenter Server is smaller than the recommended 50 GB')],
   'A /storage/* volume or / is at 100%.',
   ['Identify the full volume first: df -h (and df -i for inodes), lsblk; map the device to its SCSI ID in VM Edit Settings.', 'Remove VM snapshots and take a backup; grow the VMDK; run /usr/lib/applmgmt/support/scripts/autogrow.sh; restart services if vpostgres stopped.',
    '/storage/log: look for the largest files/dirs and known log-bloat bugs first; 50 GB is the recommended size from 8.0 U3h.', 'If the extend option is greyed out, snapshots or the datastore max disk size are the usual cause.'])
kb('/storage/log filled by Java heap dumps', ['vc.disk_full', 'vc.oom_kill'], [A(318173, 'vCenter Server Appliance /storage/log partition runs out of space due to VMware Analytics service dump files (analytics/java_pidxxxx.hprof)'), A(375839, 'Resolving /storage/log Disk Space Issues caused by Infraprofile Java Heap Dump Files in vCenter Server'),
   A(393690, 'Resolving /storage/log Disk Space Issues Caused by vmware-cis-license Java Heap Dump Files in vCenter Server')], match=r'hprof|heap dump|java_pid', basis='title')
kb('vCenter upgrade: target /storage/seat too small for the imported data', ['vc.upg_fail', 'vc.upg_sizing', 'vc.disk_full', 'vc.db'],
   [A(322286, "vCenter Appliance Upgrade Fails at Stage 2 (50%) with Error 'A problem occurred while Exporting VMware vCenter Authentication Framework data..'"), A(326287, 'The VCSA Installation wizard incorrectly detects the storage deployment size of the source vCenter during migration or upgrade'),
    A(412941, 'Unable to select the same deployment size when upgrading vCenter Server'), A(404664, 'Disk space discrepancy on vCenter disks after upgrading')],
   'The target lacks space on /storage/seat for all the upgrade data (log typically shows OSError: [Errno 28] in /var/log/vmware/upgrade/upgrade-export.log). The installer sizes the target from the source provisioned space; if the source /storage/seat, /storage/db or /storage/updatemgr is >50% full the wizard can under-size it.',
   ['Re-run Stage 1 and choose the next larger deployment/storage size (the wizard offers only larger sizes when the source provisioned space exceeds the Default storage).', 'Or finish Stage 1 and add about 50 GB to the /storage/seat disk on the new appliance before Stage 2 (snapshot first).',
    'Or truncate large source database tables (events/tasks) and re-run the upgrade.', 'Before choosing, run df -h on the source: if /storage/seat is over half full the sizing can be skewed.', 'If the target size is smaller than the source provisioned size and cannot be selected, deploy a fresh install of the same size and run Stage 2 as an upgrade (KB 412941).'],
   match=r'upgrad|import|firstboot|SEAT|stage|deployment size', priority=5,
   notes='KB 322286 is titled for a Stage 2 (50%) Authentication Framework export failure; the search summaries describe the target /storage/seat shortage under it - read the article to confirm it matches your log.')
kb('vCenter upgrade: source export partition "/" too small', ['vc.upg_fail', 'vc.disk_full'], [A(382898, "Upgrading vCenter Server fails at Stage2 - 'Insufficient space on the source export partition '/' to accommodate all the data for upgrade data'"),
   A(318157, "Upgrade to vCenter 7.0 Update 2 fails at Stage 2 with error The source disk '/' is too small to fit the export requirements.")], 'Export directory on the source / partition is too small.',
   ['Pick a directory with free space (e.g. /storage/core) in the installer "Export directory" field.', '7.0 U2 specific variant: fixed in 7.0 U2c; workaround is to finish the upgrade from the new appliance VAMI on port 5480.'], match=r'export partition|source disk|too small|export', priority=5)
kb('vCenter upgrade: Stage 2 "no space left" can also be an unsupported upgrade path', ['vc.upg_fail', 'vc.upg_sizing', 'vc.disk_full'], [A(407600, 'vCenter upgrade fails in stage 2 on step 3 Import copied data to target vCenter')],
   'The "no space left on device" import error was reported alongside a version mismatch (e.g. upgrading from a newer 7.0 patch to an older 8.0 release).', ['Check the source and target versions against the VMware Interoperability Matrix.'], match=r'import (copied )?data|Import of', priority=5)
kb('vCenter upgrade: vpxd_firstboot failures (causes to check)', ['vc.upg_fail'],
   [A(321336, 'vCenter Server Appliance upgrade from 6.5 To 6.7 fail during "vpxd firstboot"'), A(324989, 'Firstboot Failed during Install, Deployment, Upgrade, or Migration in vCenter Server and vCenter Server Appliance 6.7'),
    A(321371, 'Firstboot fails when upgrading vCenter Server Appliance due to time synchronization issue'), A(370902, 'vCenter upgrade to 8.x fails with a firstboot error due to "RESTART value (XXXXXXXXXX) cannot be greater than MAXVALUE (4294965000)"'),
    A(338851, 'Firstboot fails due to Authentication/Password or Permissions when installing or upgrading or migrating in vCenter Server 6.7 and 7.0'), A(392535, 'The vCenter upgrade failed in Stage 2: content-library-firstboot.py and vdcsvc firstboot failed - already exists')],
   'Several different causes; the real error is in the firstboot logs, not in the installer message.',
   ['Start with /var/log/firstboot/firstbootStatus.json (which step failed) and the matching vpxd_firstboot stderr/stdout logs.', 'vpxd start timeout (default 5 min, 6.5->6.7 case): pause at Stage 1, raise StartTimeout in vpxd.json (300 -> 3000 s), resume Stage 2 - check the path/values apply to your version.',
    'vCenter 8.x DB upgrade failing on event sequence value: stop vpxd, reset the sequence, clean up event tables, restart the upgrade (offline snapshot first).', 'Verify the target ESXi host is NTP-synchronised and DNS records exist (IP-only deployments without DNS are not supported); check SSO password special characters and certificate errors.',
    'No Broadcom rollback procedure for a failed Stage 2 was found in the KBs; the offline snapshot taken before the upgrade is the practical rollback point.'], priority=5)
kb('SSO / STS login failures from expired certificates', ['vc.sso'],
   [A(390983, 'Accessing vCenter Server fails with Error: [400] vCenter SSO authentication request failure due to expired certificates'), A(421381, 'vCenter Server inaccessible due to expired Solution User certificates'), A(436368, 'vCenter Server 400 Single Sign-On Error Failed to Retrieve STS Client'),
    A(338889, '"Signing certificate is not valid" error in vCenter Server 6.5.x and 6.7.x on Windows'), A(322178, 'Error "[500] An error occurred while fetching identity providers" appears while login to vCenter Server UI')],
   'Expired STS signing, Machine SSL or Solution User certificates (vpxd.log "AcquireToken exception ... Invalid credentials").',
   ['Confirm which certificates expired with vCert or vecs-cli.', 'Snapshot first (every node in Enhanced Linked Mode), renew Solution User and STS certificates with vCert (option 6 resets all if several are expired), restart services on every node.'], match=r'sts|token|credentials|solution user|signing|authentication')
kb('vCenter services fail to start (vpxd / vmon)', ['vc.service_down', 'vc.vpxd_crash'],
   [A(345089, 'vCenter server service (vpxd) fails to start after reboot'), A(434860, 'vCenter Server vpxd fails to start after a reboot, patching, or certificate renewal'), A(377224, 'VPXD services fails to start and you see error "service vpxd not found"'),
    A(410324, 'vCenter server services fail to start, vpxd-svcs operation timed out.'), A(389873, 'Many vCenter services are not started due to VCHA settings are still in config file'), A(433481, 'vCenter services fail to start after a failed domain repoint operation')],
   'Several causes; "service-control --start --all" often reports a vpxd timeout while the real error is in vmon.log.',
   ['Read /var/log/vmware/vmon/vmon.log for the first error, then vpxd.log.', 'Duplicate useSSL or malformed XML in /etc/vmware-vpx/vpxd.cfg: back up, fix, restart. Malformed vpxd.json ("service vpxd not found"): restore from a healthy node of the same version.',
    'Expired certificate in the Machine SSL chain: replace it, restart services.', 'After a failed repoint / missing registrations: lsdoctor.py -r then restart.', 'VCHA leftovers: set /storage/vmware-vmon/defaultStartProfile to ALL.', 'Snapshot before editing any config.'])
kb('Lookup Service client errors in vpxd ("LS client adapter")', ['vc.ls_client'],
   [A(80867, 'KB number from the supplied TDLog report (not independently retrieved)'), A(339619, 'vCenter Server 7.0 services fails to start in an EVC enabled cluster'), A(315461, 'lookupsvc or vpxd-svcs fails to start with error'), A(322294, 'vCenter services fail to start due to vpxd error: "Failed to initialize authorizeManager"')],
   'The Lookup Service refused connections. Documented causes: stale/mismatched SSL trust, duplicate or stale service registrations, EVC re-registration case, TLS cipher mismatch after patching.',
   ['Run lsdoctor in report-only mode (-l) first; then --trustfix for SSL trust mismatches; lsdoctor.py -r (option 3 for duplicates, with lstool.py to unregister bad IDs) for stale registrations - snapshot first.',
    'EVC case (KB 339619): vCenter 7.0 U1 VM re-registered from a 6.5 U3 host; disable EVC on the cluster or register the VM on a non-EVC cluster/host; resolved in ESXi 7.0 U1C.', 'Patching to 7.0 U3q: run the reset-ciphers script (stop rhttpproxy first).'])
kb('Java heap OutOfMemoryError in vCenter services', ['vc.oom_kill'],
   [A(344908, '"503 Service Unavailable" vCenter Server stops responding due to Secure Token Service (vmware-stsd) OutOfMemoryError'), A(375839, 'Resolving /storage/log Disk Space Issues caused by Infraprofile Java Heap Dump Files'), A(393690, 'Resolving /storage/log Disk Space Issues Caused by vmware-cis-license Java Heap Dump Files'),
    A(159679, 'How to address out of memory errors (OOM)')],
   'A vCenter Java service ran out of heap.', ['Check the current allocation: cloudvm-ram-size -l; raise it with cloudvm-ram-size -C <MB> <service> (e.g. 1024 for vmware-stsd), restart the service; you may need to add VM RAM first.', 'Snapshot/backup first; if it persists open a Broadcom case.'],
   match=r'OutOfMemoryError|Java heap')
kb('vmdir / Enhanced Linked Mode replication problems', ['vc.replication'],
   [A(369151, 'VMDir replication is not working between partners / Vmdir service is not in Normal state - upgrade pre-check fails'), A(312122, 'vCenter Server Preupgrade check result error: "VMDir Replication between partners is not working"'), A(369323, 'vCenter Server Replication Status Change Alarm'),
    A(376504, 'Enhanced Linked Mode (ELM) Replication Broken between vCenter Server Appliance (VCSA) Nodes'), A(400283, 'Removing a vCenter Server or PSC nodes from Enhanced Linked Mode that no longer exists'), A(406041, 'vCenter Enhanced Linked Mode replication broken after vCenter IP address change')],
   'Replication broken or vmdir left in Standalone/Failure state; stale agreements from decommissioned nodes; USN mismatch after a single-node restore.',
   ['Take offline snapshots of ALL nodes in the SSO domain first.', 'Check: vdcrepadmin -f showpartnerstatus -h localhost -u administrator on each node; vdcadmintool option 6 for vmdir state.', 'Restart all services on the affected node; for Standalone state see KB 369323 (edit vmdird args, lwsm refresh, dir-cli set NORMAL - may revert after reboot if the cause remains).',
    'Read-only after a single-node restore: vdcadmintool option 5 to set NORMAL; if that fails, the fixpsc workflow (KB 312122/376504).', 'Stale partners from removed nodes: showpartners then cmsso-util unregister (KB 400283). After an IP change open LDAP 389 between nodes (KB 406041).',
    'Commands differ by version (8.0 U3+ differs) - verify against the KB.'])
kb('VM power-on blocked by HA admission control', ['vc.task_fail'],
   [A(400611, 'Power on vm failed with error: Insufficient resources to satisfy configured failover level for vSphere HA'), A(301492, 'VM Power On Fails with "operation failed: Insufficient resources to satisfy configured failover level for vsphere HA"'),
    A(421814, '"Insufficient resources to satisfy configured failover level for vSphere HA" error when Powering ON a Virtual Machine')],
   'Admission control refuses placement that would eat into reserved failover capacity (VM CPU/memory reservations are a common trigger; 2-node clusters reserve 50% by design).',
   ['Add hosts, reduce/remove VM reservations, lower the failover percentage, move VMs elsewhere or power off non-essential VMs.', 'Temporarily disabling admission control lets the VM power on but removes the failover guarantee - re-enable it.', 'Phantom host count in a 2-node cluster: remove and re-add the host.'], match=r'failover level|Insufficient resources')
kb('Directory service schema/ACL on upgraded vCenter', ['vc.acl_legacy'], [A(78543, 'KB number from the supplied TDLog report (not independently retrieved)'), A(80490, '"VMware Directory Service schema update failed" while upgrading from vCenter Server 7.0 to 7.0 Update1')],
   'VMSA-2020-0006 / CVE-2020-3952 affects vCenter 6.7 / PSC before 6.7 U3f only if upgraded from an earlier release line (6.0/6.5); KB 78543 determines whether an environment is affected. Separately, "ACL MODE: Legacy" appears in PatchRunner.log when a 7.0 to 7.0 U1 schema patch fails (legacy VMDIR schema, DFL 4) - fixed in 7.0 U1C.',
   ['Update to 6.7 U3f or later and use KB 78543 to check exposure.', '7.0 -> 7.0 U1 schema-update failure: resolved in 7.0 U1C.'])


# ----------------------------------------------------------------------------- added from resolved-case research (2026-10-09)
kb('UNMAP (SCSI 0x42) failures: device busy / array UNMAP limits', ['esx.unmap'],
   [A(407579, 'ESXi logs report device busy (D:0x8) against unmap commands (0x42)'), A(420623, 'Performance issues on VMs caused by storage array UNMAP command limits.'),
    A(446350, 'Dead Space Reclamation Issue on Pure Storage LUNs After VSS Backups'), A('legacy:77030', 'High VM Stun time during snapshot deletion or SVmotion failure on ESXi 6.7U2 or later')],
   'Command 0x42 is UNMAP and D:0x8 is device busy: arrays cap UNMAP I/O and may reject it with busy (transient status, retried). Slowness can result when the array limit is hit.',
   ['Occasional entries can be a temporary peak and ignored; if frequent, review the UNMAP pattern from the hosts and reduce the load on the array (KB 407579).', 'Engage the array vendor about UNMAP limits/handling (KB 420623).',
    'VMFS-6 with array unmap granularity above 1 MB: set reclaim priority to none on all hosts sharing the volume and reclaim manually with esxcli storage vmfs unmap --volume-label=<ds> --reclaim-unit=200 (legacy KB 77030, 446350).'],
   notes='Related PSOD articles have different causes: KB 396124 (ESXi 8.0.3, #PF in the Unmap module when a datastore is at 100%; no fix at the time of the search) and legacy KB 70607 (6.5/6.7, avoid heavy unmap during reboot/unmount). No KB found that ties 0x42 failures directly to a PSOD.')
kb('Admission failure messages (closest related KB - not an exact match)', ['esx.heap_admission'], [A(425728, 'Addressing "Admission failure in path:" messages in ESXi')],
   'ESXi could not allocate the memory a process requested; only a problem if seen constantly.', ['Restart the affected management agent; if it persists, enter maintenance mode and reboot the host.'],
   notes='No Broadcom KB found for the exact vmxnet3TxdHeap / "Could not allocate ... dynamic heap" message; KB 425728 is the closest general article. A related KB (vmxnet3 slab admission failure after vMotion) ties it to hosts with many fully reserved VMs and stale vNIC entries - check the vmkernel log around power-on.')
kb('VMware Tools upgrade fails installing the PVSCSI driver (Windows)', ['guest.tools_install'],
   [A(390706, 'VMware Tools upgraded fail while installing PVSCSI driver'), A(316567, 'Removal of Windows Update published PVSCSI driver version 1.3.18.0')],
   'The target PVSCSI driver is already present or Windows prefers a different package (for example a Windows-Update published oem inf), so the installer step fails and may roll back.',
   ['Run the Tools upgrade with Custom Setup and exclude the PVSCSI driver; update the driver manually afterwards if needed (KB 390706).', 'If a Windows-Update PVSCSI 1.3.18.0 is installed, roll back to 1.3.17.0: find the package with pnputil -e, remove with pnputil -f -d oemN.inf, or use Device Manager Roll Back Driver (KB 316567).',
    'Collect C:\\Windows\\inf\\setupapi.dev.log, setupapi.app.log and pnputil /enum-drivers output to confirm which package owns pvscsi.'], match=r'PVSCSI|1603|InstallFinalize')
kb('VMware Tools installer rollback: overlapping Windows updates, VMCI or VGAuth lock', ['guest.tools_install'],
   [A(318796, 'VMware Tools installer can fail during Windows updates or when security software locks files'), A(436332, 'VMware Tools installation fails due to a VMCI driver error on a Windows Server guest OS'),
    A(454256, 'VMware Tools 13.1.0 auto-upgrade fails due to VGAuthService file lock')],
   'Auto-upgrade after a reboot can collide with Windows updates, security software or a locked service/driver and roll back.',
   ['Run the installer manually, choose Repair, then reboot (KB 318796); temporarily set the Tools upgrade policy to Manual during patching.', 'Tools 13.1.0 VGAuth lock: Stop-Service -Name "vgauthservice", rerun the upgrade, confirm the service runs again (KB 454256).',
    'Check vminst.log for the exact failing step (e.g. winerror 1052 on the vmci service) and see KB 436332 for the VMCI case.'], match=r'vmci|1052|VGAuth|rollback')
kb('VM cannot power on: lock / disk open timeout', ['esx.vm_open_disk'], [A(313027, 'Cannot power on a virtual machine: unable to locate / lock file (cannot-power-on-a-virtual-machine-locate)')],
   basis='title')
kb('Datastore full: VM stops with "no more space for virtual disk"', ['esx.datastore_full'],
   [A(318352, 'Virtual machine stop running with error "There is no more space for virtual disk"'), A(318518, 'Storage vMotion and VM power on fails with error "No space left on device" on VMFS6 datastore')], basis='title')

lib = dict(researched=RESEARCHED,
           source='Summaries of knowledge.broadcom.com search results gathered on %s (the article pages themselves could not be fetched from the research environment).' % RESEARCHED,
           entries=E)
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lvx', 'kb_library.json')
with open(out, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(lib, f, indent=1, ensure_ascii=False)
    f.write('\n')
print('wrote', os.path.normpath(out), len(E), 'entries')
