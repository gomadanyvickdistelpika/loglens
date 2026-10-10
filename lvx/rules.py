"""Signature rules. `kw` is a lowercase literal prefilter (cheap) before the regex runs.
KB numbers are included ONLY where they appear in the supplied GSS Toolbox / TDLog reports;
otherwise `search` gives a Broadcom KB search phrase. Triage aid, not a root-cause verdict."""
import re

R = []


def rule(id, title, product, severity, topics, kw, pattern, advice, kb=None, search=None, files=None, symptom=False, root_for=()):
    """symptom=True marks a downstream effect or locator (503, 'stage failed'): ranked just below an earlier, likelier cause.
    root_for lists rule ids this finding is an early warning of: if one of them follows later, this ranks above it."""
    R.append(dict(id=id, title=title, product=product, severity=severity, topics=topics,
                  kw=kw.lower(), rx=re.compile(pattern, re.I), advice=advice, kb=kb,
                  search=search or title, files=re.compile(files, re.I) if files else None, symptom=symptom, root_for=tuple(root_for)))


# ---------------- ESXi ----------------
rule('esx.psod', 'ESXi purple screen / kernel panic', 'esxi', 'critical', ['crash', 'hardware'],
     'bluescreen', r'@BlueScreen|PSOD|Panic:\s|Exception \d+ in world|#PF Exception|#GP Exception',
     'Host crashed. Collect the vmkernel-zdump/core, compare the backtrace and check hardware (MCE/ECC) and driver/firmware versions.',
     search='ESXi purple diagnostic screen PSOD backtrace')
rule('esx.mce', 'Machine check / uncorrectable memory error', 'esxi', 'critical', ['hardware', 'crash'],
     'machine check', r'Machine Check|uncorrectable (?:ecc|memory)|hardware error',
     'Hardware fault reported by CPU/memory. Check the BMC/iLO/iDRAC SEL, replace the failing DIMM/CPU through the OEM.',
     search='ESXi machine check exception uncorrectable ECC')
rule('esx.apd', 'Storage: All Paths Down / device lost', 'esxi', 'critical', ['storage'],
     'path', r'All Paths Down|\bAPD\b (?:start|timeout|exit|event)|permanently inaccessible|\bPDL\b|lost access to volume|device .{0,40} is (?:inaccessible|blocked)',
     'Host lost all paths to a device/datastore. Check fabric/array/HBA, cabling, zoning and path state (esxcli storage core path list).',
     search='ESXi All Paths Down APD PDL lost access to volume')
rule('esx.scsi_sense', 'Storage: SCSI command failures (sense data)', 'esxi', 'high', ['storage'],
     'scsideviceio', r'ScsiDeviceIO:.*failed H:0x[1-9a-f]|ScsiDeviceIO:.*failed .*D:0x(?:[2-9a-f]|[0-9a-f]{2,})',
     'Array/HBA returned SCSI errors. Decode H:/D:/P: and sense key (e.g. 0x2 not ready, 0x4 hardware error, 0xb aborted) and engage the storage vendor.',
     search='ESXi ScsiDeviceIO failed H D P sense data decode')
rule('esx.latency', 'Storage: device I/O latency deteriorated', 'esxi', 'high', ['storage', 'performance'],
     'latency', r'performance has deteriorated|I/O latency increased from average value of \d+ microseconds to \d+',
     'Device latency spiked. Correlate with array performance, queue depth, path failover and VM workload at the same time.',
     search='ESXi performance has deteriorated I/O latency increased')
rule('esx.vmfs_lock', 'Storage: VMFS lock/heartbeat/reservation problems', 'esxi', 'high', ['storage'],
     'vmfs', r'Lost (?:lock|heartbeat)|HB at offset|reservation conflict|Timed out waiting for lock|lock .{0,30} (?:lost|stale)|heartbeat .{0,20}(?:fail|timed out)',
     'VMFS metadata lock/heartbeat trouble: check storage latency, ATS/SCSI-2 reservations and concurrent access from other hosts.',
     search='VMFS heartbeat lost lock reservation conflict ESXi')
rule('esx.nfs', 'Storage: NFS datastore unavailable', 'esxi', 'high', ['storage', 'network'],
     'nfs', r'NFS.*(?:All Paths Down|unavailable|timed out|not responding|stale|mount .{0,30}fail)|lost access to NFS',
     'NFS server or network path unreachable. Check server exports, VMkernel NFS port, MTU and firewall.',
     search='ESXi NFS datastore unavailable APD')
rule('esx.nic_down', 'Network: physical NIC link down', 'esxi', 'high', ['network'],
     'link', r'(?:NIC )?Link (?:is )?down|vmnic\d+.{0,40}(?:link down|went down)|Uplink: .{0,40}down|lost (?:uplink )?redundancy|network connectivity lost',
     'Physical uplink lost link. Check switch port, cable/SFP, NIC firmware/driver (VCG) and physical switch logs.',
     search='ESXi vmnic link down uplink redundancy lost')
rule('esx.nic_hang', 'Network: NIC TX timeout / driver hang', 'esxi', 'high', ['network', 'hardware'],
     'timeout', r'(?:tx|transmit) (?:queue )?timeout|netdev watchdog|Watchdog timeout|adapter (?:hang|reset)|(?:i40e|ixgben|bnxtnet|qedentv|nmlx5_core|igbn|ntg3).{0,60}(?:reset|hang|fail|timeout)',
     'NIC driver/firmware stalled and reset. Verify driver+firmware against VCG and engage the NIC vendor.',
     search='ESXi NIC driver tx timeout watchdog reset')
rule('esx.hostd', 'Management: hostd not responding / errors', 'esxi', 'high', ['services', 'host-connection'],
     'hostd', r'Hostd.{0,60}(?:not responding|unresponsive|crash|abort|assert)|hostd.{0,40}(?:watchdog|exited|restart)|Unable to (?:connect|reach) hostd|hostd (?:is )?(?:busy|stuck)',
     'hostd stalled/crashed. Check hostd.log around the time, ramdisk/inode usage, and storage latency that blocks hostd.',
     search='ESXi hostd not responding')
rule('esx.vpxa', 'Management: vpxa / host-agent heartbeat loss to vCenter', 'esxi', 'high', ['host-connection', 'network'],
     'vpxa', r'vpxa.{0,80}(?:heartbeat|timed out|timeout|unable to (?:connect|reach)|lost connection|failed)|Failed to (?:send|get|post) heartbeat|VpxaSocket.{0,40}(?:error|closed)',
     'Host agent cannot reach vCenter (or vice versa). Check network between host and vCenter (port 443/902), DNS, and vpxa/hostd health.',
     search='ESXi host disconnected vCenter vpxa heartbeat')
rule('esx.fdm', 'HA: host isolated / partitioned / FDM failure', 'esxi', 'high', ['ha', 'network'],
     'fdm', r'fdm.{0,100}(?:isolated|partition|failed to|unreachable|election|master)|host (?:is )?isolated|network isolation|HA agent.{0,40}(?:fail|unreachable)',
     'vSphere HA saw isolation/partition. Check management network redundancy, isolation addresses (das.isolationaddress) and heartbeat datastores.',
     search='vSphere HA host isolated FDM partition')
rule('esx.vsan', 'vSAN: congestion / object or disk health', 'esxi', 'high', ['vsan', 'storage'],
     'vsan', r'(?:vsan|lsom|dom|cmmds|clom|plog).{0,100}(?:congestion|inaccessible|degraded|unhealthy|failed|permanent error|PermDeviceLoss|object.*lost)',
     'vSAN data path or device problem. Review vSAN health, disk-group state, congestion and network between hosts.',
     search='vSAN congestion object inaccessible disk unhealthy')
rule('esx.oom', 'Memory: out of memory / heap exhaustion', 'esxi', 'high', ['memory'],
     'memory', r'out of memory|Cannot allocate memory|heap .{0,40}(?:out of space|exhausted|full)|Failed to allocate|memory pool .{0,30}exhaust|oom-?kill',
     'Resource exhaustion on the host. Check host memory pressure, swap, heap/pool sizes and leaks (hostd/vpxa memory).',
     search='ESXi out of memory heap exhausted')
rule('esx.ramdisk', 'Disk space: ramdisk/filesystem full', 'esxi', 'high', ['disk-space'],
     'space', r'No space left on device|ramdisk .{0,30}(?:full|out of)|inode.{0,20}(?:exhaust|full|out)|file system.{0,30}full',
     'A filesystem/ramdisk is full. Find large files (du/vdf) and logs; full ramdisks break hostd/vpxa and logging.',
     search='ESXi ramdisk full no space left on device')
rule('esx.ntp', 'Time: NTP unreachable / clock jump', 'both', 'medium', ['time'],
     'ntp', r'ntpd?.{0,80}(?:unreachable|no server suitable|time reset|sync(?:hroni[sz]ation)? lost|offset too large)|clock .{0,40}(?:jump|drift|stepped)|time (?:has )?(?:jumped|stepped)',
     'Time sync is unstable. Certificates, SSO tokens and clustering depend on correct time: verify NTP sources and firewall.',
     search='NTP time synchronization failure vCenter ESXi')
rule('esx.vmx_crash', 'VM: VMX crash / unexpected termination', 'esxi', 'high', ['vm', 'crash'],
     'vmx', r'vmx.{0,80}(?:panic|core dump|crashed|assert|unexpected signal|terminat(?:ed|ing) unexpectedly)|VMX has left the building|Unexpected signal: \d+',
     'The VM monitor process terminated abnormally. Preserve vmware.log and the vmx core; check guest, host memory and storage at that time.',
     search='virtual machine vmx crash unexpected signal')
rule('esx.snapshot', 'VM: snapshot/consolidation/lock problems', 'both', 'medium', ['vm', 'backup'],
     'snapshot', r'consolidat\w*.{0,40}(?:fail|needed|error)|snapshot.{0,60}(?:fail|error|locked|timed out)|Failed to lock the file|Unable to access file .{0,80}(?:locked|since it is locked)',
     'Backup/snapshot workflow trouble. Check for stale delta disks, backup-proxy locks and datastore space.',
     search='VM snapshot consolidation needed failed to lock file')
rule('esx.vmotion', 'VM: vMotion / migration failure', 'both', 'medium', ['vm', 'network'],
     'vmotion', r'vmotion.{0,80}(?:fail|timed out|error|abort)|migrat\w*.{0,60}(?:failed|timed out)|Failed waiting for data\.',
     'vMotion failed. Check vMotion VMkernel connectivity/MTU, memory dirtying rate and destination resources.',
     search='vMotion fails timed out')
rule('esx.dns', 'Network: name resolution failure', 'both', 'medium', ['dns', 'network'],
     'resol', r'Name or service not known|Temporary failure in name resolution|unable to resolve|getaddrinfo.{0,30}fail|nodename nor servname|DNS (?:lookup|resolution) (?:fail|error)',
     'DNS lookups fail. Verify DNS servers, search domains and forward/reverse records for vCenter/ESXi FQDNs.',
     search='vCenter DNS resolution failure')
rule('esx.cert', 'Certificate: expired / untrusted / handshake failure', 'both', 'high', ['certificate', 'auth'],
     'cert', r'certificate.{0,60}(?:expired|not yet valid|verify failed|untrusted|revoked|invalid)|CERTIFICATE_VERIFY_FAILED|SSL(?:_ERROR|.{0,20}handshake.{0,20}fail)|unable to get local issuer',
     'TLS trust/validity issue. Check certificate expiry (vecs-cli / openssl) and the trust chain, and that time is correct.',
     search='vCenter certificate expired ssl handshake failed')
rule('esx.auth', 'Auth: repeated authentication failures / lockout', 'esxi', 'low', ['auth'],
     'auth', r'Authentication failure|Failed password|Rejected password for user|account .{0,30}locked|has been locked for \d+ seconds|Lockout|Access denied for user|pam_.*(?:fail|deny)',
     'Authentication failures on the host; check lockdown mode, AD join and brute-force attempts.',
     search='ESXi authentication failure account locked')

# ---------------- vCenter ----------------
rule('vc.503', 'vCenter: HTTP 503 / no healthy upstream', 'vcenter', 'critical', ['services', 'auth', 'upgrade'],
     'upstream', r'no healthy upstream|upstream connect error|503 Service Unavailable|HTTP/1\.[01]" 503',
     'The reverse proxy has no healthy backend. Check which service is down (service-control --status --all), vpxd/vsphere-ui, disk space and certificates.',
     search='vCenter no healthy upstream 503', symptom=True)
rule('vc.vpxd_crash', 'vCenter: vpxd crash / panic / backtrace', 'vcenter', 'critical', ['crash', 'services'],
     'backtrace', r'Panic:|PANIC|Backtrace:|Core dump|core dumped|received signal SIG(?:SEGV|ABRT)|Assert(?:ion)? failed',
     'vpxd terminated abnormally. Preserve /var/core, review the backtrace and the last operations before the crash; check DB and memory.',
     search='vpxd crash backtrace core dump', files=r'vpxd|vmware-vpx|core|vmon|vpxd-svcs')
rule('vc.db', 'vCenter: database connectivity / capacity problem', 'vcenter', 'critical', ['database', 'disk-space', 'services'],
     'connect', r'could not connect to server|too many (?:connections|clients)|remaining connection slots|ODBC error|database .{0,30}(?:unreachable|unavailable|full)|connection to (?:the )?database.{0,30}(?:lost|fail)|FATAL:\s+(?:sorry|terminating|the database system)|PANIC:\s+could not write|could not extend file',
     'Embedded PostgreSQL unreachable or out of connections/space. Check vmware-vpostgres service, /storage/db and /storage/seat usage and max_connections.',
     search='vCenter database VCDB connection failure vpostgres')
rule('vc.host_disc', 'vCenter: ESXi host disconnected / not responding', 'vcenter', 'high', ['host-connection', 'network'],
     'host', r'Host .{0,80}(?:is not responding|disconnected|got disconnected)|missing heartbeats|state changed to NO_RESPONSE|No response has been received|The Connection was broken|HostNotResponding|Cannot (?:connect|contact) (?:to )?host|ESX unresponsive|HostCommunication.{0,40}(?:error|fail)|Failed to connect to (?:host|ESX)|host (?:is )?unreachable',
     'vCenter lost management connection to a host. Check the host-side hostd/vpxa, management network, DNS and port 443/902.',
     search='ESXi host disconnected from vCenter not responding')
rule('vc.sso', 'SSO/STS: authentication or token failures', 'vcenter', 'high', ['auth', 'services', 'certificate'],
     'sso', r'(?:sts|sso|vmdird|lookupsvc|IdentityManager).{0,120}(?:fail|invalid|exception|denied|unable)|Invalid credentials|InvalidCredentials|Unable to authenticate|SAML token.{0,40}(?:invalid|expired)|Failed to (?:acquire|validate) (?:a )?token|Authentication failed',
     'Login/token problem. Check STS signing certificate validity, identity source reachability (AD/LDAP), time sync and vmdird health.',
     search='vCenter SSO login fails STS invalid credentials')
rule('vc.ls_client', 'vCenter: Lookup Service client adapter exception', 'vcenter', 'high', ['services', 'upgrade'],
     'ls client', r'Caught exception while creating LS client adapter',
     'Seen in the supplied TDLog sample linked to the KB below (vpxd cannot reach the Lookup Service, e.g. during upgrade or after cert/host-name changes).',
     kb='80867', search='vpxd Caught exception while creating LS client adapter')
rule('vc.disk_full', 'vCenter: appliance partition full (/storage/*)', 'vcenter', 'high', ['disk-space', 'database', 'services', 'upgrade'],
     'space', r'No space left on device|DiskFull|ENOSPC|disk (?:is )?full|file system.{0,30}full|/storage/\w+.{0,40}(?:\b100%|\bfull\b)',
     'A VCSA partition is full. Run df -h and find which /storage/* volume (seat = stats/events/tasks, db, log, core, archive) is at 100%; grow the VMDK/partition (KB: "Increase disk space on VCSA") or purge. Full /storage/seat or /storage/db stops vpostgres and vpxd, and also aborts upgrade imports.',
     search='VCSA /storage/seat full no space left on device increase VMDK')
rule('vc.upg_fail', 'vCenter upgrade: stage / firstboot failure', 'vcenter', 'high', ['upgrade', 'services'],
     'stage|firstboot|first boot|upgrade|import', r'Stage \d+ (?:failed|error)|(?:firstboot|first boot|vpxd_firstboot).{0,80}(?:exited with code [1-9]|failed|error)|upgrade (?:failed|aborted)|Failed to import (?:configuration )?data|Import (?:of )?\w+ data failed',
     'Marks WHERE the upgrade died (stage/step). The cause is usually the earliest ERROR just before it (database/disk, certificate, Lookup Service, DNS, service start). Read the firstboot stderr/stdout logs and /var/log/vmware/upgrade/ around this time.',
     search='VCSA upgrade fails stage 2 import data firstboot vpxd_firstboot', symptom=True)
rule('vc.upg_sizing', 'vCenter upgrade: target size / storage too small (pre-check warning)', 'vcenter', 'high', ['upgrade', 'disk-space'],
     'estimated|requirement|required|insufficient|not enough', r'(?:/storage/\w+|storage|disk|partition)\b.{0,100}(?:estimated|requirement|required|needs?)\b.{0,60}\d+\s*(?:GB|TB)|(?:insufficient|not enough) (?:free )?(?:disk |storage )?space',
     'The upgrade pre-check warned the target appliance disks are smaller than the data being imported. Redeploy the target with a larger deployment/storage size, or choose not to import events/tasks/performance data (Stage 1 option), then retry. If the warning was acknowledged and Stage 2 later hit disk-full, this is the root cause.',
     search='VCSA upgrade pre-check insufficient storage size SEAT data import', root_for=('vc.disk_full', 'vc.db'))
rule('vc.service_down', 'vCenter: service failed to start / exited', 'vcenter', 'high', ['services'],
     'service', r'service .{0,60}(?:failed to start|exited|not running|stopped unexpectedly|crashed)|An error occurred while starting service|Error executing start on service|install\.ciscommon\.service\.(?:failstart|notfound)|vmon.{0,60}(?:fail|restart|unhealthy)|Failed to start .{0,40}service|Health check .{0,40}fail',
     'A vCenter service is flapping or down. Run service-control --status --all and review the service-specific log.',
     search='vCenter service fails to start vmon', symptom=True)
rule('vc.oom_kill', 'vCenter: OOM killer / low memory', 'vcenter', 'high', ['memory', 'crash'],
     'memory', r'Out of memory: Kill(?:ed)? process|oom-killer|java\.lang\.OutOfMemoryError|OutOfMemoryError',
     'Appliance ran out of memory. Review service heap sizes, VCSA memory sizing and which process was killed.',
     search='VCSA out of memory killer java OutOfMemoryError')
rule('vc.replication', 'vCenter: vmdir/ELM replication problem', 'vcenter', 'high', ['auth', 'database'],
     'replic', r'replication.{0,80}(?:fail|error|partner|behind|unable)|vmdir.{0,60}(?:unable|error|fail)|Partner .{0,40}(?:down|unreachable)',
     'Linked-mode/PSC replication issue. Check partner reachability and replication status with vdcrepadmin.',
     search='vCenter vmdir replication failure linked mode')
rule('vc.drs_ha', 'vCenter: DRS / HA configuration or runtime error', 'vcenter', 'medium', ['ha', 'vm'],
     'drs', r'DRS.{0,60}(?:fail|error|unable)|HA.{0,40}(?:configuration failed|agent .{0,30}(?:fail|unreachable)|reconfigure.{0,20}fail)',
     'Cluster service reported errors; check cluster events and host reachability.',
     search='vSphere DRS HA configuration error')
rule('vc.task_fail', 'vCenter: VM operation / task failures', 'vcenter', 'low', ['vm'],
     'task', r'Task .{0,60}(?:failed|error)|PowerOn.{0,30}fail|Failed to (?:power on|clone|relocate|deploy)|InsufficientResources|NoCompatibleHost',
     'Individual task failures. Useful when the customer issue is about a specific operation (power on, clone, deploy).',
     search='vCenter task failed insufficient resources')
rule('vc.acl_legacy', 'Security advisory: vmdird ACL MODE Legacy', 'vcenter', 'low', ['auth'],
     'acl mode', r'ACL MODE: Legacy',
     'Informational advisory reported by TDLog (VMSA-2020-0006 / CVE-2020-3952).',
     kb='78543')


# ---------------- rules derived from resolved support cases (anonymised templates) ----------------
rule('vc.ldaps', 'vCenter: AD over LDAPS identity source / certificate trust failure', 'vcenter', 'high', ['auth', 'certificate', 'services'],
     'ldap', r"Failed to probe provider|Can't contact LDAP server|Server SSL certificate verification failed|SignatureException: Signature does not match|SHA1 Fingerprint",
     'vCenter cannot validate the domain controller LDAPS certificate. Check the DC certificate chain (openssl s_client), that Root + intermediate CAs are trusted in VECS, that the cert is SHA-256 or better (SHA-1 is rejected on vSphere 8), and that the identity source uses the FQDN in the SAN. After a certificate change remove and re-add the identity source.',
     search='vCenter LDAPS identity source certificate SHA-1 Signature does not match probe provider')
rule('esx.heap_admission', 'ESXi: kernel heap admission failure (e.g. vmxnet3TxdHeap)', 'esxi', 'high', ['memory', 'network'],
     'admission failure in path|dynamic heap|heap_align', r'Admission failure in path: host:system:net:heap|Could not allocate \d+ bytes for dynamic heap|Heap_Align\(.{0,60}failed',
     'A vmkernel heap/memory pool had no room (0 KB available). VMs started on the host may come up without working network. Check host memory pressure and reservations, the vmxnet3 and driver versions, and whether the host needs a reboot; open a case with the vmkernel excerpt if it recurs.',
     search='ESXi Admission failure in path vmxnet3TxdHeap Could not allocate dynamic heap')
rule('esx.unmap', 'Storage: UNMAP (SCSI 0x42) command failures', 'esxi', 'high', ['storage', 'performance'],
     'unmap|0x42', r'Cmd\(0x[0-9a-f]+\) 0x42,.{0,120}failed|UNMAP.{0,60}(?:fail|abort|timed out|busy)',
     'Space-reclamation (UNMAP) commands are failing, often with device-busy from the array. Throttle or schedule VMFS-6 space reclamation off-peak, keep datastores below about 85% full, and engage the array vendor with the naa device list and time windows.',
     search='ESXi UNMAP 0x42 device busy D:0x8 space reclamation')
rule('vc.lcm_download', 'vCenter Lifecycle Manager: patch/VIB download or depot authentication failure', 'vcenter', 'high', ['upgrade', 'services'],
     'download|verification service', r'Cannot download VIB|downloadMgr .{0,60}throws error: HTTP Error Code: 40[13]|File download error: .{0,200}failed, 0 byte|unable to authenticate with the VMware verification service',
     'Lifecycle Manager cannot download metadata/VIBs (HTTP 403, expired token, legacy depot) or cannot authenticate to the verification service. Reconfigure the depot with a valid Broadcom token or tenant-specific depot; after a Lifecycle Manager DB reset re-create the SDDC online depot entry with its ownerdata.',
     search='Lifecycle Manager Cannot download VIB HTTP 403 depot token ownerdata verification service')
rule('vc.ha_agent_install', 'vSphere HA agent installation / configuration failure', 'both', 'high', ['ha', 'services'],
     'cannot install|installer error|components required|applying ha', r'Cannot [Ii]nstall the vCenter Server [Aa]gent|Unknown Installer Error|missing .{0,40} components required|Applying HA VIBs?.{0,40}fail',
     'The HA (FDM) agent cannot be installed or removed on a host, typically because a dependent VIB/component is missing or versions differ. Compare installed components with a healthy host, restore the missing component, then disable/enable HA or manually replace the agent.',
     search='Cannot install the vCenter Server agent HA agent unknown installer error missing components')
rule('esx.lockdown', 'ESXi lockdown mode blocking management/HA accounts', 'both', 'medium', ['ha', 'auth'],
     'lockdown|configure vim account|no permission', r'breaks lockdown mode|Failed to configure VIM account|Cannot login user root@127\.0\.0\.1: no permission',
     'Lockdown mode is rejecting vpxuser/root sessions needed for HA or monitoring agents. Add the required exception users or temporarily disable lockdown while configuring HA, then re-enable it.',
     search='ESXi lockdown mode HA agent Access denied Failed to configure VIM account exception users')
rule('vc.vpxd_cfg', 'vCenter: vpxd.cfg malformed or leftover configuration blocks', 'vcenter', 'high', ['services', 'ha'],
     'vpxd.cfg|config file', r'(?:parse|parsing|FileFormatException|malformed).{0,80}vpxd\.cfg|vpxd\.cfg.{0,80}(?:parse|parsing|FileFormatException|duplicate|malformed)|Failed to (?:load|read|parse) config(?:uration)? file',
     'vpxd cannot start because /etc/vmware-vpx/vpxd.cfg is malformed or holds leftovers (for example incomplete vCenter HA teardown or duplicate tags). Back it up, remove the offending block, and restart services.',
     search='vpxd fails to start vpxd.cfg parse error incomplete vCenter HA removal')
rule('vc.dvs_health', 'vDS health check: VLAN / MTU mismatch alerts', 'both', 'medium', ['network'],
     'uplinkportvlan|healthcheck|health check|mtu check', r'UplinkPortVlanUntrunkedEvent|DistributedVirtualSwitchHealthCheckEvent|VLAN \d+ health check probe failed|MTU check failed for VLAN|flagged as unsupported|VLAN trunk verification failed',
     'vDS health check cannot verify VLAN trunking or MTU, usually after VLANs were removed on the physical switches while portgroups still reference them. Usually cosmetic; remove unused VLAN portgroups and align MTU, or disable the health check.',
     search='vSphere Distributed Switch health check VLAN trunked MTU supported status alert')
rule('esx.vm_open_disk', 'VM cannot open disk / power on fails (lock or storage timeout)', 'esxi', 'high', ['storage', 'vm'],
     'cannot open the disk|openfile', r"Cannot open the disk .{0,200}(?:snapshot disks it depends on|Connection timed out)|File system specific implementation of OpenFile\[file\] failed|Module Disk power on failed",
     'A VM disk cannot be opened: stale file lock, broken snapshot chain or an unresponsive datastore (NFS/array). Find the lock owner (vmfsfilelockinfo / lsof), check array and NFS state (persistent locks after failover), then retry power on.',
     search='Cannot power on virtual machine Cannot open the disk snapshot disks 110 Connection timed out lock')
rule('guest.tools_install', 'Guest: VMware Tools installer failure (PVSCSI / VMCI / service stop)', 'both', 'medium', ['upgrade', 'network'],
     'pvscsi|1603|installfinalize|inst_stopservice|inst_uninstallservice|winerror', r'VM_InstallPVSCSIDriver|MSI \(?1603|InstallFinalize.{0,20}Return value 3|Inst_StopService: Service could not be stopped|winerror code 1052|Inst_UninstallService: Service still present',
     'The Windows VMware Tools installer failed and may have rolled back, leaving the VM without drivers/network. Check which driver/service step failed in vminst.log and setupapi.dev.log; use Custom Setup to exclude PVSCSI, repair the install manually, and avoid overlapping Windows updates/reboots.',
     search='VMware Tools upgrade fails PVSCSI driver vminst.log winerror 1052 vmci', files=r'vminst|vmware-?tools|setupapi|guest')
rule('vcf.sddc_init', 'SDDC Manager: initialisation / PSC authentication failure', 'both', 'high', ['auth', 'services'],
     'idp metadata|psc init|initiate psc|authentication failed for host', r'Unable to retrieve iDP Metadata|PSC Initi\w*ation attempt .{0,20}failed|Failed to initiate PSC|Authentication failed for host',
     'SDDC Manager cannot authenticate to a vCenter/PSC. The credential stored in SDDC Manager no longer matches (for example a vCenter root or service account password changed or expired outside SDDC Manager). Restore the matching credential, then restart SDDC Manager services.',
     search='SDDC Manager stuck VMware Cloud Foundation is initializing Unable to retrieve iDP Metadata', files=r'sddc|vcf')
rule('vc.backup_fail', 'vCenter file-based backup failure (scheduled / component)', 'vcenter', 'medium', ['backup'],
     'backup|checksum', r'Error during component \w+ backup|Failed to get vCenter version|BackupManager encountered an exception|Checksum not generated at|Failed to push telemetry data for backup',
     'The VCSA backup job fails (component script, telemetry/version check or retention handling). Compare manual vs scheduled and NFS vs SFTP/other protocols, review /var/log/vmware/applmgmt/backup.log, and check for a known-issue fix for the exact build.',
     search='vCenter scheduled backup fails BackupManager encountered an exception Failed to get vCenter version')
rule('esx.vr', 'vSphere Replication: no connection to VR server', 'esxi', 'medium', ['replication'],
     'vr server', r'No connection to VR Server',
     'Replicated VMs report no connection to the VR server. Check the replication appliance, host management access and credentials.',
     search='No connection to VR Server for virtual machine vSphere Replication')
rule('esx.datastore_full', 'Datastore full: VM cannot write / snapshots exhausted space', 'esxi', 'high', ['storage', 'disk-space', 'vm'],
     'no more space|datastore|insufficient disk', r'There is no more space for virtual disk|Insufficient disk space on datastore|datastore .{0,60}(?:out of space|is full|100%)',
     'A datastore ran out of free space (often from snapshot delta disks), stopping VMs. Free or extend the datastore first, then consolidate/delete snapshots; do not power on until there is headroom.',
     search='VM stopped There is no more space for virtual disk snapshots datastore full')


# Prefilter keyword lists ('|' = any-of). Every regex alternative must contain one of these.
rule('vc.fsck_emergency', 'VCSA: filesystem check failed at boot (emergency mode)', 'vcenter', 'critical', ['disk-space', 'services'],
     'file system check', r'Failed to start File System Check on /dev/|Dependency failed for /\S*|Entering Emergency Mode|Give root password for maintenance|fsck.{0,40}(?:failed|unexpected inconsistency)|EXT4-fs error \(device [\w-]+\)',
     'The appliance cannot mount a filesystem after an unclean shutdown (power loss/storage event) and dropped to emergency mode. Reboot, edit the GRUB entry (press e), append fsck.repair=yes to the linux line and boot (F10); repeat if it reboots. Take a snapshot/backup first when possible.',
     search='VCSA Failed to start File System Check on /dev/vg_root_0/lv_root0 emergency mode fsck.repair=yes')
rule('vc.upg_precheck', 'vCenter upgrade pre-check: untrusted EAM URLs / unsupported extensions', 'vcenter', 'high', ['upgrade'],
     'not trusted|unsupported by the new', r'Source ESX agent manager Configuration contains URLs that are not trusted|extensions registered that are unsupported by the new vCenter',
     'The upgrade pre-check blocks on ESX Agent Manager agencies pointing at untrusted VIB URLs (for example a legacy NSX-V agency) and/or registered extensions the target version no longer supports. Clean up the stale agency/extension following the KBs named in the pre-check, then rerun it.',
     search='vCenter upgrade pre-check ESX agent manager configuration contains URLs that are not trusted extensions unsupported NSX manager')
rule('vr.hbr_agent', 'Replication: Host Based Replication agent cannot be installed (vLCM image deltas)', 'both', 'medium', ['replication', 'upgrade'],
     'replication agent', r'Host Based Replication Agent for ESX can.?t be installed|vLCM image has deltas',
     'The replication product reports the HBR agent cannot be installed because the vLCM image has deltas, although the cluster may show compliant. Compare the cluster image with the desired state (vLCM compliance and hms logs); escalate to the vLCM team if compliance is clean.',
     search='Host Based Replication Agent for ESX can\'t be installed vLCM image has deltas that need to be applied')
rule('vc.clone_property', 'VM clone/provision fails: cannot read managed-object property (snapshot)', 'vcenter', 'medium', ['storage', 'vm-ops'],
     'single property', r"Error reading single property '[\w.]+' from managed object: snapshot-\d+|Configuration file cannot be found",
     'Provisioning (for example Horizon replica/clone) fails because a snapshot or VM config cannot be read, typically after a storage/network redundancy loss. Check the replica/parent VM snapshot state and datastore accessibility from all hosts.',
     search="Cloning of VM failed VC_FAULT_FATAL Error reading single property config.hardware.device from managed object snapshot")
rule('srm.cert_trust', 'SRM: server certificate chain not trusted after certificate change', 'vcenter', 'high', ['certificate', 'replication'],
     'thumbprint verification', r'Server certificate chain is not trusted and thumbprint verification is not configured',
     'Site Recovery Manager (or vSphere Replication) no longer trusts vCenter after a certificate change. Reconfigure the SRM appliance in its VAMI (both sites), and check Lookup Service for duplicate/stale SRM registrations (lsdoctor).',
     search='SRM CertificateValidationException Server certificate chain is not trusted and thumbprint verification is not configured reconfigure')
rule('vc.ha_failover_alarm', 'HA: "vSphere HA virtual machine failover failed" alarm', 'vcenter', 'medium', ['ha'],
     'failover failed', r'vSphere HA virtual machine failover failed|HA (?:virtual machine )?failover failed',
     'The alarm appears when HA believes a host failed and tries to restart VMs that are still running (locked .vmx). Verify the VMs are running; acknowledge and reset the alarm; if it persists, disable and re-enable vSphere HA on the cluster. For an RCA collect vCenter and all-host bundles and review fdm.log.',
     search='vSphere HA virtual machine failover failed alarm all virtual machines in cluster')
rule('vc.rdu_nfc', 'vCenter RDU/upgrade: OVF deploy NFC upload failed (TLS handshake timeout)', 'vcenter', 'high', ['upgrade', 'network'],
     'nfc lease', r'NFC lease: upload\(.{0,120}failed|failed to read .{0,120} from OVA.{0,200}TLS handshake timeout|net/http: TLS handshake timeout',
     'Deploying the target appliance OVF fails while uploading the disk through an ESXi NFC lease (TLS handshake timeout). A proxy configured on the vCenter is a known cause: temporarily remove it (VAMI/console), rerun the upgrade, then restore it. Also verify vCenter-to-ESXi connectivity on 443/902.',
     search='VCF 9 upgrade vCenter reduced downtime upgrade OVF deployment fails NFC lease TLS handshake timeout proxy')
rule('vc.upg_stage2_cause', 'vCenter upgrade stage 2: known failure cause (vPostgres, VMDir, credentials, network, VUM import)', 'vcenter', 'high', ['upgrade'],
     'vpostgres-firstboot|vmdir replication status|invalid root credentials|failed to set network|already exists in the network|update manager data',
     r'Encountered an internal error.{0,40}vpostgres-firstboot|Unable to retrieve VMDir replication status|Invalid root credentials for source appliance|Failed to set network|IP already exists in the network|Importing VMware vSphere Update Manager data',
     'The upgrade died with a specific known message. Match it to the KB list: vPostgres firstboot error on 8.0 U3h/U3i sources (unsupported back-in-time upgrade: restore the source), VMDir replication pre-check (source entered by IP instead of FQDN), root credential error (SSH port 22 blocked), network/IP conflict at switch-over, or Update Manager data import. Check /var/log/vmware/upgrade/ and the firstboot logs on source and target.',
     search='vCenter upgrade fails stage 2 vpostgres-firstboot VMDir replication status invalid root credentials')
rule('vc.ha_unreachable', 'vSphere HA: agent unreachable / uninitialized / cannot reach management addresses', 'both', 'high', ['ha', 'certificate', 'network'],
     'agent unreachable|agent uninitialized|not reachable from vcenter|management network addresses',
     r'HA [Aa]gent (?:is )?(?:[Uu]nreachable|[Uu]ninitialized)|vSphere HA agent is not reachable from vCenter|cannot reach some management network addresses|Agent Unreachable state',
     'vCenter or the other HA agents cannot talk to the FDM agent on a host. Check, in order: certificate mode (vpxd.certmgmt.mode should be vmca unless thumbprint is deliberate) and host certificates, stale /etc/hosts entries for the vCenter FQDN, firewall/VLAN on TCP/UDP 8182 (and 8183/8042/DNS), the vLCM "updateManager" firewall ruleset, and host TPM attestation alarms; then Reconfigure for vSphere HA on the host.',
     search='vSphere HA agent unreachable uninitialized after vCenter 8.0 U3 upgrade certificate')
rule('vc.cert_expired_svc', 'vCenter services down because a required certificate expired', 'vcenter', 'critical', ['certificate', 'services'],
     'expired', r'(?:certificate|cert).{0,80}(?:has expired|is expired|expired on)|x509: certificate has expired|CERTIFICATE_EXPIRED|certificate expired',
     'vpxd/vpxd-svcs and the reverse proxy fail at service start (or after a reboot) when Machine SSL or another VECS certificate is expired. Check expiry with vecs-cli / the vCert tool, renew (Certificate Manager/vCert), verify NTP and reverse DNS, then restart all services.',
     search='vCenter 503 services fail to start expired certificate vecs-cli vCert', root_for=('vc.503', 'vc.service_down'))

BY_ID = {r['id']: r for r in R}

_KW = {
 'esx.psod': 'bluescreen|psod|panic:|exception |#pf|#gp',
 'esx.mce': 'machine check|uncorrectable|hardware error',
 'esx.apd': 'paths down|apd|permanently inaccessible|pdl|lost access|inaccessible|blocked',
 'esx.scsi_sense': 'scsideviceio',
 'esx.latency': 'deteriorated|latency increased',
 'esx.vmfs_lock': 'lock|heartbeat|hb at offset|reservation',
 'esx.nfs': 'nfs',
 'esx.nic_down': 'link|uplink|redundancy|connectivity',
 'esx.nic_hang': 'timeout|watchdog|hang|reset|i40e|ixgben|bnxtnet|qedentv|nmlx5|igbn|ntg3',
 'esx.hostd': 'hostd',
 'esx.vpxa': 'vpxa|heartbeat',
 'esx.fdm': 'fdm|isolated|isolation|ha agent',
 'esx.vsan': 'vsan|lsom|dom|cmmds|clom|plog',
 'esx.oom': 'memory|heap|allocate|oom',
 'esx.ramdisk': 'space|ramdisk|inode|file system',
 'esx.ntp': 'ntp|clock|time ',
 'esx.vmx_crash': 'vmx|signal',
 'esx.snapshot': 'consolidat|snapshot|lock',
 'esx.vmotion': 'vmotion|migrat|waiting for data',
 'esx.dns': 'resol|name or service|getaddrinfo|nodename|dns',
 'esx.cert': 'certificate|ssl|verify|local issuer',
 'esx.auth': 'authentication|password|locked|lockout|access denied|pam_',
 'vc.503': 'upstream|503',
 'vc.vpxd_crash': 'panic|backtrace|core dump|core dumped|signal sig|assert',
 'vc.db': 'connect|connections|clients|slots|odbc|database|fatal|panic|extend file',
 'vc.host_disc': 'host|esx|heartbeat|no response|connection was broken|no_response',
 'vc.sso': 'sts|sso|vmdird|lookupsvc|identitymanager|credentials|authenticate|saml|token|authentication',
 'vc.ls_client': 'ls client',
 'vc.disk_full': 'space|diskfull|enospc|full',
 'vc.upg_fail': 'stage|firstboot|first boot|upgrade|import',
 'vc.upg_sizing': 'estimated|requirement|required|insufficient|not enough',
 'vc.service_down': 'service|vmon|health check|ciscommon',
 'vc.oom_kill': 'out of memory|oom|outofmemory',
 'vc.replication': 'replic|vmdir|partner|[fail]',
 'vc.drs_ha': 'drs|ha',
 'vc.task_fail': 'task|poweron|failed to|insufficient|nocompatible',
 'vc.acl_legacy': 'acl mode',
 'vc.ldaps': 'ldap|probe provider|certificate verification|signature does not match|sha1',
 'esx.heap_admission': 'admission failure in path|dynamic heap|heap_align',
 'esx.unmap': 'unmap|0x42',
 'vc.lcm_download': 'download|verification service',
 'vc.ha_agent_install': 'cannot install|installer error|components required|applying ha',
 'esx.lockdown': 'lockdown|configure vim account|no permission',
 'vc.vpxd_cfg': 'vpxd.cfg|config file|configuration file',
 'vc.dvs_health': 'uplinkportvlan|healthcheck|health check|mtu check|flagged as unsupported|trunk verification',
 'esx.vm_open_disk': 'cannot open the disk|openfile|disk power on',
 'guest.tools_install': 'pvscsi|1603|installfinalize|inst_stopservice|inst_uninstallservice|winerror',
 'vcf.sddc_init': 'idp metadata|psc init|initiate psc|authentication failed for host|initilization|initialization',
 'vc.backup_fail': 'backup|checksum|telemetry',
 'esx.vr': 'vr server',
 'esx.datastore_full': 'no more space|datastore|insufficient disk',
 'vc.fsck_emergency': 'file system check|emergency mode|fsck|maintenance|dependency failed|ext4-fs error',
 'vc.upg_precheck': 'not trusted|unsupported by the new',
 'vr.hbr_agent': 'replication agent|vlcm image',
 'vc.clone_property': 'single property|cannot be found',
 'srm.cert_trust': 'thumbprint verification',
 'vc.ha_failover_alarm': 'failover failed',
 'vc.rdu_nfc': 'nfc lease|tls handshake',
 'vc.upg_stage2_cause': 'vpostgres-firstboot|vmdir replication status|invalid root credentials|failed to set network|already exists in the network|update manager data',
 'vc.ha_unreachable': 'agent unreachable|agent uninitialized|not reachable from vcenter|management network addresses',
 'vc.cert_expired_svc': 'expired',
}
for _r in R:
    _r['kws'] = tuple(_KW[_r['id']].split('|'))
    _r['any_level'] = _r['id'] in ('vc.acl_legacy',)
