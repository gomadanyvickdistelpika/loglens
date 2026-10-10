"""Regenerates lvx/case_templates.json - ANONYMISED templates derived from resolved support cases.

Rules for this file (privacy):
  * no customer/company/person names, no case numbers, no real hostnames/IPs/emails - everything here is invented
    (lab.example hostnames, 192.0.2.x addresses).  tests/test_templates.py enforces this.
  * `lines` are SYNTHETIC log lines.  basis 'case' = wording taken from the case's own log excerpt (anonymised),
    'typical' = a plausible companion line written for the template.  Never present synthetic lines as real logs.
  * resolution/cause text is only what the case documented.  If the case documented none, resolution stays empty.
  * kb = KB numbers the case itself cited.  Titles are only filled in when the case/KB research gave one.

Run:  python tools/build_case_templates.py
"""
import json
import os

T = []


def kb(i, title='', role='cited'):
    return dict(id=str(i), title=title or 'Broadcom KB %s (cited in the resolved case)' % i, role=role)


def tpl(id, title, product, version, issue, evidence, expect, lines, cause='', resolution=(), kbs=(), match=None,
        notes='', bundle=True, extra_files=None, expect_snapshot=False, noise='auto'):
    T.append(dict(id=id, title=title, product=product, version=version, issue=issue, evidence=evidence, bundle=bundle,
                  expect_rules=list(expect), expect_snapshot=expect_snapshot, match=match, noise=noise,
                  lines=[list(l) for l in lines], extra_files=extra_files or {},
                  cause=cause, resolution=list(resolution), kb=list(kbs), notes=notes))


VPXD = 'var/log/vmware/vpxd/vpxd-1.log'
SSO = 'var/log/vmware/sso/ssoAdminServer.log'
VUM = 'var/log/vmware/vmware-updatemgr/vum-server/vmware-vum-server.log'
VUMF = 'var/log/vmware/vmware-updatemgr/vum-server/vum-log4j-filedownload.log'
BKP = 'var/log/vmware/applmgmt/backup.log'
VMON = 'var/log/vmware/vmon/vmon.log'
VMK = 'var/run/log/vmkernel.log'
VMW = 'var/run/log/vmkwarning.log'
HOSTD = 'var/run/log/hostd.log'
VPXA = 'var/run/log/vpxa.log'

# ============================================================================= identity / certificates
tpl('CT-01', 'AD over LDAPS fails after the domain controller certificate was renewed', 'vcenter', '8.0 U3',
    'Active Directory users cannot log in to vCenter. The identity source shows it cannot contact the LDAP server on port 636 after the domain controller certificate was renewed.',
    'mixed', ['vc.ldaps'], [
        (-1500, SSO, '{t} ERROR [IdentityManager] [tomcat-http--8] Failed to probe provider ldaps://dc01.lab.example:636 : Can\'t contact LDAP server', 'typical'),
        (-1495, SSO, '{t} ERROR [IdentityManager] [tomcat-http--9] Failed to probe provider ldaps://dc01.lab.example:636 : Can\'t contact LDAP server', 'typical'),
        (-900, SSO, '{t} WARN  [LdapSslHandshake] Server SSL certificate verification failed: unable to find valid certification path to requested target', 'typical'),
        (-60, SSO, '{t} ERROR [IdentityManager] Failed to authenticate user svc-admin@corp.example against provider corp.example: Can\'t contact LDAP server', 'typical')],
    cause='The domain controller LDAPS certificate was renewed with a new issuer chain that vCenter does not yet trust; the TLS connection to the DC on 636 fails (nc to 636 timed out and openssl s_client showed the Sub-CA/Root-CA chain).',
    resolution=['Test from the VCSA: nc -zv <dc-fqdn> 636, then openssl s_client -connect <dc-fqdn>:636 -showcerts to confirm the chain presented.',
                'Import the Root CA and Sub/Issuing CA certificates into the vCenter trust store (VECS TRUSTED_ROOTS).',
                'Remove and re-add the Active Directory over LDAPS identity source.',
                'Restart VMware Identity Services (expect a brief authentication interruption).',
                'No per-DC leaf certificate upload is needed; keep Root + Sub-CA trusted. Re-adding is only needed again if the issuing CA changes.'],
    kbs=[kb(402946, role='primary'), kb(316596, role='secondary')], match=r"Can't contact LDAP server|ldaps://",
    notes='Case severity was downgraded P1 -> P2 while the customer renewed the DC certificate.')

tpl('CT-02', 'Cannot add AD over LDAPS identity source: domain controller certificate is SHA-1 signed', 'vcenter', '8.0 U3',
    'Adding an Active Directory over LDAPS identity source fails with a certificate error. vCenter can reach the domain controller on port 636.',
    'case-excerpts', ['vc.ldaps'], [
        (-1300, SSO, '{t} INFO  [LdapSslValidator] Attempting Server SSL certificate verification ... [SHA1 Fingerprint: AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD]', 'case'),
        (-1299, SSO, '{t} ERROR [LdapSslValidator] Server SSL certificate verification failed ... not a trusted certificate', 'case'),
        (-1298, SSO, '{t} ERROR [LdapSslValidator] java.security.SignatureException: Signature does not match.', 'case')],
    cause='The domain controller LDAPS endpoint presents a SHA-1 signed certificate/chain. vSphere 8.x disallows SHA-1 anywhere in the TLS chain (leaf, intermediate or root), so SSO rejects the certificate while adding the identity source.',
    resolution=['Reissue the DC LDAPS certificate from the CA with SHA-256 (SHA-2) or stronger, EKU Server Authentication (1.3.6.1.5.5.7.3.1), and SAN = the DC FQDN that vCenter will use.',
                'Export the leaf and any intermediate CA certificates in Base-64.',
                'In vCenter: Administration > Single Sign-On > Configuration > Identity Sources - remove any existing LDAPS source tied to the old certificate, then add it again using the FQDN (not the IP) and import the new leaf + intermediates.',
                'If trust problems persist, diagnose the vCenter trust/lookup store with lsdoctor in report mode first and apply fixes only if flagged.',
                'If several DCs are configured, each must present a valid SHA-2 certificate with a matching SAN.'],
    kbs=[kb(313460, 'Upgrading vCenter Server or ESXi 8.0 fails due to weak (SHA-1) certificate', 'primary'), kb(386667, 'vCenter 8.0: SHA-1 signature algorithm not supported'),
         kb(322174, 'Provided certificate using the weak signature algorithm'), kb(316596, 'Steps to configure the LDAPS identity source'), kb(401134, 'Cannot configure identity source due to a changed certificate (remove and re-add)'),
         kb(320837, 'Using the lsdoctor tool')], match=r'SHA1|Signature does not match|not a trusted certificate',
    notes='Customer closed the case before the new certificate was issued; the analysis and fix path above are from the case.')

tpl('CT-03', 'vCenter VMCA root certificate expiry warning (no log evidence in the case)', 'vcenter', '8.0 U3',
    'vCenter reports that the root certificate will expire on a given date. The environment uses VMCA certificates and the customer asks for help renewing it.',
    'no-log', ['esx.cert'], [], cause='', resolution=[], kbs=[], bundle=False,
    notes='The case report is only the opening request: no log excerpts and no documented resolution. Kept as a symptom template; see the KB research block for expired-certificate guidance.')

tpl('CT-04', 'Expired issuing certificate in the VECS machine certificate store', 'vcenter', '8.0 U3',
    'One of the issuing certificates is reported as expired. The customer asks whether the expired root certificate can be deleted.',
    'no-log', ['esx.cert'], [], bundle=False,
    cause='The active Machine SSL certificate was valid; the expired item was a stale/expired CSR alias left in the MACHINE_SSL_CERT VECS store. No STS or solution-user certificate had expired.',
    resolution=['List the VECS stores (TRUSTED_ROOTS, MACHINE_SSL_CERT) and check the STS signing certificate expiry to confirm the expired item is not in use.',
                'Take a snapshot / backup before any certificate operation.',
                'Remove the stale alias: vecs-cli entry delete --store MACHINE_SSL_CERT --alias <stale-alias>.',
                'Restart vCenter services out of hours and verify service-control --status and UI/API access.'],
    kbs=[kb(344201, 'Error: "no healthy upstream" or "503 Service Unavailable" when accessing vCenter Server (verify and resolve expired certificates)'), kb(326288), kb(385107, 'vCert utility for vCenter certificates')],
    notes='Evidence in the case was command output (VECS listings), not log lines, so no bundle is generated.')

# ============================================================================= vCenter services / lifecycle
tpl('CT-05', 'vSphere Client will not start after reboot: root filesystem 100% full', 'vcenter', '8.0 U3',
    'After a reboot the vSphere UI does not start. service-control --start vsphere-ui fails and the appliance root volume is full.',
    'mixed', ['vc.service_down'], [
        (-1500, VMON, '{t} error vmon Error executing start on service vsphere-ui. Details: install.ciscommon.service.failstart: An error occurred while starting service \'vsphere-ui\'', 'case'),
        (-1490, VMON, '{t} error vmon Service-control failed. Error: install.ciscommon.service.notfound: Unable to locate service \'ciscommon\'', 'case'),
        (-1480, 'var/log/messages', '{s} vcsa systemd[1]: vmware-vsphere-ui.service: Failed with result \'exit-code\'.', 'typical'),
        (-1470, 'var/log/messages', '{s} vcsa kernel: EXT4-fs warning (device dm-1): ext4_dx_add_entry: No space left on device', 'typical')],
    extra_files={'commands/df_h.txt': 'Filesystem                        Size  Used Avail Use% Mounted on\n/dev/mapper/vg_root_0-lv_root_0    48G   48G     0 100% /\n/dev/mapper/log_vg-log            9.8G  2.2G  7.1G  24% /storage/log\n'},
    expect_snapshot=True,
    cause='The appliance root logical volume (/dev/mapper/vg_root_0-lv_root_0, 48 GB) reached 100%, so services could not create temporary/PID/log files and failed to start (install.ciscommon.service.failstart).',
    resolution=['Confirm with df -h / lsblk that the root LV is full.',
                'Grow the VM virtual disk (here 48 GB -> 100 GB) in the ESXi/vSphere UI and reboot the appliance.',
                'Verify service-control --status shows vsphere-ui, vpxd and dependents RUNNING and that / is back to roughly 60%.',
                'Follow-up: extend the logical volume and filesystem (lvextend + resize2fs, or xfs_growfs for XFS) once the storage team enlarges the underlying disk.',
                'Prevent recurrence: log rotation/retention for the VCSA and monitoring/alerting on / and /storage/log usage.'],
    kbs=[kb(83070, 'How to clear space on VCSA /storage/log', 'primary'), kb(316602, 'Increasing the disk space for the vCenter Server Appliance'), kb(82483), kb(85468), kb(85475), kb(83238)],
    notes='The service-control errors in the case were console output; they are shown here as vmon log lines (synthetic).')

tpl('CT-06', 'Lifecycle Manager: Cannot download VIB, HTTP 403 from the legacy depot', 'vcenter', '7.0 U3',
    'Host remediation fails with: Cannot download VIB. All download sources except one vendor depot show as not connected. A Lifecycle Manager database reset did not help.',
    'case-excerpts', ['vc.lcm_download'], [
        (-1800, VUM, '{t} info vmware-vum-server[85256] [Originator@6876 sub=httpDownload] [httpDownloadPosix 691] curl_easy_perform() succeeded - url: https://hostupdate.vmware.com/software/VUM/PRODUCTION/vmtools-main/vmw-depot-index.xml', 'case'),
        (-1799, VUM, '{t} error vmware-vum-server[85256] [Originator@6876 sub=DownloadMgr] [downloadMgr 697] Executing download job {140232628422336} throws error: HTTP Error Code: 403', 'case'),
        (-1798, VUM, '{t} error vmware-vum-server[85247] [Originator@6876 sub=Default] [updateDownloaderImpl 116] File download error: Downloading file: https://hostupdate.vmware.com/software/VUM/PRODUCTION/vmtools-main/vmw-depot-index.xml failed, 0 byte downloaded.', 'case'),
        (-1700, VUM, '{t} info vmware-vum-server[85242] [Originator@6876 sub=vmomi.soapStub[0]] SOAP request returned HTTP failure; method: queryView; code: 500(Internal Server Error); fault: (vim.fault.InvalidName) { name = "UserVars.PXEBootEnabled" msg = "\'UserVars.PXEBootEnabled\' is invalid or exceeds the maximum number of characters permitted." }', 'case'),
        (-1200, 'var/log/vmware/vmware-updatemgr/vlcm/vlcm.log', '{t} error vlcm Cannot download VIB: \'\'. This might be because of network issues or the specified VIB does NOT exist or does NOT have a proper \'read\' privilege set.', 'typical')],
    cause='Lifecycle Manager was still using the legacy public depot and an expired/stale Broadcom token, so payload downloads returned HTTP 403 (metadata downloads still looked successful). The UserVars.* SOAP faults were noise and were not the cause.',
    resolution=['Review vmware-vum-server.log: HTTP Error Code 403 on the legacy depot and 0 bytes downloaded confirm the depot/token problem.',
                'Reset the Update Manager database: /usr/lib/vmware-updatemgr/bin/updatemgr-util reset-db.',
                'Reconfigure Lifecycle Manager with the Broadcom tenant-specific depot and a valid token (the legacy default depots can only be disabled on older builds; upgrading vCenter allowed the new depot configuration).',
                'Restart services and retry host remediation; verify no further 403/token errors in the log.'],
    kbs=[kb(390098, 'Reconfigure Lifecycle Manager with the tenant-specific depot and token', 'primary'), kb(390121), kb(395322)], match=r'Cannot download VIB|HTTP Error Code|failed, 0 byte')

tpl('CT-07', 'Lifecycle Manager: compatibility-data sync fails after a database reset (verification service)', 'vcenter', '9.0',
    'After resetting the Lifecycle Manager database, update sync works but compatibility-data sync fails with: unable to authenticate with the VMware verification service.',
    'mixed', ['vc.lcm_download'], [
        (-1500, VUMF, '{u} INFO  [qtp1297149880-18 INFO \'com.vmware.updatemanager.filedownload.FileDownloadServlet\'] File /storage/updatemgr/patch-store-temp/SOFTWARE_SPEC_0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9.json does not exist.', 'case'),
        (-1480, VUM, '{t} error vmware-vum-server[85242] [Originator@6876 sub=Default] A general system error has occurred: unable to authenticate with the VMware verification service. Please try again and, if the problem persists, contact Broadcom support.', 'case')],
    cause='The SDDC Manager online depot entry in vCenter lost (or was re-created without) the ownerdata value sddc_manager_esx_depot after the Lifecycle Manager database reset, so the verification service rejects the sync.',
    resolution=['Log in to the vCenter on which the Lifecycle Manager DB reset was performed.',
                'Developer Center > API: GET the online depots (settings/depots/online) and note the depotId of the SDDC depot URL.',
                'DELETE the existing SDDC depot entry using that depotId.',
                'POST a new online depot with description "SDDC Manager Online Depot", enabled true, location = the SDDC Manager depot index URL, and ownerdata "sddc_manager_esx_depot".',
                'GET again to verify the ownerdata field is present, then retry the sync.'],
    kbs=[], match=r'verification service|FileDownloadServlet', notes='The case cited no KB; the fix came from engineering and is documented in the case.')

tpl('CT-08', 'VAMI update from repository URL fails at Stage and Install (no logs in the case)', 'vcenter', '8.0 U3',
    'Updating vCenter through the VAMI using a repository URL fails when clicking Stage and Install.',
    'no-log', ['vc.lcm_download'], [], bundle=False,
    cause='Not established from logs: the case had none. The documented paths were a repository/token/URL problem versus using an offline ISO.',
    resolution=['Path A: validate DNS/egress to the repository and the token/URL, then re-stage.', 'Path B: stage and install the update from the offline ISO instead.',
                'Logs to request: applmgmt.log, update_microservice.log, software-packages.log, PatchRunner.log.'],
    kbs=[kb(390120, 'Update vCenter via VAMI repository URL (repo/token/URL path)', 'primary')],
    notes='The customer confirmed resolution on a call; no log analysis was possible.')

tpl('CT-09', 'Scheduled vCenter backup to NFS fails while manual backup works', 'vcenter', '9.0.2',
    'A scheduled file-based backup to NFS ends in "BackupManager encountered an exception"; a manual backup works. The problem started after an upgrade.',
    'case-excerpts', ['vc.backup_fail'], [
        (-1500, BKP, '{u} [20260310-091504-11112222] [VCDBBackup:PID-2280610] [telemetry::get_vc_version:telemetry.py:306] INFO: Get vCenter version from /etc/vmware/.buildInfo', 'case'),
        (-1499, BKP, '{u} [20260310-091504-11112222] [VCDBBackup:PID-2280610] [VCDB::BackupVCDB:VCDB.py:2080] ERROR: vCenter version is not as expected', 'case'),
        (-1498, BKP, '{u} [20260310-091504-11112222] [VCDBBackup:PID-2280610] [VCDB::BackupVCDB:VCDB.py:2092] ERROR: Failed to push telemetry data for backup Failed to get vCenter version', 'case'),
        (-1400, BKP, '{u} [20260310-091504-11112222] [ComponentScriptsBackup:PID-2280609] [Proc::GetProcsStatus:Proc.py:368] ERROR: Process returncode is -13, but expected exit codes are [0].', 'case'),
        (-1399, BKP, '{u} [20260310-091504-11112222] [ComponentScriptsBackup:PID-2280609] [Proc::UpdateExceptionStatus:Proc.py:408] ERROR: Checksum not generated at /dev/shm/backupRestoreSumFile-20260310-091504-11112222-k3m5n7p9', 'case'),
        (-1398, BKP, '{u} [20260310-091504-11112222] [ComponentScriptsBackup:PID-2280609] [ComponentScripts::ComponentScriptsBackup:ComponentScripts.py:148] ERROR: Error during component vum backup', 'case')],
    cause='Configuring the scheduled backup with a "Retain last X days" retention rule makes the backup fail (metadata dispatch / write-ahead-log handling) on NFS targets; changing the protocol to SFTP made the problem disappear.',
    resolution=['Take a snapshot / file-based backup of the vCenter first.',
                'Copy the two engineering fix files (ScheduleManager.py and SchedulerCron.py) to /root and keep copies of the originals (/usr/lib/applmgmt/backup_restore/py/vmware/appliance/backup_restore/ScheduleManager.py and /usr/lib/applmgmt/backup_restore/scripts/SchedulerCron.py).',
                'Replace the originals with the fixed files and run service-control --restart applmgmt.',
                'Run a scheduled backup with "Retain last X days" and confirm it succeeds (the transferred size should match a manual backup).'],
    kbs=[kb(428785, 'Internal KB: scheduled backup with retention fails (fix files)', 'primary'), kb(428423, 'Tried first, did not help')])

tpl('CT-10', 'vpxd will not start after removing vCenter HA; lockdown mode and NIC1 errors during HA redeploy', 'vcenter', '7.0 U3',
    'After removing vCenter HA and rebooting, vCenter does not come back. Afterwards, vSphere HA agent install and vCenter HA redeploy fail.',
    'mixed', ['vc.vpxd_cfg', 'esx.lockdown'], [
        (-3000, VPXD, '{t} error vpxd[05993] [Originator@6876 sub=Default] Failed to parse configuration file /etc/vmware-vpx/vpxd.cfg: unexpected element (leftover vCenter HA block)', 'typical'),
        (-2990, VMON, '{t} error vmon Service vpxd failed to start; health check failed', 'typical'),
        (-1500, HOSTD, '{t} error hostd[2099] [Originator@6876 sub=Default] Access denied. Failed to configure VIM account. Operation breaks lockdown mode', 'case'),
        (-1000, VPXD, '{t} error vpxd[05993] [Originator@6876 sub=Default opID=op-300] vCenter HA network configuration failed: NIC1 not reachable', 'case')],
    cause='Primary: an incomplete vCenter HA (vCHA) removal left malformed configuration blocks in /etc/vmware-vpx/vpxd.cfg that stopped vpxd starting after the reboot. Secondary: ESXi lockdown mode without exception users blocked the HA agent; stale NIC1 bindings broke vCHA network detection; the witness VM was pinned to a host.',
    resolution=['Remove all residual vCHA configuration (the malformed blocks in vpxd.cfg) and start services: service-control --start --all.',
                'Lockdown mode: temporarily disable it on the hosts, configure vSphere HA, then re-enable it with the exception users (vpxuser, root); confirm port 8182 is open between hosts.',
                'vCHA NIC1 detection: reassign the port group (temporary port group, then back to the correct one) to refresh the network stack.',
                'Witness VM power-on blocked by "pinned to host": vMotion it away / clear the VM-host pinning and check DRS rules, then retry the vCHA deployment.'],
    kbs=[kb(393136, 'Incomplete vCHA teardown', 'primary'), kb(345089, 'vCenter server service (vpxd) fails to start after reboot'), kb(332712, 'vCenter HA NIC1 detection failure')],
    notes='vCenter 7.0 U3 was noted in the case as having known HA-related defects and being withdrawn from downloads.')

tpl('CT-11', 'vSphere Distributed Switch health check alerts after VLANs were removed from the physical switches', 'vcenter', '7.0 U3',
    'After removing about 20 VLANs on the physical switches, every host shows "vSphere Distributed Switch VLAN trunked status" and "MTU supported status" alerts. No traffic impact.',
    'case-excerpts', ['vc.dvs_health'], [
        (-5400, VPXD, '{t} info vpxd[05993] [Originator@6876 sub=Default] vim.event.UplinkPortVlanUntrunkedEvent: VLAN 730 no longer trunked on uplink vmnic0', 'case'),
        (-5399, VPXD, '{t} warning vpxd[05993] [Originator@6876 sub=Default] DistributedVirtualSwitchHealthCheckEvent: Health status changed to RED', 'case'),
        (-5280, HOSTD, '{t} warning hostd[2099] [Originator@6876 sub=Default] NetVDS: VLAN 730 health check probe failed on uplink vmnic1', 'case'),
        (-5279, HOSTD, '{t} warning hostd[2099] [Originator@6876 sub=Default] DvsManager: VLAN trunk verification failed', 'case'),
        (-4800, VPXA, '{t} warning vpxa[2105] [Originator@6876 sub=Default] DVS health check: VLAN 283 flagged as unsupported for host esx-a01.lab.example', 'case'),
        (-5700, VMK, '{t} cpu4:2097180)WARNING: NetVDS: MTU check failed for VLAN 285 (expected 9000, found 1500)', 'case')],
    cause='The vDS portgroups still reference VLANs (for example 730, 283, 285) that were removed from the physical switch trunks, so the health-check probes for VLAN trunking and MTU fail. The alerts are cosmetic: no vSAN or VM traffic impact.',
    resolution=['Recommended: remove the unused VLAN-tagged portgroups from the vDS and make sure MTU is aligned between the vDS and the physical switches (9000 recommended for vSAN).',
                'Alternative: disable the vDS health check: Networking > vDS > Configure > Health Check, untick "VLAN and MTU" and/or "Teaming and Failover".'],
    kbs=[kb(318971, 'vDS Health Check reports unsupported VLANs for MTU and VLAN', 'primary'), kb(321305, 'Enabling / disabling the vDS health check'), kb(318448, 'Explains the cosmetic nature of these health check failures')])

tpl('CT-12', 'Two vCenters in Enhanced Linked Mode: vmdir READ_ONLY and failed pre-checks', 'vcenter', '7.0',
    'VDT reports "[FAIL] VMdir Local State Check (Read)" and vdcadmintool shows vmdir in read-only state on one of two linked vCenters; an upgrade of the other fails at Stage 2.',
    'mixed', ['vc.replication'], [
        (-1800, 'var/log/vmware/vdt/vdt-output.log', '{t} [FAIL] VMdir Local State Check (Read)', 'case'),
        (-1799, 'var/log/vmware/vdt/vdt-output.log', '{t} Please use /usr/lib/vmware-vmdir/bin/vdcadmintool option 6 to confirm the state. Check /var/log/vmware/vmdird/vmdird-syslog.log to investigate.', 'case'),
        (-1790, 'var/log/vmware/vdt/vdt-output.log', '{t} VmDir State is - Read only', 'case'),
        (-1700, 'var/log/vmware/vmdird/vmdird-syslog.log', '{t} error vmdird t@139: Replication partner vc02.lab.example unreachable (Server down)', 'typical')],
    cause='vmdir was left READ_ONLY. Findings in the case: on the second vCenter /etc/hosts mapped its FQDN to 127.0.0.1/::1 (intermittent LDAP failures); pre-checks showed an invalid trusted-root chain, duplicate registrations and an STS_INTERNAL_SSL_CERT mismatch; rsyslog "Too many open files" was seen separately.',
    resolution=['Take offline snapshots of both vCenters first (avoid deleting large snapshots live: it consumed the call time).',
                'Restore vmdird logging on both nodes, then review the directory topology (replication agreements) - a "Server down" entry was the first sign.',
                'Set the vmdir state to NORMAL with vdcadmintool (option 5, Set vmdir state), then reboot both vCenters.',
                'Verify replication: vdcrepadmin -f showpartnerstatus shows partners available = Yes; vmdir state NORMAL on both members.',
                'Fix /etc/hosts so the vCenter FQDN does not resolve to loopback; run lsdoctor in report mode and apply fixes only if flagged; handle the rsyslog file-handle issue in a separate case.'],
    kbs=[kb(312122, 'vCenter Server pre-upgrade check: VMDir replication between partners is not working', 'primary'), kb(318741, 'lookupsvc autostart'), kb(317886, 'Restoring vmdird logging')])

tpl('CT-13', 'Hosts flap Connected / Not Responding every ~60 seconds (UDP 902 heartbeats dropped)', 'vcenter', '8.0 U3',
    'Two ESXi hosts keep switching between Connected and Not Responding in vCenter with no VM impact. TCP 443 from the host to vCenter times out intermittently.',
    'case-excerpts', ['vc.host_disc'],
    [(-300 + 60 * i + d, VPXD, ln, 'case') for i in range(5) for d, ln in (
        (0, '{t} warning vpxd[05993] [Originator@6876 sub=InvtHostCnx opID=hb-%d] Connection not alive due to missing heartbeats; [vim.HostSystem:host-1001,esx-b01.lab.example]' % i),
        (1, '{t} info vpxd[05993] [Originator@6876 sub=MoHost opID=hb-%d] connection state changed to NO_RESPONSE' % i),
        (2, '{t} info vpxd[05993] [Originator@6876 sub=InvtHostCnx opID=hb-%d] Succeeded restoring heartbeat; [vim.HostSystem:host-1001,esx-b01.lab.example]' % i),
        (3, '{t} info vpxd[05993] [Originator@6876 sub=MoHost opID=hb-%d] connection state changed to CONNECTED' % i))] + [
        (-200, HOSTD, '{t} info hostd[2099] [Originator@6876 sub=Vimsvc.ha-eventmgr] user=vpxuser:VSPHERE.LOCAL\\vpxd-extension-1a2b: New error before the previous is handled', 'case')],
    cause='Intermittent loss and restoration of the vCenter-to-ESXi UDP 902 heartbeats, most likely a stateful firewall / IPS / NAT / load-balancer on the management path dropping or timing out UDP/902 flows (vpxd shows a repeating ~60 s NO_RESPONSE / CONNECTED pattern).',
    resolution=['Allow UDP 902 bidirectionally between the vCenter and each ESXi management IP.',
                'Raise UDP idle/state timeouts on the stateful devices to 120 s, or exempt these flows from inspection/NAT/ALG.',
                'During a flap capture 5-10 minutes on both ends and compare: ESXi pktcap-uw --uplink vmnicX --capture UplinkSndKernel --udpport 902 -o - | tcpdump-uw -enr -  ; VCSA tcpdump -nni any host <esxi-mgmt-ip> and udp port 902.',
                'Temporary workaround only: set config.vpxd.heartbeat.notRespondingTimeout = 120 and restart vpxd (the customer did this and still saw events).',
                'After the network change, watch vpxd.log for 30-60 minutes and keep before/after excerpts. The case was cloned to the Networking team for packet-path verification.'],
    kbs=[kb(318647, 'ESXi host disconnects intermittently from vCenter Server (dropped UDP/902 heartbeats)', 'primary'), kb(318927, 'performance has deteriorated messages (noise in this case)', 'noise'), kb(323226, 'Automated bundle-analysis rule: vCenter HA repeated failover (not the cause here)', 'noise')],
    match=r'missing heartbeats|NO_RESPONSE|restoring heartbeat')

tpl('CT-14', 'Hosts show Disconnected after a core network change; reconnect says "incorrect user name or password"', 'vcenter', '7.0',
    'After moving a circuit to a new core router several hosts are Disconnected in vCenter. Restarting management agents does not help; reconnecting reports incorrect user name or password. Hosts are reachable by SSH and the Host Client.',
    'mixed', ['vc.host_disc'], [
        (-3000, VPXD, '{t} warning vpxd[05993] [Originator@6876 sub=InvtHostCnx opID=op-77] Failed to connect to host esx-a02.lab.example: SSL Exception: handshake failure', 'typical'),
        (-2990, VPXD, '{t} error vpxd[05993] [Originator@6876 sub=Default opID=op-79] Cannot reconnect host esx-a02.lab.example: incorrect user name or password', 'case'),
        (-2400, VPXD, '{t} warning vpxd[05993] [Originator@6876 sub=MoHost] Host esx-a02.lab.example is not responding', 'typical')],
    cause='A TLS/trust breakdown between vCenter and the hosts after the network change - not real credential failure. The "incorrect user name or password" message was misleading; the handshake was failing earlier.',
    resolution=['From the vCenter appliance shell run curl -kv https://<esxi-host-fqdn> to see whether the TLS handshake completes and which certificate is presented.',
                'Correct the network/routing/inspection change; the customer reported 95% of hosts reconnected immediately and the rest after minor tweaks - no vCenter DB work was needed.',
                'Last-resort fallback only: manually remove a stuck host from the vCenter database (coordinated, after analysis).'],
    kbs=[kb(314599, 'Manually Removing an ESXi Host from the vCenter Server Database', 'fallback')])

tpl('CT-15', 'Host intermittently Not Responding / hung; management services restart reconnects it', 'vcenter', '7.0 / 8.x',
    'A single host repeatedly shows Not Responding or disconnected in vCenter while the host and its VMs still ping. Restarting the management services reconnects it. The hardware vendor found no fault.',
    'mixed', ['vc.host_disc'], [
        (-1500, VPXD, '{t} warning vpxd[05993] [Originator@6876 sub=MoHost] Host esx-c01.lab.example is not responding', 'typical'),
        (-1499, VPXD, '{t} warning vpxd[05993] [Originator@6876 sub=InvtHostCnx] Connection not alive due to missing heartbeats; [vim.HostSystem:host-4001,esx-c01.lab.example]', 'typical'),
        (-1400, VPXA, '{t} error vpxa[2105] [Originator@6876 sub=vpxaMoService] Failed to send heartbeat to vpxd: Operation timed out', 'typical'),
        (-1300, HOSTD, '{t} warning hostd[2099] [Originator@6876 sub=Default] Hostd is slow to respond: task queue backed up', 'typical')],
    cause='Not established in the case reports (no log excerpts); one case was closed after the management services restart, the other after the vendor found no hardware fault.',
    resolution=['Restart the management agents (hostd, then vpxa) and confirm the host returns to Connected.',
                'Collect the host and vCenter log bundles around the event timestamp for a real root cause (storage stalls, vpxa heartbeat path, hostd memory).'],
    kbs=[kb(317632, 'Automated bundle-analysis rule: Host is disconnected from vCenter Server', 'rule')], notes='Both source cases were opening snapshots; the log lines here are typical, not from the cases.')

# ============================================================================= ESXi
tpl('CT-16', 'VMs restarted by HA after a power outage come up without network (vmxnet3 heap admission failure)', 'esxi', '8.0 U3',
    'After a data-centre power outage some VMs restarted by vSphere HA have no network. vmkernel logs vmxnet3 heap admission failures on the host where they restarted.',
    'case-excerpts', ['esx.heap_admission'], [
        (-3600, VMK, '{t} In(182) vmkernel: cpu8:2103479)Vmxnet3: 14920: indLROPktToGuest: 1, vcd->umkShared->vrrsSelected: 7 port 0x6000016', 'case'),
        (-3599, VMK, '{t} In(182) vmkernel: cpu8:2103479)Vmxnet3: 15304: Using default queue delivery for vmxnet3 for port 0x6000016', 'case'),
        (-3598, VMK, '{t} In(182) vmkernel: cpu9:2103732)Admission failure in path: host:system:net:heap:vmxnet3TxdHeap+0x2a', 'case'),
        (-3598, VMK, '{t} In(182) vmkernel: cpu9:2103732)heap:vmxnet3TxdHeap+0x2a (159) requires 512 KB, asked 512 KB from host (0) which has 1072848848 KB occupied and 0 KB available.', 'case'),
        (-3597, VMW, '{t} Wa(180) vmkwarning: cpu9:2103732)WARNING: Heap: 3892: Could not allocate 40960 bytes for dynamic heap vmxnet3TxdHeap. Request returned Admission check failed for memory resource', 'case'),
        (-3596, VMW, '{t} Wa(180) vmkwarning: cpu81:2103917)WARNING: Heap: 4105: Heap_Align(vmxnet3TxdHeap, 40960/40960 bytes, 8 align) failed. caller: 0x4200334bfb2c', 'case')],
    cause='Not established in the case report (it was opened with the vmkernel excerpt and a support bundle). The log shows the vmxnet3 TX descriptor heap had 0 KB available when the VMs powered on.',
    resolution=[], kbs=[],
    notes='The case report contains no resolution. No exact Broadcom KB was found for the vmxnet3TxdHeap message; the KB library shows the closest general article (admission failure messages).')

tpl('CT-17', 'UNMAP (SCSI 0x42) failure storm, high latency and historical host crashes', 'esxi', '8.0 U3',
    'Several hosts crashed with purple screens in the past; none recently. The customer asks for an inspection to confirm the risk is gone. History shows tens of thousands of 0x42 failures and storage latency warnings.',
    'mixed', ['esx.unmap', 'esx.latency'], [
        (-7200 + 300 * i, VMK, '{t} cpu12:2097500)ScsiDeviceIO: 3449: Cmd(0x45d2c%d) 0x42, CmdSN 0x%x from world 0 to dev "naa.600601604d3f4e00" failed H:0x0 D:0x8 P:0x0 Possible sense data: 0x0 0x0 0x0.' % (i, 0x8a + i), 'typical') for i in range(6)] + [
        (-6000, VMK, '{t} cpu7:2097200)WARNING: ScsiDeviceIO: 1204: Device naa.600601604d3f4e00 performance has deteriorated. I/O latency increased from average value of 1500 microseconds to 58000 microseconds.', 'typical'),
        (-300, VMK, '{t} cpu3:2097100)ScsiDeviceIO: 3449: Cmd(0x45d2d0) 0x42, CmdSN 0x9b from world 0 to dev "naa.600601604d3f4e00" failed H:0x0 D:0x2 P:0x0 Valid sense data: 0x5 0x20 0x0.', 'typical')],
    cause='Working theory in the case: a storage-driven UNMAP (opcode 0x42) failure storm causes task-management stalls and host instability. Supporting evidence from earlier cases: thousands of 0x42 failures against specific naa devices, high LUN latency warnings, non-zero FC CRC counters, datastores above 85% full and failed VAAI commands.',
    resolution=['Throttle VMFS-6 space reclamation (reduce the rate / schedule it off-peak) on the affected datastores.',
                'Engage the array vendor with the naa device list and failure windows to investigate UNMAP handling/latency.',
                'Keep datastore capacity below about 85% full.',
                'Check HBA driver/firmware parity against the VMware Compatibility Guide and review FC CRC counters.',
                'The case was moved to the Storage team to validate the UNMAP signature.'],
    kbs=[], notes='The case cited no KB. The KB library lists researched articles on UNMAP device-busy and array limits (not from the case). Log lines are typical, not from the case.')

tpl('CT-18', 'VM cannot power on or vMotion: cannot open disk, connection timed out (NFS persistent file locks)', 'esxi', '8.0 U3',
    'A VM fails to vMotion and will not power on: "Cannot open the disk ... or one of the snapshot disks it depends on. 110 (Connection timed out)". No .lck file exists on the datastore; re-registering the VM or using another host did not help.',
    'case-excerpts', ['esx.vm_open_disk'], [
        (-2400, HOSTD, '{t} error hostd[2099] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/nfs-ds01/app01/app01.vmx] File system specific implementation of OpenFile[file] failed', 'case'),
        (-2399, HOSTD, '{t} error hostd[2099] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/nfs-ds01/app01/app01.vmx] Failed to start the virtual machine. Module Disk power on failed. Cannot open the disk \'/vmfs/volumes/5e0c1a2b-3d4e5f60-0000-000000000000/app01/app01.vmdk\' or one of the snapshot disks it depends on. 110 (Connection timed out)', 'case'),
        (-2300, VMK, '{t} cpu4:2097180)WARNING: NFS: 1227: Lost connection to the server nas01.lab.example mount point /export/ds01, mounted as nfs-ds01 ("ds01")', 'typical')],
    cause='Persistent file locks on the NetApp NFS datastore after a controller failover ("split-brain" locks). The customer storage team cleared them. A .lck file was not present, so the common lock KB did not apply directly.',
    resolution=['Confirm the failure on the source and destination host (vmware.log / hostd.log) and that no .lck file exists.',
                'Have the storage team check the array for stale/persistent NFS locks after failover and clear them (this fixed the case).',
                'Retry power-on / vMotion once the locks are released.'],
    kbs=[kb(313027, 'Cannot power on a virtual machine: unable to locate / lock file', 'primary'), kb(2037507, 'Legacy KB number referenced in the case subject', 'secondary')],
    notes='Automated bundle-analysis rules that fired on the bundle: NetApp NFS connectivity, NFS41 failover APD, All Paths Down, Storage vMotion timeout.')

tpl('CT-19', 'VMs read-only after a night-time event; lock file error on a VMDK (no log evidence in the case)', 'esxi', '8.0',
    'At about 1 a.m. some VMs on one host went read-only and could not access their disks after a restart. No storage errors were seen and other hosts on the same datastores were fine. Rebooting the host fixed it.',
    'no-log', ['esx.vm_open_disk'], [], bundle=False,
    cause='Not established: the report is only the opening request.', resolution=['Rebooting the affected ESXi host cleared the condition (per the customer).'], kbs=[],
    notes='Related lock/power-on guidance is in CT-18 and the KB research block.')

tpl('CT-20', 'Production VM down: three snapshots filled the datastore', 'esxi', '8.0',
    'A production database VM is down. Three snapshots consumed all free space on the datastore. The datastore was enlarged but the VM still cannot start and the snapshots cannot be removed.',
    'mixed', ['esx.datastore_full'], [
        (-1800, HOSTD, '{t} error hostd[2099] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/ds-prod-01/db01/db01.vmx] There is no more space for virtual disk \'db01-000003.vmdk\'. You might be able to continue this session by freeing disk space on the relevant volume, and clicking Retry.', 'typical'),
        (-1790, HOSTD, '{t} warning hostd[2099] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/ds-prod-01/db01/db01.vmx] Insufficient disk space on datastore ds-prod-01', 'typical'),
        (-1700, VMK, '{t} cpu6:2097210)WARNING: VMFS: 3989: Datastore ds-prod-01 has less than 1% free space', 'typical')],
    cause='Snapshot delta disks grew until the datastore was full (stated in the case description).',
    resolution=[], kbs=[], notes='The report is an opening snapshot with no documented resolution; the datastore-full KB research block gives the generic guidance.')

tpl('CT-21', 'Root account locked / "No connection to VR Server" on VMs', 'esxi', '8.0 U3',
    'ESXi root login stops working (locked or expired) and many VMs show "No connection to VR Server for virtual machine". The team cannot get into the hosts.',
    'mixed', ['esx.auth', 'esx.vr'], [
        (-1500, HOSTD, '{t} warning hostd[2111] [Originator@6876 sub=Default] Rejected password for user root from 192.0.2.50', 'typical'),
        (-1499, HOSTD, '{t} warning hostd[2111] [Originator@6876 sub=Default] Remote access for ESXi local user account \'root\' has been locked for 120 seconds', 'typical'),
        (-1400, 'var/run/log/vmkwarning.log', '{t} Wa(180) vmkwarning: cpu2:2097300)WARNING: VR: 4021: No connection to VR Server for virtual machine vm-1042', 'typical')],
    cause='The ESXi root password was locked out or expired, so SSH/UI access to fix the replication (VR) errors was not possible.',
    resolution=['Use PowerCLI with the commands in the KB to reset the ESXi root password on the affected hosts.',
                'Confirm host UI and SSH access are restored, then address the "No connection to VR Server" errors.'],
    kbs=[kb(376979, 'Reset ESXi root password with PowerCLI', 'primary'), kb(345059, 'VMware Skyline Health Diagnostics for vSphere', 'secondary')])

# ============================================================================= HA
tpl('CT-22', 'HA agent cannot be installed on one host: missing Mellanox components', 'esxi', '8.0',
    'vSphere HA shows "agent unreachable" on one node. Re-enabling HA fails: "Cannot Install. The vCenter Server Agent Service Unknown Installer Error". Maintenance mode hangs at 32%.',
    'case-excerpts', ['vc.ha_agent_install'], [
        (-3000, VPXD, '{t} error vpxd[05993] [Originator@6876 sub=vpxLro opID=op-412] [VpxLRO] -- ERROR task-5521 -- host-401 -- vim.Folder.configureHA: Cannot Install. The vCenter Server Agent Service Unknown Installer Error.', 'case'),
        (-2990, 'var/run/log/esxupdate.log', '{t} esxupdate: 2099: root: ERROR: Removing the old HA agent failed: missing Mellanox components required', 'case'),
        (-2400, 'var/run/log/fdm.log', '{t} warning fdm[2200] [Originator@6876 sub=Cluster] HA agent version differs from the other cluster hosts', 'typical')],
    cause='The affected host runs a different HA agent version than the other hosts, and removing the old agent fails because the Mellanox VIB components it needs are missing - they were probably removed during a GPU driver installation.',
    resolution=['Compare the installed components/VIBs with a healthy host to confirm the missing Mellanox components.',
                'Install the missing components: esxcli software component apply -n <component>:<version> -d <depot_url_or_offline_bundle_path> (engage NVIDIA / the vendor for the correct bundle).',
                'Then disable and re-enable vSphere HA on the cluster.',
                'If that fails, manually remove the old HA agent first and install the new agent from the /tmp folder.'],
    kbs=[kb(301499, 'Cannot install the vCenter Server agent', 'primary'), kb(318929, 'Error: vSphere HA agent cannot be corrected', 'secondary'), kb(322223), kb(328258)])

tpl('CT-23', 'Skyline Health: "Reconfigure for VMware HA on a primary node may cause unexpected VM failover" (no log evidence)', 'vcenter', '8.0 U3',
    'Skyline Health reports that performing a Reconfigure for VMware HA operation on a primary node may cause an unexpected virtual machine failover. The customer set das.config.fdm.policy.unknownStateMonitorPeriod to 30 per the KB but the alert keeps coming back.',
    'no-log', ['esx.fdm'], [], bundle=False, cause='', resolution=[],
    kbs=[kb('legacy:2017778', 'KB followed by the customer (das.config.fdm.policy.unknownStateMonitorPeriod = 30)', 'cited')],
    notes='The case was misrouted and the report contains no resolution.')

# ============================================================================= guest / VMware Tools
tpl('CT-24', 'Windows VMware Tools upgrade fails at the PVSCSI driver step and rolls back', 'guest', 'Tools 12.5.3 / 13.0.1',
    'The VMware Tools upgrade fails while installing the PVSCSI driver. The installer rolls back and removes Tools and drivers, leaving the server unreachable. Not every server is affected.',
    'mixed', ['guest.tools_install'], [
        (-1500, 'guest/vminst.log', '{t}| tools-build-24816017| I1: Inst_StopService: Attempting to stop service: \'vmci\' [stop dependents = 0]', 'typical'),
        (-1400, 'guest/vminst.log', '{t}| tools-build-24816017| E1: InstallFinalize: Return value 3 at VM_InstallPVSCSIDriver (MSI error 1603)', 'case'),
        (-1390, 'guest/vminst.log', '{t}| tools-build-24816017| E1: Installation failed, rolling back. Return value 3', 'typical')],
    cause='Working theory in the case: the Windows driver store/policy prefers an existing pvscsi package (for example a Windows-published oem*.inf) or blocks class-driver updates, so the Tools installer cannot replace the PVSCSI driver. Evidence in the case: MSI 1603 with InstallFinalize Return value 3 at VM_InstallPVSCSIDriver.',
    resolution=['Operational workaround: run the Tools installer with Custom Setup, deselect "PVSCSI", complete the Tools upgrade, then update the PVSCSI driver manually via Device Manager if needed.',
                'For bulk upgrades the customer can automate the Custom Setup (exclude PVSCSI) in their own PowerCLI process.',
                'To confirm driver ownership collect C:\\Windows\\inf\\setupapi.dev.log and setupapi.app.log for the install time and the output of pnputil /enum-drivers (pvscsi provider and version).',
                'If Windows owns pvscsi: manual driver update from the Tools package or, under change control and after a snapshot, remove the conflicting oemNN.inf and reinstall.'],
    kbs=[kb(390706, 'VMware Tools upgraded fail while installing PVSCSI driver', 'primary')], match=r'PVSCSI|1603',
    notes='Engineering was asked to consider a future Tools patch; no ETA. The case was soft-closed with this workaround.')

tpl('CT-25', 'Automatic VMware Tools upgrade after reboot fails and the VM loses network', 'guest', 'Tools (build 24816017)',
    'After a reboot starts the automatic VMware Tools upgrade the installation fails and the VM has no network. It happens to 1-2 of about 400 VMs each release, always different VMs; a manual upgrade from the mounted Tools image works.',
    'case-excerpts', ['guest.tools_install'], [
        (-1500, 'guest/vminst.log', '{t}| tools-build-24816017| I1: Inst_StopService: Attempting to stop service: \'vmci\' [stop dependents = 0]', 'case'),
        (-1499, 'guest/vminst.log', '{t}| tools-build-24816017| I2: Inst_StopService: service status: SERVICE_RUNNING cp=0x00000000', 'case'),
        (-1498, 'guest/vminst.log', '{t}| tools-build-24816017| E1: Inst_StopService: Service could not be stopped| winerror code 1052 (The requested control is not valid for this service.)', 'case'),
        (-1497, 'guest/vminst.log', '{t}| tools-build-24816017| I1: Inst_UninstallService: Service was deleted: vmci', 'case'),
        (-1496, 'guest/vminst.log', '{t}| tools-build-24816017| I1: Inst_UninstallService: Service still present, might check again', 'case')],
    cause='Windows could not stop the vmci service (winerror 1052) during the automatic upgrade; the case treated it as a guest-side/Windows condition and advised checking that the firewall/security tooling allows the upgrade.',
    resolution=['Perform a manual Tools upgrade from the mounted Tools image on the affected VM (this resolved it for the customer).',
                'Review vminst.log and the Windows event logs for the failing step; check endpoint security/firewall policy does not block the automatic upgrade.'],
    kbs=[], match=r'vmci|1052',
    notes='The case cited no KB (KB research lists related articles on VMCI/VGAuth locks and overlapping Windows updates).')

# ============================================================================= SDDC Manager
tpl('CT-26', 'SDDC Manager stuck on "VMware Cloud Foundation is initializing" after the vCenter root password expired', 'sddc', '9.0.1',
    'The management vCenter root password expired and was changed directly on vCenter. SDDC Manager now stays on "VMware Cloud Foundation is initializing..." even after restarting its services.',
    'case-excerpts', ['vcf.sddc_init'], [
        (-1500, 'var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log', '{t} ERROR [a1b2c3d4e5f60718, 0f1e2d3c4b5a6978, 1122334455667788] [services/wrappers/requestPromiseWrapper.js, init-pscs-primary, logAxiosError:58] axios.error.response.data {"data":"Authentication failed for host vc01.lab.example"}', 'case'),
        (-1499, 'var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log', '{t} ERROR [a1b2c3d4e5f60718, 0f1e2d3c4b5a6978] [services/pscUtils.js, init-pscs, attemptPSCInit:67] Caught error from await primaryPscInit', 'case'),
        (-1498, 'var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log', '{t} WARN [a1b2c3d4e5f60718, 0f1e2d3c4b5a6978] [services/pscUtils.js, init-pscs, attemptPSCInitWithRetry:111] 100.109: VError: PSC Initilization attempt "2" failed: Failed to initiate PSC: Primary psc init failed and failover psc init also failed: Unable to retrieve iDP Metadata: Request failed with status code 500', 'case')],
    cause='The vCenter root password was reset directly on the vCenter, but SDDC Manager still holds the old password, so its authentication to the vCenter/PSC fails (HTTP 500 retrieving iDP metadata).',
    resolution=['Reset the vCenter root password back to the old password that SDDC Manager holds, so the stored credential matches (this fixed the case).',
                'Then SDDC Manager initialisation completes and the UI loads.'],
    kbs=[kb(322247, 'Resetting the root password in vCenter Server Appliance', 'primary')])

# ============================================================================= second batch (remaining closed cases)
tpl('CT-27', 'VCSA drops to emergency mode after a power outage: File System Check on the root volume failed', 'vcenter', '8.0 U3',
    'After a power outage the vCenter appliance console shows "[FAILED] Failed to start File System Check on /dev/vg_root_0/lv_root0" and enters emergency mode; vCenter is down.',
    'case-excerpts', ['vc.fsck_emergency'], [
        (-1500, 'var/log/messages', '{s} vcsa systemd[1]: [FAILED] Failed to start File System Check on /dev/vg_root_0/lv_root0.', 'case'),
        (-1499, 'var/log/messages', '{s} vcsa systemd[1]: Dependency failed for /.', 'case'),
        (-1498, 'var/log/messages', '{s} vcsa systemd[1]: Entering Emergency Mode. Give root password for maintenance', 'case')],
    cause='An unclean shutdown (power outage) left the root filesystem inconsistent; the boot-time fsck did not repair it automatically, so systemd entered emergency mode.',
    resolution=['Reboot the appliance and, at the GRUB menu, press e to edit the boot entry.',
                'Append fsck.repair=yes to the end of the linux line and press F10 to boot (it may reboot several times while repairing).',
                'Confirm the services come up (service-control --status --all) and take a backup afterwards.'],
    kbs=[kb(326323, 'VCSA fails to boot with filesystem check errors (fsck.repair=yes)', 'primary')], match=r'File System Check|Emergency Mode',
    notes='Case resolved with the KB steps. KB title above is a short description, not the verbatim title.')

tpl('CT-28', 'vCenter 7.0 to 8.0 upgrade pre-check blocks: untrusted ESX Agent Manager URLs and unsupported NSX-V extension', 'vcenter', '7.0 U3 -> 8.0',
    'The upgrade pre-check stops with "Source ESX agent manager Configuration contains URLs that are not trusted by the system" and "This vCenter has extensions registered that are unsupported by the new vCenter Server".',
    'case-excerpts', ['vc.upg_precheck'], [
        (-1500, 'var/log/vmware/upgrade/pre-check.log', '{t} ERROR Source ESX agent manager Configuration contains URLs that are not trusted by the system: https://nsx.lab.example/bin/vdn/vibs-6.4.8/6.4.8-0000000/vxlan.zip', 'case'),
        (-1499, 'var/log/vmware/upgrade/pre-check.log', '{t} ERROR This vCenter has extensions registered that are unsupported by the new vCenter Server: Extensions NSX manager', 'case')],
    cause='A stale NSX-V (legacy) ESX Agent Manager agency still references a VIB URL that is not trusted, and the NSX-V extension is not supported by the target vCenter version.',
    resolution=['Follow the KBs referenced by the pre-check to clean up/untrust the legacy EAM agency and remove the unsupported NSX extension.', 'Re-run the upgrade pre-check until it is clean.'],
    kbs=[kb(313026, '', 'cited'), kb(326202, '', 'cited')], match=r'not trusted|unsupported by the new',
    notes='The case closed without a customer reply, so the fix was not confirmed. KB titles were not captured in the report.')

tpl('CT-29', 'Replication product says the HBR agent cannot be installed: "vLCM image has deltas" although the cluster is compliant', 'vcenter', 'VMware Live Recovery 9.0.4',
    'The replication UI reports "The Host Based Replication Agent for ESX can\'t be installed on <cluster>. The vLCM image has deltas that need to be applied" while the cluster shows compliant in vLCM.',
    'case-excerpts', ['vr.hbr_agent'], [
        (-1500, 'var/log/vmware/hms/hms.log', '{t} INFO  [hms] Compliance status: ClusterCompliance (com.vmware.esx.settings.cluster_compliance) => { impact = REBOOT_REQUIRED, status = COMPLIANT }', 'case'),
        (-1499, 'var/log/vmware/hms/hms.log', "{t} ERROR [hms] The Host Based Replication Agent for ESX can't be installed on cluster-1. The vLCM image has deltas that need to be applied", 'case')],
    cause='Not established in the case: it was escalated to the vLCM team.',
    resolution=[], kbs=[], match=r'Host Based Replication Agent|vLCM image',
    notes='Opening snapshot only; no resolution and no KB in the report.')

tpl('CT-30', 'Horizon provisioning fails after a network redundancy loss: cannot read snapshot properties of the replica', 'esxi', '8.0 U3',
    'After the loss of network redundancy, clone operations fail with "Fault type is VC_FAULT_FATAL - Error reading single property config.hardware.device from managed object: snapshot-N" and "Configuration file cannot be found".',
    'case-excerpts', ['vc.clone_property'], [
        (-1500, VPXD, "{t} error vpxd[1] [Originator@6876 sub=Default] Cloning of VM vdi-replica-01 has failed: Fault type is VC_FAULT_FATAL - Error reading single property 'config.hardware.device' from managed object: snapshot-42", 'case'),
        (-1499, VPXD, '{t} error vpxd[1] [Originator@6876 sub=vpxLro] Configuration file cannot be found', 'case')],
    cause='Not established: the case recorded an automated-analysis match for a storage-vMotion failure but no resolution.',
    resolution=[], kbs=[kb(307365, 'Automated analysis rule svmotion_fails (cited in the case)', 'cited')], match=r'single property|cannot be found',
    notes='Opening snapshot only; no resolution in the report.')

tpl('CT-31', 'SRM plugin error after the vCenter certificate was replaced: "Server certificate chain is not trusted"', 'vcenter', 'SRM 9.0.2',
    'After installing a new SSL certificate on vCenter, Site Recovery Manager shows CertificateValidationException: Server certificate chain is not trusted and thumbprint verification is not configured.',
    'case-excerpts', ['srm.cert_trust'], [
        (-1500, 'var/log/vmware/srm/vmware-dr.log', '{t} ERROR com.vmware.vim.vmomi.core.exception.CertificateValidationException: Server certificate chain is not trusted and thumbprint verification is not configured', 'case')],
    cause='The SRM appliance was not reconfigured after the vCenter certificate was renewed, and Lookup Service held duplicate SRM registrations (a stale v8.6 entry next to v9.0.2).',
    resolution=['If the SRM VAMI admin password is lost, reset it first (KB 312789).',
                'Run lsdoctor on the vCenter to find duplicate SRM registrations; unregister the stale one from Lookup Service and remove the stale extension from the vCenter Extension Manager.',
                'Run Reconfigure in the SRM VAMI, then on the paired site, and re-establish the site pairing.'],
    kbs=[kb(320837, 'Using the lsdoctor tool', 'primary'), kb(337576, 'Cleaning up decommissioned SRM registrations', 'secondary')], match=r'thumbprint verification',
    notes='KB 312789 was linked and later unlinked in the case; mentioned only for the password reset.')

tpl('CT-32', '"vSphere HA virtual machine failover failed" alarm on every VM in a cluster', 'vcenter', '9.0',
    'All VMs in a cluster show the alarm "vSphere HA virtual machine failover failed". The customer wants to know how to clear it and requests an RCA.',
    'mixed', ['vc.ha_failover_alarm'], [
        (-1500, VPXD, '{t} warning vpxd[1] [Originator@6876 sub=vpxLro] vSphere HA virtual machine failover failed on vm-app-01', 'typical')],
    cause='Likely a transient HA event: the HA primary declared a host isolated/dead after a network blip, agent restart or metadata inconsistency, and failover attempts failed because the VMs were still running with locked .vmx files. Not proven: no log bundle was ever received.',
    resolution=['Verify the VMs are running and accessible (then the alert is a false positive).',
                'Acknowledge the triggered alarms and reset to green.',
                'If it persists, disable vSphere HA on the cluster, wait for the agents to be removed, then enable it again.'],
    kbs=[kb(313670, 'vSphere HA virtual machine failover failed alert on virtual machines', 'secondary'), kb(318199, 'DRS migrates all VMs to a single ESXi host after reverting vCenter to a snapshot', 'secondary')], match=r'failover failed', bundle=True,
    notes='Customer confirmed by phone the issue was resolved after clearing alarms; the RCA was never done (no bundle).')

tpl('CT-33', '/storage/core partition full of core files, vCenter diagnostics disk exhaustion alarm', 'vcenter', '8.0 U3',
    'vCenter shows "Diagnostics Disk Exhaustion"; /storage/core is at 87% or higher because services crashed repeatedly and left core files.',
    'mixed', [], [
        (-1500, VMON, '{t} warning vmon Disk /storage/core usage is above the critical threshold', 'typical'),
        (-1400, 'var/log/messages', '{s} vcsa systemd-coredump[2201]: Process 1234 (vpxd) of user 0 dumped core.', 'typical')],
    extra_files={'commands/df_h.txt': 'Filesystem                      Size  Used Avail Use% Mounted on\n/dev/mapper/core_vg-core         25G   23G  1.9G  96% /storage/core\n/dev/mapper/log_vg-log          9.8G  2.2G  7.1G  24% /storage/log\n'},
    expect_snapshot=True,
    cause='Repeated service crashes accumulated core dumps (core.vpxd.N, core.netlogond.N) in /storage/core; the appliance stops vpxd when a critical partition exceeds about 95%.',
    resolution=['df -h to confirm /storage/core usage; cd /storage/core and identify the core files.', 'Delete old cores as described in the KB, then acknowledge and reset the alarm to green.', 'Investigate why services crash (most recent core timestamps) if it recurs.'],
    kbs=[kb(318750, '/storage/core partition full due to core files in vCenter Server Appliance', 'primary')], match=r'core',
    notes='Resolved on the first call after deleting cores.')

tpl('CT-34', 'SDDC Manager 5.2.1 down: "Failed to init PSC and/or Postgres" after the management vCenter root password expired', 'sddc', '5.2.1',
    'The SDDC Manager UI shows "Failed to init PSC and/or Postgres. Check the SDDC Manager UI Server logs" or "VMware Cloud Foundation is initializing".',
    'case-excerpts', ['vcf.sddc_init'], [
        (-1500, 'var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log', '{t} ERROR [a1b2c3d4e5f60718] [services/pscUtils.js, init-pscs] Caught error from await primaryPscInit.', 'case'),
        (-1499, 'var/log/vmware/vcf/sddc-manager-ui-app/sddcManagerServer.log', '{t} ERROR [a1b2c3d4e5f60718] [services/pscUtils.js, init-pscs] Failed to initiate PSC: Primary psc init failed and failover psc init also failed', 'case')],
    cause='The root password of the management domain vCenter expired or was changed outside SDDC Manager, so its stored credential no longer works and PSC/Postgres initialisation fails.',
    resolution=['SSH to the SDDC Manager, review sddcManagerServer.log for the primaryPscInit errors.', 'Try root SSH to the management vCenter; a failure or "Password expired" confirms the cause.', 'Reset/change the vCenter root password per the KB (GRUB reset if locked), update the credential in SDDC Manager and restart the UI service.'],
    kbs=[kb(322247, 'Resetting the root password in vCenter Server Appliance', 'primary')], match=r'Failed to initiate PSC|primaryPscInit',
    notes='Same family as CT-26 on a different SDDC Manager version.')

tpl('CT-35', 'VCF 9 vCenter reduced-downtime upgrade fails: OVF deployment NFC upload "TLS handshake timeout"', 'sddc', 'VCF 5.2.2 -> 9.0.2',
    'Upgrading the management vCenter with RDU fails: the OVF deployment fails in vCenter and the LCM log shows "failed to get upgrade status".',
    'case-excerpts', ['vc.rdu_nfc'], [
        (-1500, 'var/log/vmware/vlcm/vlcm.log', '{t} info vlcm [vm/deploy.go:232] [ObjectID=54[1].7] NFC lease: upload(VMware-vCenter-Server-Appliance-9.0.2.0.25148086_OVF10-disk1.vmdk)', 'case'),
        (-1490, 'var/log/vmware/vlcm/vlcm.log', '{t} error vlcm [ova/read.go:118] [ObjectID=54[1].7] ova: failed to read VMware-vCenter-Server-Appliance-9.0.2.0.25148086_OVF10-disk1.vmdk from OVA: Post "https://esx02.lab.example/nfc/00000000-0000-0000-0000-000000000000/disk-0.vmdk": net/http: TLS handshake timeout', 'case'),
        (-1489, 'var/log/vmware/vlcm/vlcm.log', '{t} error vlcm [vm/deploy.go:88] [ObjectID=54[1].7] Deploy failed: deploy: NFC lease: upload(VMware-vCenter-Server-Appliance-9.0.2.0.25148086_OVF10-disk1.vmdk) failed: net/http: TLS handshake timeout', 'case')],
    cause='The vCenter had a proxy configured; the NFC upload of the new appliance disk to the ESXi host timed out in the TLS handshake. Case treated the proxy as the cause and the upgrade succeeded after removing it.',
    resolution=['Temporarily disable or remove the proxy configuration on the vCenter (VAMI or console).', 'Start the Reduced Downtime Upgrade again.', 'After it completes, re-enable the proxy settings.'],
    kbs=[kb(418332, '', 'cited')], match=r'TLS handshake timeout|NFC lease',
    notes='KB 388921 and 395322 were linked then unlinked in the case; only 418332 remained. Titles were not captured.')

tpl('CT-36', 'Cannot remove evaluation / time-limited licence entries from vCenter licensing (no log evidence)', 'vcenter', '8.0 U3',
    'The customer cannot remove evaluation or expired licence entries from the vCenter licensing inventory.',
    'no-log', [], [], bundle=False, cause='', resolution=['Assign valid licences to hosts still on evaluation, remove the key when usage reaches 0, and clean up the remaining entries via the MOB as described in the KBs.'],
    kbs=[kb(334240, '', 'cited'), kb(323148, '', 'cited'), kb('legacy:2115869', '', 'cited')],
    notes='Administrative case: nothing to analyse in logs.')

# ============================================================================= community / KB-derived scenarios (not resolved cases)
CN = 'SYNTHETIC SCENARIO built from public Broadcom KB / community search-result summaries, not from a resolved support case; the article text was not read in full. '
FB = 'var/log/firstboot/'
UP = 'var/log/vmware/upgrade/'

tpl('CT-37', 'Upgrade 8.0 U3h/U3i to 9.0.x fails in stage 2: "Encountered an internal error" in vpostgres firstboot', 'vcenter', '8.0 U3h -> 9.0.1',
    'Stage 2 of the upgrade stops with "Encountered an internal error. see /var/log/firstboot/vpostgres-firstboot.py_<pid>_stderr.log".',
    'mixed', ['vc.upg_stage2_cause'], [
        (-1500, FB + 'vpostgres-firstboot.py_2514_stderr.log', '{t} ERROR Encountered an internal error. see /var/log/firstboot/vpostgres-firstboot.py_2514_stderr.log', 'typical'),
        (-1490, 'var/log/vmware/upgrade/import-upgrade-runner.log', '{t} ERROR Stage 2 failed: firstboot script vpostgres-firstboot.py exited with code 1', 'typical')],
    cause='Per the KB summary the source is 8.0 Update 3h/3i, which Broadcom treats as an unsupported back-in-time upgrade to this 9.x build.',
    resolution=['The summary states there is no workaround: power off the new 9.x appliance and restore the source from the pre-upgrade snapshot or backup.', 'Check the supported upgrade path for the exact source and target builds before retrying.'],
    kbs=[kb(423649, 'vCenter upgrade from 8.0 U3h to 9.0.1 fails with an error "Encountered an internal error..."', 'primary')], match=r'Encountered an internal error|Stage 2', notes=CN)

tpl('CT-38', 'vCenter 9.x upgrade stage 2 pre-check fails: "Unable to retrieve VMDir replication status information"', 'vcenter', '8.0 -> 9.x',
    'The stage 2 pre-check stops with Unable to retrieve VMDir replication status information.',
    'mixed', ['vc.upg_stage2_cause'], [
        (-1500, UP + 'upgrade-precheck.log', '{t} ERROR Unable to retrieve VMDir replication status information', 'typical'),
        (-1499, 'var/log/vmware/vmdird/vmdird-syslog.log', '{t} WARN vmdird: duplicate server object found for vc01.lab.example (192.0.2.10)', 'typical')],
    cause='Likely cause named in the summary: the source was entered by IP address instead of its FQDN/PNID in stage 1, which created a duplicate server object in the directory.',
    resolution=['Remove the duplicate entry from the directory, restart services and retry; use the FQDN/PNID of the source in stage 1.'],
    kbs=[kb(452909, 'vCenter 9.x upgrade stage 2 pre-check fails with "Unable to retrieve VMDir replication status information"', 'primary')], match=r'VMDir replication', notes=CN)

tpl('CT-39', 'Upgrade stage 2 fails: "Invalid root credentials for source appliance" although the password is right', 'vcenter', '8.0 U3 -> 9.0',
    'Stage 2 fails with Invalid root credentials for source appliance; the root password is correct.',
    'mixed', ['vc.upg_stage2_cause'], [
        (-1500, UP + 'import-upgrade-runner.log', '{t} ERROR Invalid root credentials for source appliance', 'typical'),
        (-1499, UP + 'import-upgrade-runner.log', '{t} WARN ssh: connect to host vc-old.lab.example port 22: Connection timed out', 'typical')],
    cause='The summary names blocked SSH on port 22 between target and source as a cause (not proven for any specific environment).',
    resolution=['Allow SSH (TCP 22) between the new appliance and the source, make sure SSH is enabled on the source, and retry stage 2.'],
    kbs=[kb(409555, 'Stage 2 of the vCenter upgrade fails with error - Invalid root credentials for source appliance', 'primary')], match=r'Invalid root credentials', notes=CN)

tpl('CT-40', 'Upgrade stage 2 fails at network switch-over: "IP already exists in the network" / "Failed to set network"', 'vcenter', '8.0 -> 8.0 U3 / 9.0',
    'Stage 2 fails when the new appliance takes over the source IP: IP already exists in the network, or Failed to set network.',
    'mixed', ['vc.upg_stage2_cause'], [
        (-1500, UP + 'import-upgrade-runner.log', '{t} ERROR IP already exists in the network', 'typical'),
        (-1499, UP + 'import-upgrade-runner.log', '{t} ERROR Failed to set network on the target appliance', 'typical')],
    cause='The summaries point to an IP conflict at switch-over (the source still holds the address, or another device answers on it) or a network configuration the target cannot apply. Not proven for any specific environment.',
    resolution=['Make sure the source is shut down/released correctly and nothing else uses the address; check the port group and VLAN for the target; retry per the KB.'],
    kbs=[kb(376335, 'vCenter upgrade fails with an error "Error: IP already exists in the network"', 'primary'), kb(369716, 'vCenter server upgrade fails in stage 2 with an error: "Failed to set network"', 'secondary')], match=r'already exists|Failed to set network', notes=CN)

tpl('CT-41', 'Upgrade stage 2 fails importing Update Manager data (stale legacy records)', 'vcenter', '8.0 U2d / 9.x',
    'Stage 2 fails with "A problem occurred while - Importing VMware vSphere Update Manager data".',
    'mixed', ['vc.upg_stage2_cause'], [
        (-1500, UP + 'import-upgrade-runner.log', '{t} ERROR A problem occurred while - Importing VMware vSphere Update Manager data', 'typical'),
        (-1499, 'var/log/vmware/vmware-updatemgr/vum-server/vmware-vum-server.log', '{t} ERROR foreign key violation on vci_va_upgrade_files', 'typical')],
    cause='The search summary describes stale legacy Update Manager records breaking a foreign-key cleanup during import (the exact KB for 9.x was not identified; the cited article is the 8.0 U2d one).',
    resolution=['Snapshot the source first. Reset the Update Manager database on the source (this removes custom baselines and imported patches) or remove the orphaned vci_va_upgrade_files / vci_va_upgrades rows as the KB describes, then retry.'],
    kbs=[kb(371079, 'Upgrade to vCenter 8.0 U2d fails on stage 2 with error "A problem occurred while- Importing VMware vSphere Update Manager data..."', 'primary')], match=r'Update Manager data', notes=CN)

tpl('CT-42', 'vSphere HA "Agent Unreachable / Uninitialized" after a vCenter 8.0 U3 install or upgrade (certificate mode)', 'vcenter', '8.0 U3',
    'After a vCenter 8.0 U3 install or upgrade, enabling HA fails with HA Agent unreachable or HA Agent uninitialized on one or more hosts.',
    'mixed', ['vc.ha_unreachable'], [
        (-1500, VPXD, '{t} error vpxd[1] [Originator@6876 sub=vpxLro] vSphere HA agent on host esx01.lab.example: HA Agent unreachable', 'typical'),
        (-1490, 'var/run/log/fdm.log', '{t} error fdm[2111] [Originator@6876 sub=Cluster] HA Agent uninitialized', 'typical')],
    cause='The KB summaries point to the vpxd.certmgmt.mode setting being "thumbprint" instead of "vmca", and/or stale host certificates.',
    resolution=['Set the certificate mode to VMCA (vpxd.certmgmt.mode), refresh the host certificates, then toggle vSphere HA off and on for the cluster.'],
    kbs=[kb(379366, 'vSphere HA fails to enable with error "HA Agent unreachable" or "HA Agent uninitialized" after vCenter install/upgrade to 8.0 U3', 'primary'), kb(392316, 'vSphere HA Configuration Fails After vCenter Server 8.0 Update 3 Upgrade with "HA Agent Unreachable."', 'secondary')], match=r'Agent (?:unreachable|uninitialized)', notes=CN)

tpl('CT-43', 'vSphere HA: "agent is not reachable from vCenter Server" caused by a wrong /etc/hosts entry on the ESXi host', 'esxi', '8.0 U3',
    'HA fails to configure on a host with The vSphere HA agent is not reachable from vCenter Server.',
    'mixed', ['vc.ha_unreachable'], [
        (-1500, VPXD, '{t} error vpxd[1] [Originator@6876 sub=vpxLro] The vSphere HA agent is not reachable from vCenter Server', 'typical'),
        (-1490, 'var/run/log/vpxa.log', '{t} warning vpxa[2140] [Originator@6876 sub=vpxaNet] failed to connect to vc01.lab.example (192.0.2.99): No route to host', 'typical')],
    cause='A static /etc/hosts entry on the ESXi host maps the vCenter FQDN to a wrong address (per the KB summary).',
    resolution=['Remove or correct the stale vCenter entry in /etc/hosts on the host, then reconfigure vSphere HA on it.'],
    kbs=[kb(438017, 'vSphere HA fails with error "The vSphere HA agent is not reachable from vCenter Server" due to incorrect /etc/hosts entries', 'primary')], match=r'not reachable', notes=CN)

tpl('CT-44', 'vSphere HA: "Applying HA VIBs on the cluster encountered a failure" (vLCM updateManager firewall ruleset disabled)', 'esxi', '8.0 U3',
    'Enabling HA fails with Applying HA VIBs on the cluster encountered a failure.',
    'mixed', ['vc.ha_agent_install'], [
        (-1500, VPXD, '{t} error vpxd[1] [Originator@6876 sub=vpxLro] Applying HA VIBs on the cluster encountered a failure.', 'typical'),
        (-1490, HOSTD, '{t} warning hostd[2099] [Originator@6876 sub=Default] firewall ruleset updateManager is disabled', 'typical')],
    cause='Per the KB summary the vLCM "updateManager" firewall ruleset is disabled on the hosts, which blocks HA VIB installation.',
    resolution=['Enable the updateManager firewall ruleset on the affected hosts, then retry/Reconfigure for vSphere HA.'],
    kbs=[kb(399646, 'The vSphere HA agent fails with the error "Applying HA VIBs on the cluster encountered a failure" in the vSphere Client', 'primary')], match=r'Applying HA VIBs', notes=CN)

tpl('CT-45', 'vSphere HA: "agent on host cannot reach some management network addresses of other hosts"', 'esxi', '8.0 U3',
    'ESXi hosts show the alert vSphere HA agent on host cannot reach some management network addresses of other hosts.',
    'mixed', ['vc.ha_unreachable'], [
        (-1500, 'var/run/log/fdm.log', '{t} warning fdm[2111] [Originator@6876 sub=Cluster] vSphere HA agent on host esx02.lab.example cannot reach some management network addresses of other hosts', 'typical'),
        (-1490, 'var/run/log/fdm.log', '{t} info fdm[2111] [Originator@6876 sub=Cluster] Agent Unreachable state for host esx03.lab.example', 'typical')],
    cause='The summaries name VLAN, firewall or partition problems on the HA agent ports (TCP/UDP 8182; also 8183, 8042 and DNS 53).',
    resolution=['Verify the management VLAN and firewall rules on the HA ports between all hosts, then Reconfigure for vSphere HA on the host.'],
    kbs=[kb(418585, 'ESX host shows "vSphere HA agent on host cannot reach some management network addresses of other hosts" alert', 'primary'), kb(409440, 'Troubleshooting vSphere HA Agent in Unreachable State', 'secondary')], match=r'management network addresses', notes=CN)

tpl('CT-46', 'vCenter not accessible (503) after a reboot because a certificate expired', 'vcenter', '8.0 U3',
    'After a reboot the vSphere Client and VAMI return 503 / no healthy upstream; vpxd and vpxd-svcs do not start.',
    'mixed', ['vc.cert_expired_svc', 'vc.503'], [
        (-1500, VMON, '{t} error vmon Service vpxd-svcs failed to start: x509: certificate has expired', 'typical'),
        (-1490, 'var/log/vmware/envoy/envoy.log', '{t} warning envoy upstream connect error or disconnect/reset before headers: no healthy upstream', 'typical'),
        (-1480, 'var/log/vmware/vpxd/vpxd.log', '{t} error vpxd Machine SSL certificate has expired on 2026-03-01', 'typical')],
    cause='A required VECS certificate (Machine SSL in the KB 451480 summary) expired; services refuse to start once restarted.',
    resolution=['Enable SSH from the appliance console if needed, check expiry with vecs-cli or the vCert tool, renew the expired certificate, check NTP and reverse DNS, and restart all services (service-control --stop --all && --start --all). Snapshot first.'],
    kbs=[kb(344201, 'Error: "no healthy upstream" or "503 Service Unavailable" when accessing vCenter Server', 'primary'), kb(451480, 'vCenter Server VAMI 503 Error and Service Startup Failures Due to Expired SSL Certificates on vCenter 8.0.3', 'secondary')], match=r'expired|no healthy upstream', notes=CN)

tpl('CT-47', 'VAMI (port 5480) returns "503 - OK": applmgmt service stopped', 'vcenter', '8.0',
    'The vCenter Appliance Management Interface returns 503 - OK (Service Unavailable).',
    'mixed', ['vc.service_down'], [
        (-1500, VMON, '{t} error vmon Service applmgmt stopped unexpectedly', 'typical'),
        (-1490, 'var/log/vmware/applmgmt/applmgmt.log', '{t} ERROR applmgmt service not running, port 5480 closed', 'typical')],
    cause='The KB summary names the applmgmt service being stopped as the usual cause; if it will not start, certificates are the next check.',
    resolution=['service-control --status applmgmt, then service-control --start applmgmt; if it fails to start check the certificates.'],
    kbs=[kb(378577, 'Attempting to access the vCenter Appliance Management Interface results in a 503 - OK Error (Service Unavailable)', 'primary')], match=r'applmgmt', notes=CN)

tpl('CT-48', 'VCSA boots to a black screen with a blinking cursor (filesystem corruption)', 'vcenter', '8.0',
    'After a power-on or host crash the vCenter VM console shows only a blinking cursor and never boots.',
    'mixed', ['vc.fsck_emergency'], [
        (-1500, 'var/log/messages', '{s} vcsa kernel: EXT4-fs error (device dm-0): ext4_lookup:1700: inode #131073: comm systemd: deleted inode referenced', 'typical')],
    cause='The KB summary names filesystem corruption of the appliance as the cause.',
    resolution=['Snapshot or back up the VCSA first (connect directly to the ESXi host if it runs on a host it manages). Reboot, edit the GRUB entry and add the forced fsck parameters to the linux line, then boot.'],
    kbs=[kb(413871, 'VMware vCenter Server fails to boot and shows a black screen with a blinking/flashing cursor', 'primary')], match=r'EXT4-fs error', notes=CN)

tpl('CT-49', 'VM registration / power-on hangs after an ESXi boot-drive failure: orphaned .lck files', 'esxi', '8.0 U3',
    'After an ESXi host lost its boot drive, registering or powering on its VMs hangs from vCenter.',
    'mixed', ['esx.vm_open_disk'], [
        (-1500, HOSTD, '{t} error hostd[2099] [Originator@6876 sub=Vmsvc.vm:/vmfs/volumes/ds01/app01/app01.vmx] Failed to start the virtual machine. Module Disk power on failed. Cannot open the disk \'/vmfs/volumes/ds01/app01/app01.vmdk\' or one of the snapshot disks it depends on. 16 (Device or resource busy)', 'typical')],
    cause='Per the KB summary: orphaned lock files left by the failed host.',
    resolution=['Log in to a healthy ESXi host (SSH or Browse Datastore), find and move the *.lck files in the VM folder, then register and power on the VM from that host. Back up first.'],
    kbs=[kb(435528, 'VM registration or power-on hangs in vCenter due to orphaned locks after ESXi boot drive failure', 'primary')], match=r'Cannot open the disk', notes=CN)

# ============================================================================= not templated (kept in the report only)
out = dict(version=1,
           source='ANONYMISED templates derived from %d resolved support case reports (CT-01..CT-36) plus synthetic scenarios built from public KB/community summaries (CT-37 onwards, marked in their notes). Hostnames, addresses and identifiers are invented; log lines are synthetic (basis case = wording from the case excerpt, typical = written for the template).' % 42,
           reviewed_cases=42,
           templates=T)
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'lvx', 'case_templates.json')
with open(path, 'w', encoding='utf-8', newline='\n') as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
    f.write('\n')
print('wrote', os.path.normpath(path), len(T), 'templates;', sum(1 for t in T if t['bundle']), 'with bundles')
