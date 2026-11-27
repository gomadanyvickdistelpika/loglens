"""Ten-case synthetic test + performance benchmark for LogLens Vates.

Ten multi-incident synthetic bundles (XCP-ng host / pool / storage / VM and Xen Orchestra), each 14 days of background logs with benign
near-miss lines, the same signatures 12 days earlier as decoys, and a planted incident whose ROOT CAUSE has a known expected rule.  One case is a
clean negative.  Every case is analysed in its own process and the following is recorded:

  accuracy   root rule at rank 1 / in top 3, expected secondary findings within the top 8, false high/critical rule findings,
             evidence correctness (the stored sample line really is that line of the file)
  noise      lines scanned vs lines inside the incident window
  speed      extract + analyse wall time, lines/second, peak RSS, bundle size

IN-SAMPLE CAVEAT: I wrote the rules and these cases, so the accuracy numbers show the pipeline works, not real-world recall.  The cases use fresh wording
(not copied from rule patterns or earlier scenarios) but are still my own approximation of real logs.  Timings depend on the machine.

Usage:
  python tests/ten_case_benchmark.py run   [--out docs/ten-case-test] [--step 15]   run all 10 (full size), write RESULTS.md + results.json
  python tests/ten_case_benchmark.py build OUT_DIR                                  write the 10 compact bundles (.tgz) + CASES.md
  python tests/ten_case_benchmark.py worker T01 --step 15                           (internal) one case, JSON on stdout
"""
import argparse
import json
import os
import platform
try:
    import resource                                       # POSIX only
except ImportError:                                       # Windows
    resource = None
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, '..')
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import vates_gen as vg                                    # noqa: E402

X, SM, DM, KN, HA, XJ, XU, XI = vg.X, vg.SM, vg.DM, vg.KN, vg.HA, vg.XJ, vg.XU, vg.XI
SHOW_IN_REPORT = 8       # also-expected findings must be within the top N

C = []


def case(id, name, kind, issue, root, also, allowed, lines, desc):
    C.append(dict(id=id, name=name, kind=kind, issue=issue, root=root, also=also, allowed=allowed, lines=lines, desc=desc))


case('T01', 'HA pool: hosts self-fence after a management-network blip', 'xcpng',
     'Three hosts in an HA pool rebooted within a minute of each other and the ERP VMs were restarted on other hosts. The network team saw a short switch outage.',
     'xcp.ha_fence', ['xcp.master_unreachable'], ['xcp.vm_start_fail'], [
         (-2700, HA, '{s} xcp03 xhad[{n}]: lost heartbeat from xcp01 over the management interface'),
         (-2690, HA, '{s} xcp03 xhad[{n}]: statefile is not accessible, leaving the liveset'),
         (-2680, HA, '{s} xcp03 xhad[{n}]: this host is going to fence itself now'),
         (-2400, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] Unable to reach the pool coordinator 192.0.2.11, entering emergency mode'),
         (-2300, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xenops] Async.VM.start failed: HVM_BOOT_FAILED for VM erp01')],
     'Root cause: HA heartbeat/statefile loss -> self-fence. Downstream: members lose the coordinator, VMs fail to start while hosts reboot.')
case('T02', 'Storage cascade across XCP-ng and XO: SR full -> coalesce -> chain -> backup + VM start', 'vates',
     'Nightly backups started failing a week ago and today a CRM VM will not start. The NFS storage repository is nearly full.',
     'xcp.sr_full', ['xcp.coalesce_stuck', 'xcp.sr_chain', 'xcp.xo_backup', 'xcp.vm_start_fail'], [], [
         (-9000, SM, '{s} xcp01 SM: [{n}] SR_BACKEND_FAILURE_44 insufficient space on SR nfs-sr01'),
         (-7200, SM, '{s} xcp01 SMGC: [{n}] Leaf-coalesce failed, no space left for the coalesce'),
         (-6000, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] SR_BACKEND_FAILURE_109(, The snapshot chain is too long, )'),
         (-5000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job nightly failed: VDI_IO_ERROR(Device I/O errors)'),
         (-600, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xenops] Failed to start the VM crm02: HVM boot failed')],
     'Root cause: SR out of space. Effects in order: coalesce cannot run, VHD chain grows, XO backups fail, a VM cannot start.')
case('T03', 'iSCSI multipath storm: paths fail, the SR drops, disk I/O errors', 'xcpng',
     'After switch maintenance an iSCSI SR went offline and a dozen VMs froze. Storage says the array is healthy.',
     'xcp.multipath_fail', ['xcp.sr_unplugged', 'xcp.io_error'], ['xcp.mount_stall'], [
         (-3600, DM, '{s} xcp02 multipathd[812]: mpathc: sdd - tur checker reports path is down'),
         (-3590, KN, '{s} xcp02 kernel: device-mapper: multipath: Failing path 8:48.'),
         (-3500, DM, '{s} xcp02 multipathd[812]: mpathc: remaining active paths: 0'),
         (-3300, SM, '{s} xcp02 SM: [{n}] SR is not available: /dev/disk/by-scsid/360000000000000000e00000000010002 does not exist'),
         (-3200, X, '{s} xcp02 xapi: [error|xcp02|{n} ||xapi] PBD_PLUG_FAILED for SR san-sr02'),
         (-3000, KN, '{s} xcp02 kernel: blk_update_request: I/O error, dev sde, sector 8192 op 0x0:(READ)')],
     'Root cause: all multipath paths lost. Effects: the SR cannot be plugged, reads fail with I/O errors.')
case('T04', 'dom0 out of memory kills xapi, XO shows the host disconnected and backups fail', 'vates',
     'xe commands on xcp01 hang, Xen Orchestra shows the host as disconnected and the nightly backup did not run.',
     'xcp.dom0_oom', ['xcp.xapi_down', 'xcp.xo_backup'], [], [
         (-4200, KN, '{s} xcp01 kernel: xenopsd-xc invoked oom-killer: gfp_mask=0x24201ca, order=0, oom_score_adj=0'),
         (-4199, KN, '{s} xcp01 kernel: Out of memory: Killed process 5521 (xapi) total-vm:2204576kB, anon-rss:1148576kB, file-rss:0kB'),
         (-4100, DM, '{s} xcp01 systemd[1]: xapi.service: main process exited, code=killed, status=9/KILL'),
         (-4000, X, '{s} xcp01 xe: Connection refused (calling connect )'),
         (-3000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job nightly failed: HTTP connection has been closed')],
     'Root cause: kernel OOM killed xapi. Effects: toolstack down, XO loses the host, backup job fails.')
case('T05', 'Leaked storage datapath after an aborted export: backups and VM start fail', 'vates',
     'Weekly backup of one VM failed and now the VM will not start on its host; its disk seems to be still in use.',
     'xcp.datapath_leak', ['xcp.xo_backup', 'xcp.vm_start_fail'], [], [
         (-5400, SM, '{s} xcp01 SM: [{n}] VDI 9f8e7d6c is not detached cleanly'),
         (-5390, SM, '{s} xcp01 SM: [{n}] Failed to lock /var/lock/sm/5e4d3c2b/sr on first attempt, blocked by PID 9120'),
         (-5380, X, '{s} xcp01 xapi: [error|xcp01|{n} ||storage_access] Illegal_transition: Attached -> Activated'),
         (-4000, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker ERROR Backup job weekly failed: VDI_IO_ERROR'),
         (-1200, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Failed to start the VM file01: VM_BAD_POWER_STATE')],
     'Root cause: a VDI/datapath left attached on the host. Effects: export fails, later attach/start fails.')
case('T06', 'dom0 disk full from log spam: xapi down and updates fail', 'xcpng',
     'Host xcp04 is disconnected in XO and yum updates fail. The control domain disk usage alarm fired last night.',
     'xcp.host_disk_full', ['xcp.xapi_down', 'xcp.update_fail'], [], [
         (-6000, DM, '{s} xcp04 rsyslogd: file /var/log/messages write error - discarding: No space left on device'),
         (-5900, X, '{s} xcp04 xapi: [error|xcp04|{n} ||xapi] Could not write the database: ENOSPC'),
         (-5000, DM, '{s} xcp04 systemd[1]: xapi.service: main process exited, code=exited, status=1/FAILURE'),
         (-4000, DM, '{s} xcp04 yum[{n}]: Error downloading packages: xen-hypervisor-4.17: [Errno 256] No more mirrors to try.')],
     'Root cause: dom0 filesystem full. Effects: xapi cannot write its database and exits, yum cannot download.')
case('T07', 'Xen Orchestra cannot connect to the pool after a certificate change', 'xo',
     'After the certificate on the pool master was replaced, Xen Orchestra shows the pool as disconnected.',
     'xcp.xo_tls', [], [], [
         (-3000, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.30 connection failed: UNABLE_TO_VERIFY_LEAF_SIGNATURE'),
         (-2990, XJ, '{s} xo01 xo-server[771]: {u} xo:xo-mixins:xen-servers WARN server 192.0.2.30 connection failed: self signed certificate'),
         (-2800, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker INFO Backup job nightly completed successfully in 11m')],
     'Root cause: untrusted/self-signed certificate. A successful backup line is a benign near-miss.')
case('T08', 'XOA update fails because the appliance disk is full', 'xo',
     'Updating the Xen Orchestra appliance fails every time with an obscure error.',
     'xcp.xo_disk_full', ['xcp.xoa_update'], [], [
         (-3000, XU, '{s} xoa xoa-updater[412]: ERROR ENOSPC: no space left on device, write'),
         (-2990, XU, '{s} xoa xoa-updater[412]: ERROR upgrade failed'),
         (-2980, XI, '{s} xoa xo-install[1301]: error ENOSPC: no space left on device')],
     'Root cause: appliance filesystem full. Effect: the updater fails.')
case('T09', 'Rolling Pool Update stops: not enough free memory to evacuate a host', 'xcpng',
     'A Rolling Pool Update from XO stops on the first host and the task is stuck.',
     'xcp.vm_no_memory', ['xcp.update_fail'], [], [
         (-7000, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] host.evacuate: HOST_NOT_ENOUGH_FREE_MEMORY for VM sql02'),
         (-6990, X, '{s} xcp01 xapi: [error|xcp01|{n} ||xapi] Rolling pool update: aborted because of CANNOT_EVACUATE_HOST'),
         (-6900, DM, '{s} xcp01 yum[{n}]: Cannot retrieve repository metadata (repomd.xml) for repository: xcp-ng-updates')],
     'Root cause: not enough free memory to move VMs off the host. Effect: the update stops.')
case('T10', 'Healthy pool with heavy benign noise (negative case)', 'vates',
     'Routine check after the weekend, nothing reported.',
     None, [], [], [
         (-6000, SM, '{s} xcp01 SMGC: [{n}] Coalesce of 7a6b5c4d finished successfully, SR has 62% free'),
         (-5900, DM, '{s} xcp01 multipathd[812]: mpatha: remaining active paths: 2'),
         (-5800, KN, '{s} xcp01 kernel: megaraid_sas 0000:03:00.0: firmware crash dump: disabled'),
         (-5700, KN, '{s} xcp01 kernel: oom_score_adj of xapi set to -1000'),
         (-5600, XJ, '{s} xo01 xo-server[771]: {u} xo:backups:worker INFO Backup job nightly completed successfully in 9m'),
         (-5500, X, '{s} xcp01 xapi: [ info|xcp01|{n} ||xapi] HA is enabled: 3 hosts, plan exists for 1 failure')],
     'No incident. Counts false positives: nothing at high/critical severity may be reported.')


def scenario(c):
    return dict(name=c['id'], kind=c['kind'], issue=c['issue'], expect=[c['root']] if c['root'] else [], lines=c['lines'], min_rank=1)


def build_case(c, dest, step):
    vg.STEP = step
    return vg.build_dir(dest, scenario(c), noisy=True, seed=int(c['id'][1:]) + 100)


def run_worker(cid, step):
    from lvx.analyzer import Analyzer
    from lvx.bundle import open_bundle
    from lvx.timeparse import fmt_ts
    c = next(x for x in C if x['id'] == cid)
    tmp = tempfile.mkdtemp(prefix='lvx_10c_')
    try:
        src = os.path.join(tmp, cid)
        truth = build_case(c, src, step)
        total_lines = sum(1 for dp, _d, fns in os.walk(src) for fn in fns if not fn.endswith('.gz') for _ in open(os.path.join(dp, fn), 'rb'))
        tgz = vg.pack(src, os.path.join(tmp, cid + '.tgz'), 'tgz', inner_name=cid)
        mb = os.path.getsize(tgz) / 1e6
        t0 = time.time()
        b = open_bundle('b', tgz)
        t_open = time.time() - t0
        res = Analyzer(b, issue=truth['issue'], anchor=truth['anchor'], before_s=24 * 3600, after_s=3 * 3600).run()
        wall = time.time() - t0
        ev_ok = None
        ranked = [f['id'] for f in res['findings']]
        rules = [f for f in res['findings'] if f['kind'] == 'rule']
        if c['root']:
            f0 = next((f for f in res['findings'] if f['id'] == c['root']), None)
            if f0:
                s = f0['samples'][0]
                with open(b.resolve(s['file']), encoding='utf-8', errors='replace') as fh:
                    for n, line in enumerate(fh, 1):
                        if n == s['line']:
                            ev_ok = line.rstrip('\n')[:500] == s['text'][:500]
                            break
        b.close()
        expected = ([c['root']] if c['root'] else []) + c['also'] + c['allowed']
        false_high = [f['id'] for f in rules if f['severity'] in ('high', 'critical') and f['id'] not in expected]
        st = res['stats']
        row = dict(id=cid, name=c['name'], kind=c['kind'], root=c['root'], top5=[f['id'] for f in rules][:5],
                   root_rank=(ranked.index(c['root']) + 1) if c['root'] and c['root'] in ranked else None,
                   also_expected=c['also'], also_found=[a for a in c['also'] if a in ranked[:SHOW_IN_REPORT]],
                   false_high=false_high, evidence_ok=ev_ok,
                   lines_total=total_lines, lines_in_window=st.get('lines_in_window', 0),
                   noise_removed_pct=round(100.0 * (1 - st.get('lines_in_window', 0) / max(total_lines, 1)), 2),
                   findings=len(res['findings']), rule_findings=len(rules),
                   bundle_mb=round(mb, 2), extract_s=round(t_open, 2), analyse_s=round(res['stats']['seconds'], 2), wall_s=round(wall, 2),
                   lines_per_s=int(total_lines / max(wall, 1e-6)), peak_rss_mb=(round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0, 1) if resource else 0.0),
                   window=res['window']['start'] + ' -> ' + res['window']['end'], anchor=fmt_ts(truth['anchor']))
        if c['root']:
            row['passed'] = (row['root_rank'] == 1 and len(row['also_found']) == len(c['also']) and not false_high and ev_ok is True)
        else:
            row['passed'] = not false_high
        return row
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def write_report(rows, out, step, wall_total, scale=()):
    ok = [r for r in rows if r['root']]
    top1 = sum(1 for r in ok if r['root_rank'] == 1)
    top3 = sum(1 for r in ok if r['root_rank'] and r['root_rank'] <= 3)
    also_t = sum(len(r['also_expected']) for r in ok)
    also_f = sum(len(r['also_found']) for r in ok)
    fh = sum(len(r['false_high']) for r in rows)
    ev = sum(1 for r in ok if r['evidence_ok'])
    passed = sum(1 for r in rows if r['passed'])
    tl = sum(r['lines_total'] for r in rows)
    tw = sum(r['wall_s'] for r in rows)
    agg = dict(cases=len(rows), passed=passed, top1=top1, top3=top3, positives=len(ok), also_found=also_f, also_expected=also_t, false_high=fh,
               evidence_ok=ev, evidence_total=len(ok), total_lines=tl, total_wall_s=round(tw, 1), avg_lines_per_s=int(tl / max(tw, 1e-6)),
               max_peak_rss_mb=max(r['peak_rss_mb'] for r in rows), max_wall_s=max(r['wall_s'] for r in rows),
               avg_noise_removed_pct=round(sum(r['noise_removed_pct'] for r in rows) / len(rows), 2), step_s=step,
               python=platform.python_version(), platform=platform.platform(), cpus=os.cpu_count(), run_date=time.strftime('%Y-%m-%d', time.gmtime()))
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'results.json'), 'w', encoding='utf-8') as f:
        json.dump(dict(aggregate=agg, cases=rows, scaling=list(scale)), f, indent=1)
    L = ['# LogLens Vates - 10-case synthetic test and performance results', '',
         'Run on %s (Python %s, %s CPU(s), %s). Each case: 14 days of background logs (one line every %ss per file, plus benign warnings/near-misses), the same signatures 12 days earlier as decoys, and a planted incident.'
         % (agg['run_date'], agg['python'], agg['cpus'], agg['platform'], step), '',
         '> **In-sample caveat.** The rules and these cases were written by the same author. The cases use fresh wording but are still approximations of real logs, so the numbers below show the pipeline works - not real-world recall. Please try real, sanitised XCP-ng / XO logs.', '',
         '## Summary', '',
         '| Metric | Result |', '|---|---|',
         '| Cases passed (root cause #1, secondary findings in top %d, no false high/critical, evidence line correct) | **%d / %d** |' % (SHOW_IN_REPORT, passed, len(rows)),
         '| Root cause ranked #1 | %d / %d (%.0f%%) |' % (top1, len(ok), 100.0 * top1 / max(len(ok), 1)),
         '| Root cause within top 3 | %d / %d |' % (top3, len(ok)),
         '| Expected secondary findings found in top %d | %d / %d |' % (SHOW_IN_REPORT, also_f, also_t),
         '| False high/critical rule findings (all cases incl. the clean negative) | %d |' % fh,
         '| Evidence correct (stored sample line equals the file line) | %d / %d |' % (ev, len(ok)),
         '| Lines scanned in total | %s |' % format(tl, ','),
         '| Average noise removed by the incident window | %.1f%% of lines |' % agg['avg_noise_removed_pct'],
         '| Total / slowest wall time (extract + analyse) | %.1f s / %.1f s |' % (tw, agg['max_wall_s']),
         '| Average throughput | %s lines/s |' % format(agg['avg_lines_per_s'], ','),
         '| Highest peak memory (RSS, per-case process) | %.0f MB |' % agg['max_peak_rss_mb'], '',
         '## Per case', '',
         '| # | Case | Expected root | Rank | Top rule findings | Secondary | False high | Evidence | Lines | In window | Wall s | lines/s | RSS MB | Result |',
         '|---|---|---|---|---|---|---|---|---|---|---|---|---|---|']
    for r in rows:
        L.append('| %s | %s | `%s` | %s | %s | %s | %s | %s | %s | %s | %.1f | %s | %.0f | %s |' % (
            r['id'], r['name'], r['root'] or 'none (negative)', r['root_rank'] or '-', ', '.join('`%s`' % t.replace('xcp.', '') for t in r['top5'][:4]) or '-',
            '%d/%d' % (len(r['also_found']), len(r['also_expected'])) if r['also_expected'] else '-', ', '.join(r['false_high']) or '0',
            {True: 'ok', False: 'WRONG', None: '-'}[r['evidence_ok']], format(r['lines_total'], ','), format(r['lines_in_window'], ','),
            r['wall_s'], format(r['lines_per_s'], ','), r['peak_rss_mb'], 'PASS' if r['passed'] else '**FAIL**'))
    if scale:
        L += ['', '## Scaling (case T02 at three sizes)', '', '| Background line every | Lines scanned | Bundle MB | Wall s | lines/s | Peak RSS MB | Rank-1 correct |', '|---|---|---|---|---|---|---|']
        for r in scale:
            L.append('| %s s | %s | %.1f | %.1f | %s | %.0f | %s |' % (r['step'], format(r['lines_total'], ','), r['bundle_mb'], r['wall_s'], format(r['lines_per_s'], ','), r['peak_rss_mb'], 'yes' if r['root_rank'] == 1 else 'NO'))
        a0, a2 = scale[0], scale[-1]
        L += ['', 'Measured: %.1fx more lines (%s -> %s) took %.1fx the wall time and %.1fx the peak memory (%.0f -> %.0f MB, about %.2f KB per line). So time scales roughly linearly with the number of lines and memory grows with it; '
                  'very large bundles (tens of millions of lines) have not been tested and would need a lot of RAM.' % (
                      a2['lines_total'] / a0['lines_total'], format(a0['lines_total'], ','), format(a2['lines_total'], ','), a2['wall_s'] / max(a0['wall_s'], 1e-6),
                      a2['peak_rss_mb'] / max(a0['peak_rss_mb'], 1e-6), a0['peak_rss_mb'], a2['peak_rss_mb'], (a2['peak_rss_mb'] - a0['peak_rss_mb']) * 1024.0 / max(a2['lines_total'] - a0['lines_total'], 1))]
    L += ['', '## The ten cases', '']
    for c in C:
        L += ['**%s - %s**  ' % (c['id'], c['name']), '*Issue given to the tool:* %s  ' % c['issue'], '*Ground truth:* %s' % c['desc'], '']
    L += ['## How the test works', '',
          '1. `python tests/ten_case_benchmark.py run` builds each bundle deterministically (`tests/vates_gen.py` noise + the planted lines), packs it as `.tgz`, and runs the analysis **in a separate process** (so peak memory is per case).',
          '2. The analysis uses the real code path: extract the archive, scan every log file, window the lines around the incident, rank findings, attach KB research.',
          '3. A case **passes** when the expected root-cause rule is rank 1, every expected secondary rule is in the top %d, no *other* rule finding at high/critical severity appears, and the first stored evidence line equals the real line in the file. The negative case passes when no rule finding at high/critical severity appears.' % SHOW_IN_REPORT,
          '4. Rules allowed as extra findings in a case (benign companions such as a VM start failure) are listed per case in the script and are not counted as false positives; anything else at high/critical is.',
          '5. `python tests/ten_case_benchmark.py build OUT` writes compact versions of the ten bundles (one line per 300 s) as `.tgz` for trying them in the web UI; they are also in `examples/ten-case-test/`.', '',
          '## Limits', '',
          '* In-sample: see the caveat above. Held-out wording was used, but by the same author as the rules.',
          '* Timings come from one machine and one run; the sandbox is not a benchmark lab. Throughput depends on disk, CPU and Python version.',
          '* Real XCP-ng logs have more variety (long Python tracebacks, rotated `.gz` files, multi-line messages) than these synthetic ones.',
          '* Total run time of the script: %.0f s.' % wall_total, '']
    with open(os.path.join(out, 'RESULTS.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(L))
    return agg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('cmd', choices=['run', 'build', 'worker'])
    ap.add_argument('arg', nargs='?')
    ap.add_argument('--step', type=int, default=15)
    ap.add_argument('--out', default=os.path.join(ROOT, 'docs', 'ten-case-test'))
    a = ap.parse_args()
    if a.cmd == 'worker':
        print(json.dumps(run_worker(a.arg, a.step)))
        return 0
    if a.cmd == 'build':
        out = a.arg or 'ten-case-bundles'
        os.makedirs(out, exist_ok=True)
        md = ['# Ten synthetic cases', '', 'Compact bundles (one background line per 300 s). Upload one in the web UI, paste the issue, set the incident time shown below.', '']
        for c in C:
            tmp = tempfile.mkdtemp(prefix='lvx_10b_')
            try:
                src = os.path.join(tmp, c['id'])
                truth = build_case(c, src, 300)
                vg.pack(src, os.path.join(out, '%s.tgz' % c['id']), 'tgz', inner_name=c['id'])
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            from lvx.timeparse import fmt_ts
            md += ['## %s - %s' % (c['id'], c['name']), '', '* Bundle: `%s.tgz`' % c['id'], '* Issue: %s' % c['issue'], '* Incident time: `%s`' % fmt_ts(truth['anchor']),
                   '* Expected rank 1: `%s`' % (c['root'] or 'nothing at high/critical (negative case)'), '* Also expected: %s' % (', '.join('`%s`' % x for x in c['also']) or '-'), '* %s' % c['desc'], '']
        with open(os.path.join(out, 'CASES.md'), 'w', encoding='utf-8') as f:
            f.write('\n'.join(md))
        print('wrote', out)
        return 0
    t0 = time.time()
    rows = []
    for c in C:
        p = subprocess.run([sys.executable, os.path.abspath(__file__), 'worker', c['id'], '--step', str(a.step)], capture_output=True, text=True, timeout=1800)
        if p.returncode:
            print(p.stderr[-2000:])
            raise SystemExit('worker %s failed' % c['id'])
        r = json.loads(p.stdout.strip().splitlines()[-1])
        rows.append(r)
        print('%s %-4s rank=%s also=%d/%d false_high=%s ev=%s lines=%s wall=%.1fs rss=%.0fMB  %s' % (
            r['id'], 'PASS' if r['passed'] else 'FAIL', r['root_rank'], len(r['also_found']), len(r['also_expected']), r['false_high'] or 0, r['evidence_ok'],
            format(r['lines_total'], ','), r['wall_s'], r['peak_rss_mb'], r['name']), flush=True)
    scale = []
    for st_ in (60, 15, 5):
        p = subprocess.run([sys.executable, os.path.abspath(__file__), 'worker', 'T02', '--step', str(st_)], capture_output=True, text=True, timeout=3000)
        if p.returncode:
            raise SystemExit('scaling worker failed: ' + p.stderr[-1000:])
        r = json.loads(p.stdout.strip().splitlines()[-1])
        r['step'] = st_
        scale.append(r)
        print('scaling T02 step=%ss lines=%s wall=%.1fs rss=%.0fMB' % (st_, format(r['lines_total'], ','), r['wall_s'], r['peak_rss_mb']), flush=True)
    agg = write_report(rows, a.out, a.step, time.time() - t0, scale)
    print('\n%d/%d passed; top1 %d/%d; false high %d; avg %s lines/s; max RSS %.0f MB; wrote %s' % (
        agg['passed'], agg['cases'], agg['top1'], agg['positives'], agg['false_high'], format(agg['avg_lines_per_s'], ','), agg['max_peak_rss_mb'], a.out))
    return 0 if agg['passed'] == agg['cases'] else 1


if __name__ == '__main__':
    sys.exit(main())
