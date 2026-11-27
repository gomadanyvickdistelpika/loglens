"""Live collection over SSH + continuous analysis (a read-only 'PuTTY + log analyser').

Design
* ONE persistent `ssh` process per session (the system OpenSSH client: ships with Windows 10/11, macOS, Linux).  LogLens never
  implements the SSH protocol itself and never stores a password.  Auth = key file / ssh-agent / ~/.ssh/config, or a password
  held in memory only and handed to ssh through SSH_ASKPASS.
* READ-ONLY by construction: the only things ever sent to the remote shell are (a) a fixed script template that tails files
  from a byte offset, and (b) commands from a fixed per-product allowlist.  Paths are validated (absolute, no '..', fixed
  prefixes) and shell-quoted; there is no way to send arbitrary commands.
* New bytes are appended to a local mirror directory that has the same layout as a support bundle, so the normal Analyzer,
  log viewer, evidence view and exports work unchanged on live data.
Standard library only."""
import os
import queue
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid

PRODUCTS = {
    'esxi': dict(
        label='ESXi host',
        logs=['/var/run/log/vmkernel.log', '/var/run/log/hostd.log', '/var/run/log/vmkwarning.log', '/var/run/log/vpxa.log',
              '/var/run/log/fdm.log', '/var/run/log/vobd.log', '/var/run/log/syslog.log'],
        commands={'df_-h': 'df -h', 'uptime': 'uptime', 'esxcli_system_version_get': 'esxcli system version get'}),
    'vcsa': dict(
        label='vCenter Server Appliance',
        logs=['/var/log/vmware/vpxd/vpxd.log', '/var/log/vmware/vmon/vmon.log', '/var/log/vmware/vpostgres/postgresql.log',
              '/var/log/vmware/rhttpproxy/rhttpproxy.log', '/var/log/vmware/envoy/envoy.log', '/var/log/vmware/applmgmt/applmgmt.log',
              '/var/log/vmware/sso/ssoAdminServer.log', '/var/log/vmware/vsphere-ui/logs/vsphere_client_virgo.log'],
        commands={'df_-h': 'df -h', 'uptime': 'uptime', 'service-control_--status_--all': 'service-control --status --all'}),
    'xcpng': dict(
        label='XCP-ng host',
        logs=['/var/log/xensource.log', '/var/log/SMlog', '/var/log/daemon.log', '/var/log/kern.log', '/var/log/xha.log', '/var/log/messages'],
        commands={'df_-h': 'df -h', 'free_-m': 'free -m', 'uptime': 'uptime', 'xe_sr-list': 'xe sr-list params=name-label,physical-size,physical-utilisation',
                  'xe_pool-list': 'xe pool-list params=name-label,master,ha-enabled', 'xe_host-list': 'xe host-list params=name-label,software-version',
                  'multipath_-ll': 'multipath -ll', 'chronyc_tracking': 'chronyc tracking', 'systemctl_is-active_xapi': 'systemctl is-active xapi',
                  'openssl_x509_enddate': 'openssl x509 -enddate -noout -in /etc/xensource/xapi-ssl.pem'}),
    'xo': dict(
        label='Xen Orchestra (XOA / from sources)',
        logs=[], journal=['xo-server', 'xo-proxy', 'xo-updater'],
        commands={'df_-h': 'df -h', 'free_-m': 'free -m', 'uptime': 'uptime', 'systemctl_is-active_xo-server': 'systemctl is-active xo-server'}),
}
ALLOWED_PREFIXES = ('/var/log/', '/var/run/log/', '/storage/log/', '/scratch/log/')
PATH_RX = re.compile(r'^/[A-Za-z0-9._/@+-]{1,300}$')
UNIT_RX = re.compile(r'^[A-Za-z0-9@._-]{1,80}$')
HOST_RX = re.compile(r'^[A-Za-z0-9._:-]{1,255}$')
USER_RX = re.compile(r'^[A-Za-z0-9._@-]{1,64}$')
BACKFILL = 4 << 20          # bytes of history fetched per file when a session starts
MAX_CHUNK = 8 << 20         # bytes per file per poll
FILE_CAP = 200 << 20        # stop mirroring one file beyond this


class LiveError(Exception):
    pass


def validate_path(p):
    p = (p or '').strip()
    if not PATH_RX.match(p) or '..' in p.split('/') or '//' in p or not p.startswith(ALLOWED_PREFIXES):
        raise LiveError('log path not allowed (must be under %s, no ".."): %r' % (', '.join(ALLOWED_PREFIXES), p))
    return p


def validate_target(host, user, port):
    if not HOST_RX.match(host or '') or (host or '').startswith('-'):
        raise LiveError('invalid host name')
    if user and (not USER_RX.match(user) or user.startswith('-')):
        raise LiveError('invalid user name')
    try:
        port = 22 if port in (None, '') else int(port)
    except (TypeError, ValueError):
        raise LiveError('invalid port')
    if not 1 <= port <= 65535:
        raise LiveError('invalid port')
    return host, user, port


# ------------------------------------------------------------------------------------------------ remote shell transports
class ProcShell:
    """A persistent shell process; `exec(script)` sends a script and returns its stdout bytes (framed by a random nonce)."""

    def __init__(self, argv, env=None):
        self.argv = argv
        self.err = []
        self._q = queue.Queue()
        self._buf = b''
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        try:
            self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      env=env, creationflags=flags)
        except OSError as e:
            raise LiveError('cannot start %s: %s' % (argv[0], e))
        threading.Thread(target=self._pump, args=(self.p.stdout, self._q), daemon=True).start()
        threading.Thread(target=self._drain_err, daemon=True).start()
        try:
            self.exec('true', timeout=25, _first=True)
        except LiveError:
            self.close()
            raise

    def _pump(self, stream, q):
        try:
            while True:
                b = stream.read1(1 << 16) if hasattr(stream, 'read1') else stream.read(1 << 16)
                if not b:
                    break
                q.put(b)
        finally:
            q.put(None)

    def _drain_err(self):
        for line in iter(self.p.stderr.readline, b''):
            self.err.append(line.decode('utf-8', 'replace').rstrip())
            del self.err[:-20]

    def alive(self):
        return self.p.poll() is None

    def exec(self, script, timeout=60, _first=False):
        if not self.alive():
            raise LiveError(self.explain('connection closed'))
        nonce = uuid.uuid4().hex
        done = ('@@DONE' + nonce).encode()
        try:
            self.p.stdin.write(('%s\necho; echo @@DONE%s\n' % (script, nonce)).encode())
            self.p.stdin.flush()
        except OSError:
            raise LiveError(self.explain('connection closed'))
        deadline = time.time() + timeout
        while done not in self._buf:
            left = deadline - time.time()
            if left <= 0:
                raise LiveError(self.explain('timed out after %ss' % timeout))
            try:
                chunk = self._q.get(timeout=min(left, 1.0))
            except queue.Empty:
                continue
            if chunk is None:
                raise LiveError(self.explain('connection closed'))
            self._buf += chunk
        data, _, rest = self._buf.partition(done)
        self._buf = rest.lstrip(b'\r\n')
        return data[:-1] if data.endswith(b'\n') else data       # drop the `echo` newline we added

    def explain(self, what):
        time.sleep(0.2)
        tail = ' | '.join(x for x in self.err[-4:] if x)
        return '%s%s' % (what, (': ' + tail) if tail else '')

    def close(self):
        try:
            if self.alive():
                self.p.stdin.close()
                self.p.terminate()
            self.p.wait(5)
        except (OSError, subprocess.TimeoutExpired):
            try:
                self.p.kill()
            except OSError:
                pass
        for st in (self.p.stdin, self.p.stdout, self.p.stderr):
            try:
                st.close()
            except OSError:
                pass


def _find_ssh():
    exe = shutil.which('ssh')
    if not exe and os.name == 'nt':
        for c in (os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'OpenSSH', 'ssh.exe'),):
            if os.path.isfile(c):
                return c
    return exe


def ssh_argv(host, user=None, port=22, key=None, host_key='accept-new', password=False, ssh_bin=None):
    host, user, port = validate_target(host, user, port)
    exe = ssh_bin or _find_ssh()
    if not exe:
        raise LiveError('OpenSSH client (ssh) not found. On Windows: Settings > Apps > Optional features > OpenSSH Client.')
    if host_key not in ('strict', 'accept-new'):
        raise LiveError('host_key must be "strict" or "accept-new"')
    a = [exe, '-T', '-p', str(port), '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
         '-o', 'StrictHostKeyChecking=' + ('yes' if host_key == 'strict' else 'accept-new'), '-o', 'LogLevel=ERROR']
    if password:
        a += ['-o', 'PreferredAuthentications=password,keyboard-interactive', '-o', 'NumberOfPasswordPrompts=1', '-o', 'PubkeyAuthentication=no']
    else:
        a += ['-o', 'BatchMode=yes']
    if key:
        if not os.path.isfile(key):
            raise LiveError('key file not found: %s' % key)
        a += ['-i', key, '-o', 'IdentitiesOnly=yes']
    a += ['--', ('%s@%s' % (user, host)) if user else host, 'sh']
    return a


class _Askpass:
    """Hands a password to ssh through SSH_ASKPASS without writing it to disk (it travels in the child's environment only)."""

    def __init__(self, password):
        self.dir = tempfile.mkdtemp(prefix='lvx_ap_')
        if os.name == 'nt':
            self.path = os.path.join(self.dir, 'askpass.cmd')
            body = '@echo off\r\necho(%LVX_PW%\r\n'
        else:
            self.path = os.path.join(self.dir, 'askpass.sh')
            body = '#!/bin/sh\nprintf "%s\\n" "$LVX_PW"\n'
        with open(self.path, 'w', newline='') as f:
            f.write(body)
        os.chmod(self.path, stat.S_IRWXU)
        self.env = dict(os.environ, SSH_ASKPASS=self.path, SSH_ASKPASS_REQUIRE='force', DISPLAY=os.environ.get('DISPLAY') or 'lvx:0', LVX_PW=password)

    def close(self):
        shutil.rmtree(self.dir, ignore_errors=True)


def open_ssh(host, user=None, port=22, key=None, host_key='accept-new', password=None, ssh_bin=None):
    argv = ssh_argv(host, user, port, key, host_key, bool(password), ssh_bin)
    ap = _Askpass(password) if password else None
    try:
        sh = ProcShell(argv, env=ap.env if ap else None)
    except LiveError as e:
        hint = ''
        m = str(e)
        if 'Permission denied' in m:
            hint = ' (check user/key/password; ESXi and vCenter must allow SSH and a shell)'
        elif 'Host key verification failed' in m or 'REMOTE HOST IDENTIFICATION' in m:
            hint = ' (the server key differs from ~/.ssh/known_hosts - verify before trusting it)'
        raise LiveError(m + hint)
    finally:
        if ap:
            ap.close()
    return sh


# ------------------------------------------------------------------------------------------------ polling protocol
def build_poll_script(files, nonce, journal=()):
    """files: [(path, offset)] offset=-1 -> initial backfill.  Output per file:  @@F<nonce> <path> <size> <start> then the bytes then @@E<nonce>."""
    L = []
    for path, off in files:
        q = shlex.quote(validate_path(path))
        off = int(off)
        L.append(
            'f=%s; if [ -r "$f" ]; then s=$(wc -c < "$f"); o=%d; '
            'if [ $o -lt 0 ]; then o=$((s-%d)); [ $o -lt 0 ] && o=0; fi; '
            'if [ $s -lt $o ]; then o=0; fi; n=$((s-o)); [ $n -gt %d ] && n=%d; '
            'echo "@@F%s $f $s $o"; if [ $n -gt 0 ]; then tail -c +$((o+1)) "$f" | head -c $n; fi; echo; echo "@@E%s"; '
            'else echo "@@X%s $f"; fi' % (q, off, BACKFILL, MAX_CHUNK, MAX_CHUNK, nonce, nonce, nonce))
    for unit, cursor in journal:
        if not UNIT_RX.match(unit):
            raise LiveError('invalid journal unit')
        if cursor and not re.match(r'^[A-Za-z0-9=;:_,.-]{1,300}$', cursor):
            raise LiveError('invalid journal cursor')
        sel = ('--after-cursor=%s' % shlex.quote(cursor)) if cursor else '-n 3000'
        L.append('echo "@@J%s %s"; journalctl -u %s %s -o short-iso --no-pager --show-cursor </dev/null 2>/dev/null; echo; echo "@@E%s"' % (nonce, unit, shlex.quote(unit), sel, nonce))
    return '\n'.join(L)


def parse_poll(data, nonce):
    """-> list of dict(kind='file'|'missing'|'journal', path/unit, size, start, data(bytes))"""
    out = []
    pos = 0
    hdr = re.compile(rb'@@([FXJ])' + nonce.encode() + rb' ([^\n]*)\n')
    end = ('\n@@E%s' % nonce).encode()
    while True:
        m = hdr.search(data, pos)
        if not m:
            break
        kind, rest = m.group(1), m.group(2).decode('utf-8', 'replace').split(' ')
        if kind == b'X':
            out.append(dict(kind='missing', path=rest[0]))
            pos = m.end()
            continue
        e = data.find(end, m.end() - 1)
        if e < 0:
            break
        body = data[m.end():e]
        if kind == b'F':
            out.append(dict(kind='file', path=rest[0], size=int(rest[1]), start=int(rest[2]), data=body))
        else:
            out.append(dict(kind='journal', unit=rest[0], data=body))
        pos = e + len(end)
    return out


def _strip_trailing_echo(b):
    return b[:-1] if b.endswith(b'\n') else b


# ------------------------------------------------------------------------------------------------ session
class LiveSession:
    def __init__(self, sid, shell_factory, product, workdir, extra_logs=(), interval=10.0, window_h=2.0, issue='', on_result=None, label=''):
        if product not in PRODUCTS:
            raise LiveError('unknown product %r' % product)
        self.id, self.product, self.dir, self.interval = sid, product, workdir, max(2.0, float(interval))
        self.window_s = max(300.0, float(window_h) * 3600)
        self.issue = issue
        self.label = label or PRODUCTS[product]['label']
        prof = PRODUCTS[product]
        self.logs = [validate_path(p) for p in list(prof['logs']) + list(extra_logs)]
        self.journal = list(prof.get('journal', []))
        self.cursors = {u: None for u in self.journal}
        self.offsets = {p: -1 for p in self.logs}
        self.sizes = {}
        self.missing = set()
        self.shell_factory, self.shell = shell_factory, None
        self.on_result = on_result
        self.state, self.error = 'connecting', None
        self.events = []
        self.started = time.time()
        self.last_poll = None
        self.bytes_total = 0
        self.seen_ids = set()
        self.result = None
        self.job_id = self.bundle_id = None
        self._stop = threading.Event()
        self._dirty = True
        self._last_analysis = 0.0
        self._last_snapshot = 0.0
        self.thread = threading.Thread(target=self._run, daemon=True)

    # -- helpers
    def _event(self, kind, msg):
        self.events.append(dict(n=(self.events[-1]['n'] + 1) if self.events else 1, t=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), kind=kind, msg=msg))
        del self.events[:-300]

    def local_path(self, remote):
        return os.path.join(self.dir, *remote.strip('/').split('/'))

    def _append(self, remote, data):
        lp = self.local_path(remote)
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        if os.path.exists(lp) and os.path.getsize(lp) + len(data) > FILE_CAP:
            self._event('warn', 'size cap reached for %s; no longer mirrored' % remote)
            return False
        with open(lp, 'ab') as f:
            f.write(data)
        return True

    def snapshot_commands(self):
        d = os.path.join(self.dir, 'commands')
        os.makedirs(d, exist_ok=True)
        for fname, cmd in PRODUCTS[self.product]['commands'].items():
            try:
                out = self.shell.exec('%s </dev/null 2>&1' % cmd, timeout=40)
            except LiveError as e:
                self._event('warn', 'command %r failed: %s' % (cmd, e))
                continue
            with open(os.path.join(d, fname + '.txt'), 'wb') as f:
                f.write(out)
        self._dirty = True
        self._last_snapshot = time.time()

    def poll_once(self):
        nonce = uuid.uuid4().hex[:16]
        files = [(p, self.offsets[p]) for p in self.logs if p not in self.missing or self.offsets[p] == -1]
        script = build_poll_script(files, nonce, [(u, c) for u, c in self.cursors.items()])
        raw = self.shell.exec(script, timeout=90)
        got = 0
        for it in parse_poll(raw, nonce):
            if it['kind'] == 'missing':
                if it['path'] not in self.missing:
                    self.missing.add(it['path'])
                continue
            if it['kind'] == 'journal':
                data = it['data']
                m = re.search(rb'-- cursor: (\S+)\s*$', data)
                if m:
                    self.cursors[it['unit']] = m.group(1).decode()
                    data = data[:m.start()]
                if data.strip():
                    rel = 'journal/journalctl-%s.txt' % it['unit']
                    lp = os.path.join(self.dir, rel)
                    os.makedirs(os.path.dirname(lp), exist_ok=True)
                    with open(lp, 'ab') as f:
                        f.write(data if data.endswith(b'\n') else data + b'\n')
                    got += len(data)
                continue
            p, data = it['path'], it['data']
            self.missing.discard(p)
            rotated = it['start'] == 0 and self.offsets.get(p, -1) > 0     # remote file shrank: rotated / truncated
            if rotated and os.path.exists(self.local_path(p)):
                os.replace(self.local_path(p), self.local_path(p) + '.%d.prev' % int(time.time()))
                self._event('info', 'log rotated: %s' % p)
            if data and self._append(p, data):
                got += len(data)
            self.offsets[p] = it['start'] + len(data)
            self.sizes[p] = it['size']
        self.bytes_total += got
        self.last_poll = time.time()
        return got

    def analyze(self):
        from .analyzer import Analyzer
        from .bundle import open_bundle
        b = open_bundle('live-' + self.id, self.dir)
        az = Analyzer(b, issue=self.issue, anchor=None, before_s=self.window_s, after_s=3600, min_level='warning')
        res = az.run()
        self._last_analysis = time.time()
        for f in res.get('findings', []):
            if f['id'] not in self.seen_ids and f.get('kind') == 'rule' and f['confidence'] != 'low':
                self.seen_ids.add(f['id'])
                self._event('finding', 'NEW %s: %s (score %s)' % (f['severity'].upper(), f['title'], f['score']))
        self.result = res
        if self.on_result:
            self.on_result(res)

    def _run(self):
        try:
            self.shell = self.shell_factory()
            self._event('info', 'connected; reading %d log file(s)' % len(self.logs))
            self.state = 'live'
            self.snapshot_commands()
            while not self._stop.is_set():
                try:
                    if time.time() - self._last_snapshot >= 300:        # refresh df / memory / SR space / services for the Vates Toolbox
                        self.snapshot_commands()
                    got = self.poll_once()
                    self._dirty = self._dirty or got > 0
                    if self._dirty and (time.time() - self._last_analysis >= self.interval or self.result is None):
                        self.analyze()
                        self._dirty = False
                    self.error = None
                except LiveError as e:
                    self.error = str(e)
                    self._event('error', str(e))
                    if not self.shell.alive():
                        self.state = 'reconnecting'
                        self._reconnect()
                self._stop.wait(self.interval)
        except Exception as e:                       # connection failed at start, or analyzer bug
            self.state, self.error = 'error', str(e)
            self._event('error', str(e))
        finally:
            if self.state != 'error':
                self.state = 'stopped'
            if self.shell:
                self.shell.close()

    def _reconnect(self):
        for wait in (3, 6, 12, 24, 48):
            if self._stop.wait(wait):
                return
            try:
                self.shell.close()
                self.shell = self.shell_factory()
                self.state = 'live'
                self._event('info', 'reconnected')
                return
            except LiveError as e:
                self._event('error', 'reconnect failed: %s' % e)
        self.state = 'error'
        self._stop.set()

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self._stop.set()

    def status(self, since=0):
        return dict(id=self.id, label=self.label, product=self.product, state=self.state, error=self.error,
                    started=self.started, last_poll=self.last_poll, bytes=self.bytes_total, interval=self.interval,
                    window_h=self.window_s / 3600.0, files=[dict(path=p, size=self.sizes.get(p), mirrored=max(self.offsets[p], 0), missing=p in self.missing) for p in self.logs],
                    events=[e for e in self.events if e['n'] > since], findings=len((self.result or {}).get('findings', [])))
