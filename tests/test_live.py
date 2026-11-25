"""Live SSH collector: argument safety (no network needed) + the real polling protocol against a local `sh`."""
import os
import shutil
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from lvx import live                                           # noqa: E402

SH = shutil.which('sh') or shutil.which('bash')


def posix(p):
    p = os.path.abspath(p).replace('\\', '/')
    return '/' + p[0].lower() + p[2:] if len(p) > 1 and p[1] == ':' else p


class Safety(unittest.TestCase):
    def test_paths(self):
        self.assertEqual(live.validate_path('/var/log/vmware/vpxd/vpxd.log'), '/var/log/vmware/vpxd/vpxd.log')
        for bad in ('/etc/shadow', '/var/log/../../etc/passwd', '/var/log/a b', '/var/log/$(id)', '/var/log/x;rm -rf /', 'var/log/x', '/var/log/`id`', '/var/log//x', ''):
            with self.assertRaises(live.LiveError, msg=bad):
                live.validate_path(bad)

    def test_target(self):
        self.assertEqual(live.validate_target('esx01.lab.example', 'root', '22'), ('esx01.lab.example', 'root', 22))
        for h, u, p in (('-oProxyCommand=x', 'root', 22), ('host; id', 'root', 22), ('h', '-x', 22), ('h', 'ro ot', 22), ('h', 'root', 0), ('h', 'root', 70000), ('h', 'root', 'x')):
            with self.assertRaises(live.LiveError, msg=(h, u, p)):
                live.validate_target(h, u, p)

    def test_ssh_argv_has_no_password_and_ends_with_sh(self):
        a = live.ssh_argv('esx01', 'root', 2222, ssh_bin='ssh')
        self.assertIn('BatchMode=yes', a)
        self.assertEqual(a[-1], 'sh')
        self.assertEqual(a[a.index('--') + 1], 'root@esx01')
        p = live.ssh_argv('esx01', 'root', 22, host_key='strict', password=True, ssh_bin='ssh')
        self.assertNotIn('BatchMode=yes', p)
        self.assertIn('StrictHostKeyChecking=yes', p)
        with self.assertRaises(live.LiveError):
            live.ssh_argv('esx01', 'root', 22, host_key='off', ssh_bin='ssh')

    def test_poll_script_rejects_injection(self):
        with self.assertRaises(live.LiveError):
            live.build_poll_script([('/var/log/x; rm -rf /', 0)], 'abc')
        with self.assertRaises(live.LiveError):
            live.build_poll_script([], 'abc', [('xo-server; id', None)])
        with self.assertRaises(live.LiveError):
            live.build_poll_script([], 'abc', [('xo-server', "x'; id #")])


@unittest.skipUnless(SH, 'needs a POSIX sh')
class Protocol(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='lvx_live_')
        self.remote = os.path.join(self.tmp, 'remote', 'var', 'run', 'log')
        os.makedirs(self.remote)
        self.work = os.path.join(self.tmp, 'mirror')
        os.makedirs(self.work)
        self.prefix = posix(os.path.join(self.tmp, 'remote')) + '/'
        self._pref = live.ALLOWED_PREFIXES
        live.ALLOWED_PREFIXES = self._pref + (self.prefix,)
        self.vmk = posix(os.path.join(self.remote, 'vmkernel.log'))
        self.hostd = posix(os.path.join(self.remote, 'hostd.log'))
        self.missing = posix(os.path.join(self.remote, 'nothere.log'))
        live.PRODUCTS['_t'] = dict(label='test', logs=[self.vmk, self.hostd, self.missing], commands={'df_-h': 'df -h'})
        self.sessions = []

    def tearDown(self):
        live.ALLOWED_PREFIXES = self._pref
        live.PRODUCTS.pop('_t', None)
        for s in self.sessions:
            s.stop()
            if s.shell:
                s.shell.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def session(self):
        s = live.LiveSession('t1', lambda: live.ProcShell([SH]), '_t', self.work, interval=2)
        s.shell = live.ProcShell([SH])
        self.sessions.append(s)
        return s

    def write(self, name, text, mode='ab'):
        with open(os.path.join(self.remote, name), mode) as f:
            f.write(text.encode())

    def mirror(self, remote):
        with open(self.sessions[0].local_path(remote), 'rb') as f:
            return f.read()

    def test_incremental_is_byte_exact_and_detects_new_fault(self):
        s = self.session()
        base = ''.join('2026-11-20T09:%02d:00.000Z cpu1:2097100)vmnic1: NIC Link is Up 10000 Mbps Full Duplex\n' % i for i in range(40))
        self.write('vmkernel.log', base)
        s.poll_once()
        self.assertEqual(self.mirror(self.vmk), base.encode())
        self.assertIn(self.missing, s.missing)
        # more data arrives, including a partial last line that is completed on the next poll
        fault = ('2026-11-20T10:00:00.000Z cpu4:1)StorageApdHandler: 1389: Device or filesystem with identifier [naa.600] has entered the All Paths Down Timeout state after being in the All Paths Down state for 140 seconds. I/Os will now be fast failed.\n'
                 '2026-11-20T10:00:01.000Z cpu4:1)WARNING: ScsiDevice: 5812: Device naa.600 has been removed or is permanently inaccessible\n')
        self.write('vmkernel.log', fault[:70])
        s.poll_once()
        self.write('vmkernel.log', fault[70:])
        s.poll_once()
        self.assertEqual(self.mirror(self.vmk), (base + fault).encode())
        s.analyze()
        self.assertIn('esx.apd', [f['id'] for f in s.result['findings']][:2])
        self.assertTrue(any(e['kind'] == 'finding' and 'All Paths Down' in e['msg'] for e in s.events))

    def test_rotation_is_archived_not_lost(self):
        s = self.session()
        self.write('hostd.log', 'old line 1\n' * 200)
        s.poll_once()
        self.write('hostd.log', '2026-11-20T10:00:00.000Z info hostd[1] fresh after rotation\n', mode='wb')
        s.poll_once()
        self.assertEqual(self.mirror(self.hostd), b'2026-11-20T10:00:00.000Z info hostd[1] fresh after rotation\n')
        self.assertTrue([f for f in os.listdir(os.path.dirname(s.local_path(self.hostd))) if f.endswith('.prev')])

    def test_command_snapshots_feed_df_detection(self):
        s = self.session()
        s.snapshot_commands()
        self.assertTrue(os.path.isfile(os.path.join(self.work, 'commands', 'df_-h.txt')))

    def test_thread_loop_and_stop(self):
        self.write('vmkernel.log', '2026-11-20T09:00:00.000Z cpu1:1)vmnic1: NIC Link is Up 10000 Mbps Full Duplex\n')
        s = live.LiveSession('t2', lambda: live.ProcShell([SH]), '_t', self.work, interval=2)
        self.sessions.append(s)
        s.start()
        for _ in range(60):
            if s.last_poll:
                break
            time.sleep(0.5)
        self.assertEqual(s.state, 'live', s.error)
        s.stop()
        s.thread.join(10)
        self.assertEqual(s.state, 'stopped')

    def test_dead_shell_reports_a_clear_error(self):
        with self.assertRaises(live.LiveError):
            live.ProcShell([SH, '-c', 'echo boom >&2; exit 3'])


@unittest.skipUnless(SH, 'needs a POSIX sh')
class ServerLive(unittest.TestCase):
    """HTTP API end to end: start a live session (sh instead of ssh), see the fault appear, pull evidence and a redacted report."""

    def setUp(self):
        import json, threading, urllib.request
        from lvx import server, live_profiles
        self.json, self.urlreq = json, urllib.request
        self.tmp = tempfile.mkdtemp(prefix='lvx_srvlive_')
        os.environ['LVX_HOME'] = os.path.join(self.tmp, 'home')
        self.remote = os.path.join(self.tmp, 'remote', 'var', 'log')
        os.makedirs(self.remote)
        self._pref = live.ALLOWED_PREFIXES
        live.ALLOWED_PREFIXES = self._pref + (posix(os.path.join(self.tmp, 'remote')) + '/',)
        self.log = posix(os.path.join(self.remote, 'vmkernel.log'))
        live.PRODUCTS['_t'] = dict(label='test', logs=[self.log], commands={'df_-h': 'df -h'})
        self._open, self._argv = live_profiles.open_ssh, live_profiles.ssh_argv
        live_profiles.open_ssh = lambda *a, **k: live.ProcShell([SH])
        live_profiles.ssh_argv = lambda *a, **k: ['ssh']
        with open(os.path.join(self.remote, 'vmkernel.log'), 'w') as f:
            f.write('2026-11-20T09:00:00.000Z cpu1:1)vmnic1: NIC Link is Up 10000 Mbps Full Duplex' + chr(10))
        self.srv = server.create_server('127.0.0.1', 0, live_enabled=True)
        self.base = 'http://127.0.0.1:%d' % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        from lvx import live_profiles
        self.srv.lvx_state.cleanup()
        self.srv.shutdown()
        self.srv.server_close()
        live_profiles.open_ssh, live_profiles.ssh_argv = self._open, self._argv
        live.ALLOWED_PREFIXES = self._pref
        live.PRODUCTS.pop('_t', None)
        os.environ.pop('LVX_HOME', None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def call(self, method, path, body=None):
        req = self.urlreq.Request(self.base + path, method=method, data=self.json.dumps(body).encode() if body is not None else None)
        try:
            with self.urlreq.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except Exception as e:
            if hasattr(e, 'code'):
                return e.code, e.read()
            raise

    def test_end_to_end(self):
        code, raw = self.call('POST', '/api/live/start', dict(host='127.0.0.1', user='root', product='_t', interval=2, window_h=2, password='s3cret-pw'))
        self.assertEqual(code, 200, raw)
        info = self.json.loads(raw)
        for _ in range(40):                      # wait until connected + first analysis
            st = self.json.loads(self.call('GET', '/api/live/' + info['live'])[1])
            if st['state'] == 'live' and st['bytes']:
                break
            time.sleep(0.5)
        self.assertEqual(st['state'], 'live', st)
        self.assertNotIn('s3cret-pw', self.call('GET', '/api/live/' + info['live'])[1].decode())     # password never echoed
        with open(os.path.join(self.remote, 'vmkernel.log'), 'a') as f:
            f.write('2026-11-20T09:05:00.000Z cpu4:1)StorageApdHandler: 1389: Device or filesystem with identifier [naa.60] has entered the All Paths Down Timeout state after being in the All Paths Down state for 140 seconds. I/Os will now be fast failed.' + chr(10))
        for _ in range(40):
            st = self.json.loads(self.call('GET', '/api/live/%s?since=0' % info['live'])[1])
            if any(e['kind'] == 'finding' for e in st['events']):
                break
            time.sleep(0.5)
        self.assertTrue(any('All Paths Down' in e['msg'] for e in st['events']), st['events'])
        job = self.json.loads(self.call('GET', '/api/jobs/' + info['job'])[1])
        self.assertEqual(job['state'], 'done')
        self.assertEqual(job['result']['findings'][0]['id'], 'esx.apd')
        fid = job['result']['findings'][0]['id']
        code, ev = self.call('GET', '/api/evidence?job=%s&finding=%s&ctx=1' % (info['job'], fid))
        self.assertEqual(code, 200)
        self.assertIn('All Paths Down', ev.decode())
        code, rep = self.call('GET', '/api/report/%s.md?redact=1' % info['job'])
        self.assertEqual(code, 200)
        self.assertIn('Action plan and drafts', rep.decode())
        self.assertEqual(self.call('POST', '/api/live/%s/stop' % info['live'])[0], 200)

    def test_disabled_without_flag(self):
        self.srv.lvx_state.live_enabled = False
        self.assertEqual(self.call('GET', '/api/live/config')[0], 403)

    def test_bad_input_is_rejected(self):
        for bad in (dict(host='-oProxyCommand=x', user='root', product='_t'), dict(host='h', user='root', product='nope'),
                    dict(host='h', user='root', product='_t', extra_logs=['/etc/passwd'])):
            code, _ = self.call('POST', '/api/live/start', bad)
            self.assertEqual(code, 400, bad)

    def test_profiles_never_store_a_password(self):
        code, _ = self.call('POST', '/api/live/profiles', dict(name='lab esx', host='esx01', user='root', product='esxi', password='nope', key='C:/k'))
        self.assertEqual(code, 200)
        with open(os.path.join(self.tmp, 'home', 'profiles.json')) as f:
            self.assertNotIn('nope', f.read())

    def test_refuses_remote_bind_without_token(self):
        from lvx import server
        os.environ.pop('LVX_TOKEN', None)
        with self.assertRaises(SystemExit):
            server.create_server('0.0.0.0', 0, live_enabled=True)


if __name__ == '__main__':
    unittest.main()
