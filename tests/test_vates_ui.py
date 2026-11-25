"""Playwright UI test for a Vates bundle (verdict controls, raw-log context, viewer, persistence). Skipped when node/playwright/Chromium are missing."""
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..'))
from lvx import templates                 # noqa: E402
from lvx.server import create_server      # noqa: E402


def _env():
    node = shutil.which('node')
    if not node:
        return None
    try:
        root = subprocess.run(['npm', 'root', '-g'], capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None
    if not root or not os.path.isdir(os.path.join(root, 'playwright')):
        return None
    exe = os.environ.get('CHROMIUM_PATH') or next(iter(sorted(glob.glob('/opt/pw-browsers/chromium-*/chrome-linux/chrome'))), None)
    return dict(os.environ, NODE_PATH=root, **({'CHROMIUM_PATH': exe} if exe else {}))


class VatesUi(unittest.TestCase):
    def test_ui_flow_and_screenshots(self):
        env = _env()
        if not env:
            self.skipTest('node + global playwright module not available')
        d = tempfile.mkdtemp(prefix='lvx_ui_')
        srv = create_server('127.0.0.1', 0)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            t = templates.get('CT-53')
            templates.build_bundle(t, os.path.join(d, 'CT-53'))
            out = os.environ.get('LVX_UI_OUT') or os.path.join(d, 'shots')
            p = subprocess.run(['node', os.path.join(HERE, 'ui_vates_playwright.js'), 'http://127.0.0.1:%d' % srv.server_address[1], os.path.join(d, 'CT-53'), out,
                                t['issue'], '2026-03-10T10:00:00Z'], env=env, capture_output=True, text=True, timeout=240)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            for f in ('vates-findings-confirm.png', 'vates-viewer.png'):
                self.assertGreater(os.path.getsize(os.path.join(out, f)), 5000)
        finally:
            srv.shutdown()
            srv.lvx_state.cleanup()
            shutil.rmtree(d, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
