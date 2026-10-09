"""Entry point for the Windows executable: start the local server and open the browser."""
import socket
import sys

from lvx.server import serve


def free_port(preferred=8765):
    for p in (preferred, 0):
        with socket.socket() as s:
            try:
                s.bind(('127.0.0.1', p))
                return s.getsockname()[1]
            except OSError:
                continue
    return 8765


if __name__ == '__main__':
    print('LogLens - close this window to stop.')
    serve('127.0.0.1', free_port(), open_browser=True)
    sys.exit(0)
