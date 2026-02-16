# Stub for standalone testing outside Whonix
import os
import socket
import subprocess
import tempfile

def tor_status():
    """Return tor_enabled if tor is running, tor_disabled otherwise.
    Checks: PID file, process list, then control ports (9051/9151)."""
    if os.path.exists('/run/tor/tor.pid'):
        return 'tor_enabled'
    try:
        ret = subprocess.call(['pgrep', '-x', 'tor'],
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        if ret == 0:
            return 'tor_enabled'
    except FileNotFoundError:
        pass
    for port in (9051, 9151):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect(('127.0.0.1', port))
            return 'tor_enabled'
        except (OSError, socket.error):
            pass
        finally:
            if s:
                try:
                    s.close()
                except OSError:
                    pass
    return 'tor_disabled'

def set_disabled():
    pass

def set_enabled():
    pass

def write_to_temp_then_move(content):
    """Write content to the torrc file."""
    torrc_path = '/usr/local/etc/torrc.d/40_tor_control_panel.conf'
    try:
        os.makedirs(os.path.dirname(torrc_path), exist_ok=True)
        with tempfile.NamedTemporaryFile(mode='w', delete=False,
                                         dir=os.path.dirname(torrc_path)) as f:
            f.write(content)
            tmp = f.name
        os.rename(tmp, torrc_path)
    except PermissionError:
        print('[WARN] Cannot write to %s (permission denied)' % torrc_path)
