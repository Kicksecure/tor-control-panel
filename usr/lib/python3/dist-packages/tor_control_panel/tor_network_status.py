#!/usr/bin/python3 -su

## Tor Control Panel - Network Status Module

import os
import re
import socket
import time

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QPalette
from PyQt5.QtWidgets import QWidget

## ---- Constants ----

CONTROL_PORTS = [9051, 9151]
SOCKS_PORTS = [9050, 9150]
CONTROL_SOCKET = '/run/tor/control'
COOKIE_PATH = '/run/tor/control.authcookie'

CHART_COLORS = [
    '#4285f4', '#ea4335', '#fbbc04', '#34a853', '#ff6d01',
    '#46bdc6', '#7baaf7', '#f07b72', '#fcd04f', '#71c287',
    '#ff9e40', '#78d9e0', '#a0c4ff', '#f4a7a0', '#fde293',
    '#a8d8b0',
]

COUNTRY_NAMES = {
    'AD': 'Andorra', 'AE': 'UAE', 'AF': 'Afghanistan',
    'AL': 'Albania', 'AM': 'Armenia', 'AR': 'Argentina',
    'AT': 'Austria', 'AU': 'Australia', 'AZ': 'Azerbaijan',
    'BA': 'Bosnia', 'BD': 'Bangladesh', 'BE': 'Belgium',
    'BG': 'Bulgaria', 'BR': 'Brazil', 'BY': 'Belarus',
    'CA': 'Canada', 'CH': 'Switzerland', 'CL': 'Chile',
    'CN': 'China', 'CO': 'Colombia', 'CZ': 'Czechia',
    'DE': 'Germany', 'DK': 'Denmark', 'EE': 'Estonia',
    'EG': 'Egypt', 'ES': 'Spain', 'FI': 'Finland', 'FR': 'France',
    'GB': 'United Kingdom', 'GE': 'Georgia', 'GR': 'Greece',
    'HK': 'Hong Kong', 'HR': 'Croatia', 'HU': 'Hungary',
    'ID': 'Indonesia', 'IE': 'Ireland', 'IL': 'Israel', 'IN': 'India',
    'IR': 'Iran', 'IS': 'Iceland', 'IT': 'Italy', 'JP': 'Japan',
    'KE': 'Kenya', 'KR': 'South Korea', 'KZ': 'Kazakhstan',
    'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia',
    'MC': 'Monaco', 'MD': 'Moldova', 'ME': 'Montenegro',
    'MK': 'North Macedonia', 'MT': 'Malta', 'MX': 'Mexico', 'MY': 'Malaysia',
    'NL': 'Netherlands', 'NO': 'Norway', 'NZ': 'New Zealand',
    'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland', 'PT': 'Portugal',
    'PA': 'Panama', 'PE': 'Peru', 'PY': 'Paraguay',
    'RO': 'Romania', 'RS': 'Serbia', 'RU': 'Russia',
    'SA': 'Saudi Arabia', 'SC': 'Seychelles', 'SE': 'Sweden',
    'SG': 'Singapore', 'SI': 'Slovenia', 'SK': 'Slovakia',
    'TH': 'Thailand', 'TN': 'Tunisia',
    'TR': 'Turkey', 'TW': 'Taiwan', 'UA': 'Ukraine',
    'US': 'United States', 'UY': 'Uruguay',
    'UZ': 'Uzbekistan', 'VE': 'Venezuela', 'VN': 'Vietnam',
    'ZA': 'South Africa', 'CY': 'Cyprus', 'LI': 'Liechtenstein',
    'CR': 'Costa Rica', 'DO': 'Dominican Republic',
    'DZ': 'Algeria', 'GH': 'Ghana', 'NG': 'Nigeria',
    'PR': 'Puerto Rico', 'RE': 'Reunion',
    '??': 'Unknown',
}


## ---- Helpers ----

def country_label(code):
    name = COUNTRY_NAMES.get(code.upper(), '')
    return '%s - %s' % (code.upper(), name) if name else code.upper()


def format_bandwidth(bw_kb):
    if bw_kb >= 1024 * 1024:
        return '%.1f GB/s' % (bw_kb / (1024 * 1024))
    elif bw_kb >= 1024:
        return '%.1f MB/s' % (bw_kb / 1024)
    return '%d KB/s' % bw_kb


def format_uptime(seconds):
    if seconds <= 0:
        return 'N/A'
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    if d > 0:
        return '%dd %dh' % (d, h)
    return '%dh %dm' % (h, m)


## ---- Port detection ----

def detect_control_ports():
    found = []
    if os.path.exists(CONTROL_SOCKET) and os.access(CONTROL_SOCKET, os.R_OK):
        found.append(('socket', CONTROL_SOCKET, 0))
    for port in CONTROL_PORTS:
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect(('127.0.0.1', port))
            found.append(('tcp', '127.0.0.1', port))
        except (OSError, socket.error):
            pass
        finally:
            if s:
                try:
                    s.close()
                except OSError:
                    pass
    return found


def detect_tor_running():
    return len(detect_control_ports()) > 0


def get_controller(control_method, control_address, control_port,
                   control_socket_path='', password='', cookie_path='',
                   timeout=15):
    import stem.control
    if control_method == 'socket':
        controller = stem.control.Controller.from_socket_file(
            control_socket_path or CONTROL_SOCKET)
    else:
        controller = stem.control.Controller.from_port(
            control_address, int(control_port))
    ## Set socket timeout — stem 1.8.x has no set_timeout() API,
    ## so we reach into the underlying raw socket directly.
    try:
        controller._socket._socket.settimeout(timeout)
    except Exception:
        pass
    if cookie_path and os.path.isfile(cookie_path):
        controller.authenticate(cookie_path)
    elif password:
        controller.authenticate(password=password)
    else:
        controller.authenticate()
    return controller


## ---- Custom table item for numeric bandwidth sort ----

class BandwidthItem(QtWidgets.QTableWidgetItem):
    def __init__(self, bw_kb):
        super().__init__(format_bandwidth(bw_kb))
        self._value = bw_kb

    def __lt__(self, other):
        if isinstance(other, BandwidthItem):
            return self._value < other._value
        return super().__lt__(other)


## ---- Chart widgets (palette-aware for dark/light themes) ----

class BarChartWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = []
        self._title = ''
        self.setMinimumHeight(80)
        self.setMaximumHeight(180)

    def set_data(self, data, title=''):
        self._data = data
        self._title = title
        self.update()

    def paintEvent(self, event):
        if not self._data:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        text_color = self.palette().color(QPalette.WindowText)
        w, h = self.width(), self.height()
        max_val = max(v for _, v, _ in self._data) or 1
        n = len(self._data)
        bar_h = max(10, min(16, (h - 24) // max(n, 1)))
        label_w = min(100, w // 4)
        bar_area = w - label_w - 50
        y = 20
        if self._title:
            p.setFont(QtGui.QFont('sans-serif', 8, QtGui.QFont.Bold))
            p.setPen(text_color)
            p.drawText(0, 0, w, 18, Qt.AlignCenter, self._title)
        p.setFont(QtGui.QFont('sans-serif', 7))
        for label, val, color in self._data:
            if isinstance(color, str):
                color = QtGui.QColor(color)
            bw = int(bar_area * val / max_val) if max_val else 0
            p.setPen(Qt.NoPen)
            p.setBrush(color)
            p.drawRoundedRect(label_w, y, max(bw, 2), bar_h - 2, 2, 2)
            p.setPen(text_color)
            p.drawText(0, y, label_w - 3, bar_h,
                       Qt.AlignRight | Qt.AlignVCenter, label)
            p.drawText(label_w + bw + 3, y, 46, bar_h,
                       Qt.AlignLeft | Qt.AlignVCenter, str(val))
            y += bar_h
        p.end()


class PieChartWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._data = []
        self._title = ''
        self.setMinimumSize(160, 100)
        self.setMaximumHeight(180)

    def set_data(self, data, title=''):
        self._data = data
        self._title = title
        self.update()

    def paintEvent(self, event):
        if not self._data:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        text_color = self.palette().color(QPalette.WindowText)
        w, h = self.width(), self.height()
        total = sum(v for _, v, _ in self._data) or 1
        size = min(w // 2, h - 24) - 4
        if size < 30:
            p.end()
            return
        cx, cy = 4, 20
        if self._title:
            p.setFont(QtGui.QFont('sans-serif', 8, QtGui.QFont.Bold))
            p.setPen(text_color)
            p.drawText(0, 0, w, 18, Qt.AlignCenter, self._title)
        start = 0
        for label, val, color in self._data:
            if isinstance(color, str):
                color = QtGui.QColor(color)
            span = int(5760 * val / total)
            p.setPen(QtGui.QColor('#ffffff'))
            p.setBrush(color)
            p.drawPie(cx, cy, size, size, start, span)
            start += span
        lx = cx + size + 8
        ly = cy + 2
        p.setFont(QtGui.QFont('sans-serif', 7))
        for label, val, color in self._data:
            if ly + 12 > h:
                break
            if isinstance(color, str):
                color = QtGui.QColor(color)
            p.setBrush(color)
            p.setPen(Qt.NoPen)
            p.drawRect(lx, ly, 8, 8)
            p.setPen(text_color)
            p.drawText(lx + 11, ly - 1, w - lx - 12, 11,
                       Qt.AlignLeft | Qt.AlignVCenter,
                       '%s (%d)' % (label, val))
            ly += 12
        p.end()


## ---- Background workers ----

class TorNetworkFetcher(QThread):
    ## NOTE: do NOT name this 'finished' — shadows QThread.finished
    fetch_done = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, control_method, control_address, control_port,
                 control_socket_path='', password='', cookie_path='',
                 parent=None):
        super().__init__(parent)
        self._args = (control_method, control_address, control_port,
                      control_socket_path, password, cookie_path)

    def run(self):
        try:
            self.progress.emit('Connecting...')
            controller = get_controller(*self._args)
            self.progress.emit('Fetching consensus...')
            relays = list(controller.get_network_statuses())
            total = len(relays)
            result = {
                'total': total, 'guards': 0, 'exits': 0,
                'fast': 0, 'stable': 0, 'relays': [],
                'countries': {}, 'guard_countries': {},
                'exit_countries': {},
            }
            for idx, relay in enumerate(relays):
                if idx % 500 == 0:
                    self.progress.emit('Processing %d/%d...' % (idx, total))
                flags = [str(f) for f in relay.flags] if relay.flags else []
                bw = relay.bandwidth or 0
                cc = '??'
                try:
                    cc = controller.get_info(
                        'ip-to-country/%s' % relay.address).upper()
                except Exception:
                    pass
                ig = 'Guard' in flags
                ie = 'Exit' in flags
                ifa = 'Fast' in flags
                ist = 'Stable' in flags
                if ig: result['guards'] += 1
                if ie: result['exits'] += 1
                if ifa: result['fast'] += 1
                if ist: result['stable'] += 1
                result['countries'][cc] = result['countries'].get(cc, 0) + 1
                if ig:
                    result['guard_countries'][cc] = \
                        result['guard_countries'].get(cc, 0) + 1
                if ie:
                    result['exit_countries'][cc] = \
                        result['exit_countries'].get(cc, 0) + 1
                result['relays'].append({
                    'nickname': relay.nickname,
                    'fingerprint': relay.fingerprint,
                    'address': relay.address,
                    'or_port': relay.or_port,
                    'flags': flags, 'bandwidth': bw, 'country': cc,
                    'is_guard': ig, 'is_exit': ie,
                })
            result['relays'].sort(key=lambda r: r['bandwidth'], reverse=True)
            controller.close()
            self.fetch_done.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class TorNodeDetailFetcher(QThread):
    ## NOTE: do NOT name this 'finished' — shadows QThread.finished
    detail_done = pyqtSignal(dict)
    error = pyqtSignal(str)
    log = pyqtSignal(str)

    def __init__(self, fingerprint, control_method, control_address,
                 control_port, control_socket_path='', password='',
                 cookie_path='', parent=None):
        super().__init__(parent)
        self.fp = fingerprint
        self._args = (control_method, control_address, control_port,
                      control_socket_path, password, cookie_path)

    def _fetch_onionoo(self, socks_port):
        """Fetch relay details from Onionoo API via Tor SOCKS5 (stdlib)."""
        import json as _json
        host = 'onionoo.torproject.org'
        path = '/details?lookup=%s' % self.fp
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect(('127.0.0.1', socks_port))
            ## SOCKS5 handshake (no auth)
            s.send(b'\x05\x01\x00')
            resp = s.recv(2)
            if resp != b'\x05\x00':
                s.close()
                return None
            ## SOCKS5 connect request (domain)
            addr = host.encode()
            s.send(b'\x05\x01\x00\x03' + bytes([len(addr)]) + addr +
                   (443).to_bytes(2, 'big'))
            resp = s.recv(10)
            if len(resp) < 2 or resp[1] != 0:
                s.close()
                return None
            ## Wrap in SSL
            import ssl
            ctx = ssl.create_default_context()
            ss = ctx.wrap_socket(s, server_hostname=host)
            req = ('GET %s HTTP/1.0\r\nHost: %s\r\n'
                   'User-Agent: tor-control-panel\r\n\r\n' %
                   (path, host)).encode()
            ss.send(req)
            data = b''
            while True:
                chunk = ss.recv(4096)
                if not chunk:
                    break
                data += chunk
            ss.close()
            ## Parse HTTP response body (after \r\n\r\n)
            text = data.decode('utf-8', errors='replace')
            body_start = text.find('\r\n\r\n')
            if body_start < 0:
                return None
            body = text[body_start + 4:]
            return _json.loads(body)
        except Exception as e:
            self.log.emit('Onionoo fetch failed: %s' % e)
            return None

    def run(self):
        try:
            import datetime
            controller = get_controller(*self._args)
            ns = controller.get_network_status(self.fp)

            ## Try to get full server descriptor (multiple methods)
            desc = None
            raw_desc = ''
            source = 'none'
            try:
                desc = controller.get_server_descriptor(self.fp)
                if desc:
                    source = 'server_descriptor'
            except Exception:
                pass
            if desc is None:
                try:
                    raw_desc = controller.get_info(
                        'desc/id/%s' % self.fp, '')
                    if raw_desc:
                        source = 'desc/id'
                except Exception:
                    pass
            if desc is None and not raw_desc:
                try:
                    raw_desc = controller.get_info(
                        'md/id/%s' % self.fp, '')
                    if raw_desc:
                        source = 'md/id'
                except Exception:
                    pass

            self.log.emit('Node %s descriptor source: %s' %
                          (self.fp[:8], source))

            cc = '??'
            try:
                cc = controller.get_info(
                    'ip-to-country/%s' % ns.address).upper()
            except Exception:
                pass

            ## Published date from consensus
            pub_str = ''
            if ns.published:
                try:
                    dt = ns.published
                    if dt.year > 2030 or dt.year < 2000:
                        pub_str = 'N/A'
                    else:
                        pub_str = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
                except Exception:
                    pub_str = str(ns.published)

            ## Extract fields from descriptor or raw text
            obs_bw = 0
            avg_bw = 0
            burst_bw = 0
            uptime_sec = 0
            platform = ''
            contact = ''
            exit_policy_str = ''

            if desc:
                ## stem returns bytes/s; convert to KB/s
                obs_bw = (getattr(desc, 'observed_bandwidth', 0) or 0) // 1024
                avg_bw = (getattr(desc, 'average_bandwidth', 0) or 0) // 1024
                burst_bw = (getattr(desc, 'burst_bandwidth', 0) or 0) // 1024
                uptime_sec = getattr(desc, 'uptime', 0) or 0
                platform = getattr(desc, 'platform', '') or ''
                contact = getattr(desc, 'contact', '') or ''
                try:
                    ep = getattr(desc, 'exit_policy', None)
                    if ep:
                        exit_policy_str = str(ep)
                except Exception:
                    pass
            elif raw_desc:
                ## Parse raw descriptor text for key fields
                for line in raw_desc.splitlines():
                    if line.startswith('bandwidth '):
                        parts = line.split()
                        if len(parts) >= 4:
                            try:
                                ## Raw descriptor: bytes/s -> KB/s
                                avg_bw = int(parts[1]) // 1024
                                burst_bw = int(parts[2]) // 1024
                                obs_bw = int(parts[3]) // 1024
                            except ValueError:
                                pass
                    elif line.startswith('uptime '):
                        try:
                            uptime_sec = int(line.split()[1])
                        except (ValueError, IndexError):
                            pass
                    elif line.startswith('platform '):
                        platform = line[9:].strip()
                    elif line.startswith('contact '):
                        contact = line[8:].strip()
                    elif line.startswith('reject ') or \
                            line.startswith('accept '):
                        exit_policy_str += line + '\n'

            ## Fallback: Onionoo API if no useful data from local desc
            if obs_bw == 0 and uptime_sec == 0 and not platform:
                self.log.emit('Local descriptors empty, trying Onionoo...')
                socks_port = 9050
                try:
                    sp = controller.get_conf('SocksPort', '9050')
                    if sp and sp.split()[0].isdigit():
                        socks_port = int(sp.split()[0])
                except Exception:
                    pass
                controller.close()
                oo = self._fetch_onionoo(socks_port)
                if oo and 'relays' in oo and len(oo['relays']) > 0:
                    r = oo['relays'][0]
                    self.log.emit('Onionoo returned data for %s' %
                                  r.get('nickname', '?'))
                    ## Onionoo returns bytes/s; convert to KB/s
                    obs_bw = r.get('observed_bandwidth', 0) // 1024
                    avg_bw = r.get('advertised_bandwidth', 0) // 1024
                    platform = r.get('platform', '') or ''
                    contact = r.get('contact', '') or ''
                    if r.get('last_restarted'):
                        try:
                            since_dt = datetime.datetime.strptime(
                                r['last_restarted'],
                                '%Y-%m-%d %H:%M:%S')
                            delta = (datetime.datetime.utcnow() -
                                     since_dt)
                            uptime_sec = int(delta.total_seconds())
                        except Exception:
                            pass
                    if not pub_str and r.get('last_seen'):
                        pub_str = r['last_seen']
                    ep = r.get('exit_policy', [])
                    if ep:
                        exit_policy_str = '\n'.join(
                            str(e) for e in ep[:20])
                    ep_summary = r.get('exit_policy_summary', {})
                    if ep_summary and not exit_policy_str:
                        parts = []
                        for action, ports in ep_summary.items():
                            parts.append('%s %s' % (action, ports))
                        exit_policy_str = '\n'.join(parts)
                else:
                    self.log.emit('Onionoo returned no data')
            else:
                controller.close()

            ## Compute "running since" from uptime
            running_since = ''
            if uptime_sec > 0:
                try:
                    since = (datetime.datetime.utcnow() -
                             datetime.timedelta(seconds=uptime_sec))
                    running_since = since.strftime('%Y-%m-%d %H:%M UTC')
                except Exception:
                    pass

            info = {
                'nickname': ns.nickname,
                'fingerprint': ns.fingerprint,
                'address': ns.address,
                'or_port': ns.or_port,
                'dir_port': getattr(ns, 'dir_port', 0),
                'flags': [str(f) for f in ns.flags] if ns.flags else [],
                'bandwidth': ns.bandwidth or 0,
                'country': cc,
                'published': pub_str,
                'platform': platform,
                'uptime': uptime_sec,
                'running_since': running_since,
                'contact': contact,
                'observed_bandwidth': obs_bw,
                'average_bandwidth': avg_bw,
                'burst_bandwidth': burst_bw,
                'exit_policy': exit_policy_str.strip()[:500],
            }
            self.detail_done.emit(info)
        except Exception as e:
            self.error.emit(str(e))


class TorCircuitTester(QThread):
    result = pyqtSignal(list)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, control_method, control_address, control_port,
                 control_socket_path='', password='', cookie_path='',
                 num_tests=3, test_url='', parent=None):
        super().__init__(parent)
        self._args = (control_method, control_address, control_port,
                      control_socket_path, password, cookie_path)
        self.num_tests = num_tests
        self.test_url = test_url or 'https://check.torproject.org/'

    def _measure_download(self, socks_port):
        """Measure real download speed through Tor SOCKS5 proxy (stdlib only).
        Uses raw SOCKS5 handshake — no external dependencies required."""
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(self.test_url)
            use_ssl = parsed.scheme == 'https'
            host = parsed.hostname or 'detectportal.firefox.com'
            port = parsed.port or (443 if use_ssl else 80)
            path = parsed.path or '/'
            if parsed.query:
                path += '?' + parsed.query

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect(('127.0.0.1', socks_port))
            ## SOCKS5 handshake (no auth)
            s.send(b'\x05\x01\x00')
            resp = s.recv(2)
            if resp != b'\x05\x00':
                s.close()
                return 0, 0, 0
            ## SOCKS5 connect request (domain)
            addr = host.encode()
            s.send(b'\x05\x01\x00\x03' + bytes([len(addr)]) + addr +
                   port.to_bytes(2, 'big'))
            resp = s.recv(10)
            if len(resp) < 2 or resp[1] != 0:
                s.close()
                return 0, 0, 0

            if use_ssl:
                import ssl
                ctx = ssl.create_default_context()
                s = ctx.wrap_socket(s, server_hostname=host)

            req = ('GET %s HTTP/1.0\r\nHost: %s\r\n'
                   'User-Agent: tor-control-panel\r\n'
                   'Accept: */*\r\n\r\n' %
                   (path, host)).encode()
            t_start = time.time()
            s.send(req)
            ## First chunk = TTFB (latency)
            first = s.recv(8192)
            t_first = time.time()
            latency_ms = int((t_first - t_start) * 1000)
            data = first
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                data += chunk
            t_end = time.time()
            s.close()
            total_elapsed = t_end - t_start
            ## Strip HTTP headers
            body_pos = data.find(b'\r\n\r\n')
            body = data[body_pos + 4:] if body_pos >= 0 else data
            size_kb = len(body) / 1024.0
            speed = size_kb / total_elapsed if total_elapsed > 0.001 else 0
            return speed, latency_ms, len(body)
        except Exception:
            return 0, 0, 0

    def run(self):
        try:
            controller = get_controller(*self._args)
            ## Detect SOCKS port
            socks_port = 9050
            try:
                sp = controller.get_conf('SocksPort', '9050')
                if sp and sp.split()[0].isdigit():
                    socks_port = int(sp.split()[0])
            except Exception:
                for p in SOCKS_PORTS:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(('127.0.0.1', p))
                        s.close()
                        socks_port = p
                        break
                    except Exception:
                        pass

            results = []
            seen_paths = set()
            from stem import Signal

            for i in range(self.num_tests):
                self.progress.emit(
                    'Test %d/%d: requesting new circuit...' %
                    (i + 1, self.num_tests))
                ## Force new circuit
                try:
                    controller.signal(Signal.NEWNYM)
                except Exception:
                    pass
                time.sleep(4)

                ## Find a BUILT circuit
                circuit = None
                for c in controller.get_circuits():
                    if c.status != 'BUILT':
                        continue
                    path_key = tuple(fp for fp, _ in c.path)
                    if path_key not in seen_paths:
                        circuit = c
                        seen_paths.add(path_key)
                        break
                if circuit is None:
                    ## Use any BUILT circuit
                    for c in controller.get_circuits():
                        if c.status == 'BUILT':
                            circuit = c
                            break
                if circuit is None:
                    self.progress.emit('Test %d: no circuit available' % (i+1))
                    continue

                ## Gather path info
                path_info = []
                for fp, nick in circuit.path:
                    bw, cc = 0, '??'
                    try:
                        ns = controller.get_network_status(fp)
                        cc = controller.get_info(
                            'ip-to-country/%s' % ns.address).upper()
                        bw = ns.bandwidth or 0
                    except Exception:
                        pass
                    path_info.append({
                        'fingerprint': fp, 'nickname': nick,
                        'country': cc, 'bandwidth': bw,
                    })

                ## Measure real speed
                self.progress.emit(
                    'Test %d/%d: measuring speed...' % (i+1, self.num_tests))
                speed, latency, size = self._measure_download(socks_port)
                min_bw = min(n['bandwidth'] for n in path_info) if path_info else 0

                results.append({
                    'circuit_id': circuit.id,
                    'path': path_info,
                    'min_bandwidth': min_bw,
                    'real_speed_kbs': round(speed, 1),
                    'latency_ms': latency,
                    'download_bytes': size,
                })

            results.sort(key=lambda r: r['real_speed_kbs'], reverse=True)
            controller.close()
            self.result.emit(results)
        except Exception as e:
            self.error.emit(str(e))


class TorConfigApplier(QThread):
    ## NOTE: do NOT name this 'finished' — it shadows QThread.finished
    ## and prevents the slot from being called on some PyQt versions.
    apply_done = pyqtSignal(bool, str)
    log = pyqtSignal(str)

    def __init__(self, control_method, control_address, control_port,
                 control_socket_path='', password='', cookie_path='',
                 config=None, torrc_path='', parent=None):
        super().__init__(parent)
        self._args = (control_method, control_address, control_port,
                      control_socket_path, password, cookie_path)
        self.config = config or {}
        self.torrc_path = torrc_path

    def _log(self, msg):
        self.log.emit('[ConfigApplier] %s' % msg)

    def _build_node_value(self, cfg_key, cc_re, fp_re):
        """Build Tor node spec string from countries + fingerprints."""
        codes = self.config.get(cfg_key, [])
        fps_key = cfg_key.replace('countries', 'fps')
        fps = self.config.get(fps_key, [])
        parts = []
        for c in codes:
            if cc_re.match(c):
                parts.append('{%s}' % c)
        for f in fps:
            if fp_re.match(f):
                parts.append('$%s' % f)
        return ','.join(parts) if parts else ''

    def run(self):
        try:
            cc_re = re.compile(r'^[A-Z]{2}$')
            fp_re = re.compile(r'^[A-F0-9]{40}$')
            applied = []
            torrc_lines = [
                '## Auto-generated by Tor Control Panel circuit config\n']

            ## Build node selection directives
            directives = [
                ('entry_countries', 'EntryNodes'),
                ('exit_countries', 'ExitNodes'),
                ('middle_countries', 'MiddleNodes'),
                ('exclude_countries', 'ExcludeNodes'),
            ]
            for cfg_key, tor_key in directives:
                value = self._build_node_value(cfg_key, cc_re, fp_re)
                if value:
                    torrc_lines.append('%s %s\n' % (tor_key, value))
                    applied.append('%s=%s' % (tor_key, value))

            ## StrictNodes
            strict = '1' if self.config.get('strict_nodes') else '0'
            torrc_lines.append('StrictNodes %s\n' % strict)
            applied.append('StrictNodes=%s' % strict)

            ## NumEntryGuards
            ng = self.config.get('num_entry_guards')
            if ng and isinstance(ng, int) and 1 <= ng <= 10:
                torrc_lines.append('NumEntryGuards %d\n' % ng)

            self._log('torrc content:\n%s' % ''.join(torrc_lines))

            ## Step 1: Write torrc file (persistent)
            torrc_written = False
            write_err = ''
            if self.torrc_path:
                try:
                    torrc_dir = os.path.dirname(self.torrc_path)
                    if not os.path.isdir(torrc_dir):
                        os.makedirs(torrc_dir, exist_ok=True)
                    with open(self.torrc_path, 'w') as f:
                        f.writelines(torrc_lines)
                    torrc_written = True
                    self._log('Wrote torrc to %s' % self.torrc_path)
                except PermissionError:
                    self._log('PermissionError writing torrc, trying sudo -n tee')
                    import subprocess
                    content = ''.join(torrc_lines)
                    ## Try 1: sudo -n (passwordless)
                    try:
                        p = subprocess.Popen(
                            ['sudo', '-n', 'tee', self.torrc_path],
                            stdin=subprocess.PIPE,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
                        _, stderr = p.communicate(
                            content.encode(), timeout=10)
                        if p.returncode == 0:
                            torrc_written = True
                            self._log('Wrote torrc via sudo tee')
                        else:
                            self._log('sudo -n tee failed: %s'
                                      % stderr.decode().strip())
                    except Exception as e:
                        self._log('sudo -n tee exception: %s' % e)
                    ## Try 2: pkexec (shows GUI password dialog)
                    if not torrc_written:
                        self._log('Trying pkexec tee for GUI password prompt')
                        try:
                            p = subprocess.Popen(
                                ['pkexec', 'tee', self.torrc_path],
                                stdin=subprocess.PIPE,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE)
                            _, stderr = p.communicate(
                                content.encode(), timeout=60)
                            if p.returncode == 0:
                                torrc_written = True
                                self._log('Wrote torrc via pkexec tee')
                            else:
                                write_err = stderr.decode().strip()
                                self._log('pkexec tee failed: %s'
                                          % write_err)
                        except Exception as e:
                            write_err = str(e)
                            self._log('pkexec tee exception: %s' % e)
                except Exception as e:
                    write_err = str(e)
                    self._log('torrc write error: %s' % e)

            ## Step 2: Connect to Tor controller
            controller = get_controller(*self._args)

            ## Step 3: Apply config via set_conf (immediate, always works).
            ## NEVER rely on SIGHUP alone — it won't apply config if the
            ## torrc was written to a path Tor doesn't include, AND it
            ## resets all SETCONF changes (including SocksPort intercept).
            from stem import Signal

            self._log('Applying config via set_conf...')
            for cfg_key, tor_key in directives:
                value = self._build_node_value(cfg_key, cc_re, fp_re)
                try:
                    if value:
                        controller.set_conf(tor_key, value)
                        self._log('set_conf %s=%s' % (tor_key, value))
                    else:
                        controller.reset_conf(tor_key)
                        self._log('reset_conf %s' % tor_key)
                except Exception as e:
                    self._log('set_conf %s error: %s' % (tor_key, e))
            try:
                controller.set_conf('StrictNodes', strict)
            except Exception as e:
                self._log('set_conf StrictNodes error: %s' % e)
            if ng and isinstance(ng, int) and 1 <= ng <= 10:
                try:
                    controller.set_conf('NumEntryGuards', str(ng))
                except Exception as e:
                    self._log('set_conf NumEntryGuards error: %s' % e)

            ## Step 4: Drop cached guard nodes so Tor picks new ones
            ## from the updated EntryNodes list (guards are persisted
            ## in the state file and reused even after config change)
            self._log('Dropping cached guard nodes...')
            try:
                controller.drop_guards()
                self._log('Guard cache dropped (drop_guards)')
            except Exception as e:
                self._log('drop_guards not available (%s), '
                          'trying DROPGUARDS signal...' % e)
                try:
                    controller.msg('DROPGUARDS')
                    self._log('DROPGUARDS sent via raw command')
                except Exception as e2:
                    self._log('DROPGUARDS also failed: %s — '
                              'will try state file cleanup' % e2)
                    ## Last resort: wipe guard entries from state file
                    try:
                        import glob
                        state_files = glob.glob('/var/lib/tor/state') + \
                            glob.glob('/var/lib/tor/*/state')
                        for sf in state_files:
                            self._log('Clearing guard state in %s' % sf)
                            try:
                                with open(sf, 'r') as f:
                                    lines = f.readlines()
                                cleaned = [l for l in lines
                                           if not l.startswith('Guard ')]
                                with open(sf, 'w') as f:
                                    f.writelines(cleaned)
                            except PermissionError:
                                import subprocess
                                ## Use sed to remove Guard lines
                                subprocess.run(
                                    ['pkexec', 'sed', '-i',
                                     '/^Guard /d', sf],
                                    timeout=30)
                            except Exception as e3:
                                self._log('state cleanup error: %s' % e3)
                    except Exception as e4:
                        self._log('state file cleanup failed: %s' % e4)

            ## Step 5: Request new circuits
            self._log('Sending NEWNYM to request new circuits...')
            try:
                controller.signal(Signal.NEWNYM)
                self._log('NEWNYM sent')
            except Exception as e:
                self._log('NEWNYM error: %s' % e)

            ## Step 6: Close only IDLE circuits (no active streams).
            ## Do NOT close all circuits — that forces Tor to
            ## aggressively rebuild hundreds simultaneously.
            ## NEWNYM already tells Tor to build new circuits; closing
            ## idle ones just frees resources for the new ones.
            self._log('Closing idle circuits...')
            try:
                stream_cids = set()
                try:
                    for line in controller.get_info(
                            'stream-status', '').splitlines():
                        parts = line.split()
                        if len(parts) >= 3:
                            stream_cids.add(parts[2])
                except Exception:
                    pass
                closed_n = 0
                for circ in controller.get_circuits():
                    if circ.id not in stream_cids:
                        try:
                            controller.close_circuit(circ.id)
                            closed_n += 1
                        except Exception:
                            pass
                self._log('Closed %d idle circuits '
                          '(kept %d with streams)' % (
                              closed_n, len(stream_cids)))
            except Exception as e:
                self._log('Error closing circuits: %s' % e)

            controller.close()

            ## Build result message
            parts_msg = []
            if applied:
                parts_msg.append('Set: %s' %
                                 ', '.join(a.split('=')[0] for a in applied))
            parts_msg.append('Config applied via set_conf.')
            if torrc_written:
                parts_msg.append('Also saved to %s.' % self.torrc_path)
            elif write_err:
                parts_msg.append(
                    '(torrc save failed: %s)' % write_err)
            parts_msg.append('New circuits requested.')
            self.apply_done.emit(True, ' '.join(parts_msg))
        except Exception as e:
            self._log('FATAL: %s' % e)
            self.apply_done.emit(False, str(e))


def _parse_stream_target(target):
    """Parse stream target into (host, port_str) handling IPv6.

    Tor stream targets can be:
      - host:port         (IPv4 or hostname)
      - [ipv6addr]:port   (IPv6)
    Returns (host, port_str).  host has brackets stripped.
    """
    if target.startswith('['):
        bracket_end = target.find(']')
        if bracket_end >= 0:
            host = target[1:bracket_end]
            rest = target[bracket_end + 1:]
            if rest.startswith(':'):
                return host, rest[1:]
            return host, ''
        return target.strip('[]'), ''
    if ':' in target:
        host, port = target.rsplit(':', 1)
        return host, port
    return target, ''


def _is_ip_address(host):
    """Return True if host looks like an IPv4 or IPv6 address."""
    ## IPv4
    if all(c in '0123456789.' for c in host) and '.' in host:
        return True
    ## IPv6 (hex digits, colons, and optionally dots for mapped addrs)
    if ':' in host and all(c in '0123456789abcdefABCDEF.:' for c in host):
        return True
    return False


class TorCircuitFetcher(QThread):
    ## NOTE: do NOT name this 'finished' — shadows QThread.finished
    circuits_done = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, control_method, control_address, control_port,
                 control_socket_path='', password='', cookie_path='',
                 parent=None):
        super().__init__(parent)
        self._args = (control_method, control_address, control_port,
                      control_socket_path, password, cookie_path)

    def run(self):
        import socket as _socket
        try:
            controller = get_controller(*self._args)

            ## Map circuit_id -> list of stream detail dicts
            stream_targets = {}
            stream_details = {}  ## target -> {stream_id, status, source_addr}
            try:
                for line in controller.get_info('stream-status', '').splitlines():
                    parts = line.split()
                    ## Format: StreamID Status CircuitID Target [key=val...]
                    if len(parts) >= 4:
                        stream_id = parts[0]
                        stream_status = parts[1]
                        circ_id = parts[2]
                        target = parts[3]
                        stream_targets.setdefault(circ_id, []).append(target)
                        ## Parse optional key=value pairs (SOURCE_ADDR etc)
                        extra = {}
                        for kv in parts[4:]:
                            if '=' in kv:
                                k, v = kv.split('=', 1)
                                extra[k] = v
                        stream_details[target] = {
                            'stream_id': stream_id,
                            'status': stream_status,
                            'circuit_id': circ_id,
                            'source_addr': extra.get('SOURCE_ADDR', ''),
                            'purpose': extra.get('PURPOSE', ''),
                        }
            except Exception:
                pass

            ## Build IP→hostname map from Tor's own DNS cache.
            ## This is far more reliable than local gethostbyaddr.
            ip_to_host = {}
            try:
                for line in controller.get_info(
                        'address-mappings/all', '').splitlines():
                    ## Format: hostname ip "expiry-time"
                    parts = line.split()
                    if len(parts) >= 2:
                        hostname = parts[0]
                        ip = parts[1]
                        ## Only map IP→hostname (not hostname→hostname)
                        if _is_ip_address(ip) and not _is_ip_address(
                                hostname):
                            ip_to_host[ip] = hostname
            except Exception:
                pass

            ## Reverse-DNS cache for stream target IPs -> hostnames
            rdns_cache = {}
            for targets_list in stream_targets.values():
                for t in targets_list:
                    host, _port = _parse_stream_target(t)
                    if host in rdns_cache:
                        continue
                    ## Skip .onion and already-resolved domains
                    if host.endswith('.onion') or not _is_ip_address(host):
                        rdns_cache[host] = host
                        continue
                    ## First try Tor's own DNS cache
                    if host in ip_to_host:
                        rdns_cache[host] = ip_to_host[host]
                        continue
                    ## Fallback: local reverse DNS
                    try:
                        name = _socket.gethostbyaddr(host)[0]
                        rdns_cache[host] = name
                    except Exception:
                        rdns_cache[host] = host

            ## Resolve stream targets: replace IPs with hostnames
            resolved_targets = {}
            for circ_id, tlist in stream_targets.items():
                resolved = []
                for t in tlist:
                    host, port = _parse_stream_target(t)
                    name = rdns_cache.get(host, host)
                    if port:
                        resolved.append('%s:%s' % (name, port))
                    else:
                        resolved.append(name)
                resolved_targets[circ_id] = resolved

            result = []
            for circuit in controller.get_circuits():
                ## Show ALL circuit states, not just BUILT
                ## (LAUNCHED, EXTENDED, BUILT, FAILED, CLOSED)
                status = circuit.status
                path_info = []
                for fp, nick in circuit.path:
                    bw, cc, addr, or_port, flags = 0, '??', '', 0, []
                    try:
                        ns = controller.get_network_status(fp)
                        cc = controller.get_info(
                            'ip-to-country/%s' % ns.address).upper()
                        bw = ns.bandwidth or 0
                        addr = ns.address or ''
                        or_port = ns.or_port or 0
                        flags = list(ns.flags) if ns.flags else []
                    except Exception:
                        pass
                    path_info.append({
                        'fingerprint': fp, 'nickname': nick,
                        'country': cc, 'bandwidth': bw,
                        'address': addr, 'or_port': or_port,
                        'flags': flags,
                    })
                targets = resolved_targets.get(circuit.id, [])
                ## Attach per-target stream details
                tgt_details = []
                for t_raw in stream_targets.get(circuit.id, []):
                    sd = stream_details.get(t_raw, {})
                    ## Resolve target name
                    h, p = _parse_stream_target(t_raw)
                    rname = rdns_cache.get(h, h)
                    if p:
                        resolved_name = '%s:%s' % (rname, p)
                    else:
                        resolved_name = rname
                    tgt_details.append({
                        'target': resolved_name,
                        'raw_target': t_raw,
                        'stream_id': sd.get('stream_id', ''),
                        'stream_status': sd.get('status', ''),
                        'source_addr': sd.get('source_addr', ''),
                        'purpose': sd.get('purpose', ''),
                    })
                ## For IPv6 targets that failed parsing, provide a
                ## cleaned-up display string
                for td in tgt_details:
                    t = td['target']
                    if t.startswith('[') or '\x00' in t:
                        h, p = _parse_stream_target(td['raw_target'])
                        name = rdns_cache.get(h, h)
                        td['target'] = ('%s:%s' % (name, p)) if p \
                            else name
                result.append({
                    'circuit_id': circuit.id,
                    'status': status,
                    'purpose': circuit.purpose or '',
                    'path': path_info,
                    'targets': targets,
                    'target_details': tgt_details,
                })
            controller.close()
            self.circuits_done.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class TorDashboardPoller(QThread):
    """Polls Tor controller for bandwidth, version, events — like nyx."""
    update = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, control_method, control_address, control_port,
                 control_socket_path='', password='', cookie_path='',
                 parent=None):
        super().__init__(parent)
        self._args = (control_method, control_address, control_port,
                      control_socket_path, password, cookie_path)
        self._running = True
        self._bw_download = []
        self._bw_upload = []
        self._events = []
        self._total_down = 0
        self._total_up = 0

    def stop(self):
        self._running = False

    def run(self):
        try:
            controller = get_controller(*self._args)
        except Exception as e:
            self.error.emit(str(e))
            return

        ## Gather static info once
        version = ''
        pid = 0
        bw_rate = 0
        bw_burst = 0
        flags = []
        try:
            version = controller.get_info('version', '')
        except Exception:
            pass
        try:
            pid = int(controller.get_info('process/pid', '0'))
        except Exception:
            pass
        try:
            bw_rate = int(controller.get_conf('BandwidthRate', '0'))
            bw_burst = int(controller.get_conf('BandwidthBurst', '0'))
        except Exception:
            pass
        try:
            fp = controller.get_info('fingerprint', '')
            if fp:
                ns = controller.get_network_status(fp)
                flags = [str(f) for f in ns.flags] if ns.flags else []
        except Exception:
            pass

        or_port = ''
        try:
            or_port = controller.get_conf('ORPort', '0')
        except Exception:
            pass
        is_relay = or_port and or_port != '0'

        control_info = ''
        try:
            cp = controller.get_conf('ControlPort', '')
            cs = controller.get_conf('ControlSocket', '')
            auth = 'cookie' if controller.get_conf(
                'CookieAuthentication', '0') == '1' else 'password'
            parts = []
            if cs:
                parts.append('Socket: %s' % cs)
            if cp:
                parts.append('Port: %s' % cp)
            control_info = ', '.join(parts) + ' (%s)' % auth
        except Exception:
            pass

        ## Event listener
        import threading
        event_lock = threading.Lock()

        def _on_event(event):
            with event_lock:
                ts = time.strftime('%H:%M:%S')
                msg = str(event)
                if len(msg) > 200:
                    msg = msg[:200] + '...'
                self._events.append('[%s] %s' % (ts, msg))
                if len(self._events) > 100:
                    self._events = self._events[-100:]

        try:
            from stem.control import EventType
            controller.add_event_listener(
                _on_event, EventType.WARN, EventType.ERR, EventType.NOTICE)
        except Exception:
            pass

        ## Polling loop
        while self._running:
            bw_down, bw_up = 0, 0
            try:
                bw_str = controller.get_info(
                    'traffic/read', '0')
                total_read = int(bw_str)
                bw_str = controller.get_info(
                    'traffic/written', '0')
                total_written = int(bw_str)

                if self._total_down > 0:
                    bw_down = total_read - self._total_down
                    bw_up = total_written - self._total_up
                self._total_down = total_read
                self._total_up = total_written
            except Exception:
                pass

            self._bw_download.append(bw_down)
            self._bw_upload.append(bw_up)
            if len(self._bw_download) > 120:
                self._bw_download = self._bw_download[-120:]
                self._bw_upload = self._bw_upload[-120:]

            cpu, mem = 0.0, 0
            if pid > 0:
                try:
                    with open('/proc/%d/stat' % pid) as f:
                        parts = f.read().split()
                    with open('/proc/%d/statm' % pid) as f:
                        mem_pages = int(f.read().split()[1])
                    mem = mem_pages * 4096
                except Exception:
                    pass

            avg_down = (sum(self._bw_download) //
                        max(len(self._bw_download), 1))
            avg_up = (sum(self._bw_upload) //
                      max(len(self._bw_upload), 1))

            with event_lock:
                recent_events = list(self._events[-20:])

            data = {
                'version': version,
                'pid': pid,
                'is_relay': is_relay,
                'flags': flags,
                'bw_rate': bw_rate,
                'bw_burst': bw_burst,
                'control_info': control_info,
                'bw_down': bw_down,
                'bw_up': bw_up,
                'avg_down': avg_down,
                'avg_up': avg_up,
                'total_down': self._total_down,
                'total_up': self._total_up,
                'bw_download_history': list(self._bw_download),
                'bw_upload_history': list(self._bw_upload),
                'mem': mem,
                'events': recent_events,
            }
            self.update.emit(data)
            time.sleep(1)

        try:
            controller.close()
        except Exception:
            pass


class BandwidthGraphWidget(QWidget):
    """Draws download/upload bandwidth graph over time, like nyx."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._down = []
        self._up = []
        self.setMinimumHeight(80)
        self.setMaximumHeight(120)

    def set_data(self, download, upload):
        self._down = download
        self._up = upload
        self.update()

    def paintEvent(self, event):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        tc = self.palette().color(QtGui.QPalette.WindowText)
        bg = self.palette().color(QtGui.QPalette.Window)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, bg)

        if not self._down and not self._up:
            p.setPen(tc)
            p.drawText(0, 0, w, h, Qt.AlignCenter, 'No data yet')
            p.end()
            return

        n = max(len(self._down), len(self._up), 1)
        max_val = max(max(self._down, default=1),
                      max(self._up, default=1), 1)
        margin_top = 14
        graph_h = h - margin_top - 2

        ## Labels
        p.setFont(QtGui.QFont('sans-serif', 7))
        p.setPen(tc)
        p.drawText(2, 0, w // 2, 13, Qt.AlignLeft,
                   'Download')
        p.drawText(w // 2, 0, w // 2, 13, Qt.AlignRight,
                   'Upload')

        ## Grid lines
        grid_pen = QtGui.QPen(QtGui.QColor(180, 180, 180, 60))
        p.setPen(grid_pen)
        for gy in range(4):
            yy = margin_top + int(graph_h * gy / 4)
            p.drawLine(0, yy, w, yy)

        ## Download (green fill)
        if len(self._down) > 1:
            down_color = QtGui.QColor(76, 175, 80, 100)
            down_line = QtGui.QColor(76, 175, 80, 200)
            step = w / max(n - 1, 1)
            poly = QtGui.QPolygonF()
            poly.append(QtCore.QPointF(0, h))
            for i, v in enumerate(self._down):
                x = i * step
                y = margin_top + graph_h - (graph_h * v / max_val)
                poly.append(QtCore.QPointF(x, y))
            poly.append(QtCore.QPointF((len(self._down) - 1) * step, h))
            p.setPen(Qt.NoPen)
            p.setBrush(down_color)
            p.drawPolygon(poly)
            ## Line
            p.setPen(QtGui.QPen(down_line, 1.5))
            p.setBrush(Qt.NoBrush)
            for i in range(len(self._down) - 1):
                x1 = i * step
                y1 = margin_top + graph_h - (graph_h * self._down[i] / max_val)
                x2 = (i + 1) * step
                y2 = margin_top + graph_h - (graph_h * self._down[i+1] / max_val)
                p.drawLine(QtCore.QPointF(x1, y1), QtCore.QPointF(x2, y2))

        ## Upload (blue fill)
        if len(self._up) > 1:
            up_color = QtGui.QColor(33, 150, 243, 80)
            up_line = QtGui.QColor(33, 150, 243, 200)
            step = w / max(n - 1, 1)
            poly = QtGui.QPolygonF()
            poly.append(QtCore.QPointF(0, h))
            for i, v in enumerate(self._up):
                x = i * step
                y = margin_top + graph_h - (graph_h * v / max_val)
                poly.append(QtCore.QPointF(x, y))
            poly.append(QtCore.QPointF((len(self._up) - 1) * step, h))
            p.setPen(Qt.NoPen)
            p.setBrush(up_color)
            p.drawPolygon(poly)
            p.setPen(QtGui.QPen(up_line, 1.5))
            p.setBrush(Qt.NoBrush)
            for i in range(len(self._up) - 1):
                x1 = i * step
                y1 = margin_top + graph_h - (graph_h * self._up[i] / max_val)
                x2 = (i + 1) * step
                y2 = margin_top + graph_h - (graph_h * self._up[i+1] / max_val)
                p.drawLine(QtCore.QPointF(x1, y1), QtCore.QPointF(x2, y2))

        p.end()


def format_bytes(n):
    if n >= 1024 * 1024 * 1024:
        return '%.1f GB' % (n / (1024 * 1024 * 1024))
    elif n >= 1024 * 1024:
        return '%.1f MB' % (n / (1024 * 1024))
    elif n >= 1024:
        return '%.1f KB' % (n / 1024)
    return '%d B' % n


def format_rate(n):
    """Format bytes/sec rate."""
    if n >= 1024 * 1024:
        return '%.1f MB/s' % (n / (1024 * 1024))
    elif n >= 1024:
        return '%.1f KB/s' % (n / 1024)
    return '%d B/s' % n
