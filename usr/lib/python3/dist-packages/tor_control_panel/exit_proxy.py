"""
Post-Tor Exit Proxy — local SOCKS5 server that chains traffic through
Tor and then through an external proxy so the destination sees the
proxy's IP instead of a Tor exit node IP.

Chain on non-Whonix:
  App → Local SOCKS5 (this server) → Tor SOCKS → Tor network →
  Exit node → External proxy → Internet

Chain on Whonix (all traffic already goes through Tor via gateway):
  App → Local SOCKS5 (this server) → External proxy
  (routed through Tor transparently) → Internet

Supports SOCKS5 and HTTP CONNECT exit proxies.
No external dependencies — pure asyncio + stdlib.
"""

import asyncio
import json
import logging
import os
import re
import socket
import struct
import threading
import time
from urllib.parse import urlparse

log = logging.getLogger('exit_proxy')

## IP-check services (plain text response with IP)
## Connection: close is critical so server closes socket after response
_IP_CHECK_SERVICES = [
    ('ifconfig.me', 80, 'GET / HTTP/1.1\r\nHost: ifconfig.me\r\n'
     'User-Agent: curl/8.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'),
    ('icanhazip.com', 80, 'GET / HTTP/1.1\r\nHost: icanhazip.com\r\n'
     'User-Agent: curl/8.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'),
    ('api.ipify.org', 80, 'GET / HTTP/1.1\r\nHost: api.ipify.org\r\n'
     'User-Agent: curl/8.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'),
    ('checkip.amazonaws.com', 80,
     'GET / HTTP/1.1\r\nHost: checkip.amazonaws.com\r\n'
     'User-Agent: curl/8.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'),
    ('ip.seeip.org', 80, 'GET / HTTP/1.1\r\nHost: ip.seeip.org\r\n'
     'User-Agent: curl/8.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'),
]

## Whonix detection
_WHONIX_GW = os.path.exists('/usr/share/anon-gw-base-files/gateway')
_WHONIX_WS = os.path.exists('/usr/share/anon-ws-base-files/workstation')
_WHONIX = _WHONIX_GW or _WHONIX_WS

## Intercept state file for crash recovery
_INTERCEPT_STATE_FILE = os.path.join(
    os.path.expanduser('~'), '.config', 'tor-control-panel',
    '.exit_proxy_intercept.json')


## ---------------------------------------------------------------------------
## Low-level SOCKS5 / HTTP-CONNECT helpers (async, operate on reader/writer)
## ---------------------------------------------------------------------------

async def _socks5_handshake(reader, writer, host, port,
                            username=None, password=None):
    """Perform a SOCKS5 client handshake and CONNECT to host:port.

    Returns True on success, raises on failure.
    """
    ## Greeting — offer no-auth and user/pass
    if username and password:
        writer.write(b'\x05\x02\x00\x02')
    else:
        writer.write(b'\x05\x01\x00')
    await writer.drain()
    resp = await reader.readexactly(2)
    ver, method = resp[0], resp[1]
    if ver != 0x05:
        raise RuntimeError('SOCKS5 server returned version %d' % ver)

    ## Username/password auth (RFC 1929)
    if method == 0x02:
        if not username or not password:
            raise RuntimeError('SOCKS5 server requires auth but none given')
        u = username.encode('utf-8')
        p = password.encode('utf-8')
        writer.write(b'\x01' + bytes([len(u)]) + u +
                     bytes([len(p)]) + p)
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        if auth_resp[1] != 0x00:
            raise RuntimeError('SOCKS5 auth failed (status %d)' %
                               auth_resp[1])
    elif method == 0xFF:
        raise RuntimeError('SOCKS5 server: no acceptable auth method')

    ## CONNECT request
    ## Detect if host is an IPv4 address → use type 0x01, else domain 0x03
    try:
        _ip4 = socket.inet_aton(host)
        req = b'\x05\x01\x00\x01' + _ip4 + struct.pack('!H', port)
    except OSError:
        host_bytes = host.encode('utf-8')
        req = (b'\x05\x01\x00\x03' +
               bytes([len(host_bytes)]) + host_bytes +
               struct.pack('!H', port))
    writer.write(req)
    await writer.drain()

    ## Response
    resp = await reader.readexactly(4)
    if resp[1] != 0x00:
        codes = {
            0x01: 'general failure', 0x02: 'not allowed',
            0x03: 'network unreachable', 0x04: 'host unreachable',
            0x05: 'connection refused', 0x06: 'TTL expired',
            0x07: 'command not supported', 0x08: 'address type not supported',
        }
        raise RuntimeError('SOCKS5 CONNECT failed: %s (0x%02x)' %
                           (codes.get(resp[1], 'unknown'), resp[1]))
    ## Consume bound address
    atype = resp[3]
    if atype == 0x01:
        await reader.readexactly(4 + 2)   # IPv4 + port
    elif atype == 0x04:
        await reader.readexactly(16 + 2)  # IPv6 + port
    elif atype == 0x03:
        alen = (await reader.readexactly(1))[0]
        await reader.readexactly(alen + 2)
    return True


async def _http_connect(reader, writer, host, port,
                        username=None, password=None):
    """Perform an HTTP CONNECT handshake through an HTTP proxy."""
    import base64
    req = 'CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n' % (
        host, port, host, port)
    if username and password:
        cred = base64.b64encode(
            ('%s:%s' % (username, password)).encode()).decode()
        req += 'Proxy-Authorization: Basic %s\r\n' % cred
    req += '\r\n'
    writer.write(req.encode())
    await writer.drain()

    ## Read response line
    line = await reader.readline()
    if not line:
        raise RuntimeError('HTTP proxy: empty response')
    parts = line.decode('utf-8', errors='replace').split()
    if len(parts) < 2 or not parts[1].startswith('2'):
        raise RuntimeError('HTTP CONNECT failed: %s' %
                           line.decode('utf-8', errors='replace').strip())
    ## Consume rest of headers
    while True:
        hdr = await reader.readline()
        if hdr in (b'\r\n', b'\n', b''):
            break
    return True


## ---------------------------------------------------------------------------
## Bidirectional data relay
## ---------------------------------------------------------------------------

async def _relay(r1, w1, r2, w2):
    """Relay data between two stream pairs until one side closes."""

    async def _copy(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionError, asyncio.IncompleteReadError,
                OSError, asyncio.CancelledError):
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(_copy(r1, w2), _copy(r2, w1))


## ---------------------------------------------------------------------------
## Per-connection handler
## ---------------------------------------------------------------------------

async def _try_chain_one_proxy(px, dst_host, dst_port,
                               tor_socks_addr, tor_socks_port, is_whonix,
                               isolation_key=None):
    """Try to establish a chain through one exit proxy.

    isolation_key: if set, sent as SOCKS5 username to Tor so different
    keys get different Tor circuits (IsolateSOCKSAuth).  This enables
    domain rotation — the same proxy is reached via different Tor exit
    nodes depending on the destination domain.

    Returns (upstream_reader, upstream_writer) on success, raises on failure.
    """
    px_host = px['host']
    px_port = px['port']
    px_user = px.get('user') or None
    px_pass = px.get('pass') or None
    px_scheme = px.get('scheme', 'socks5')

    if is_whonix:
        upstream_r, upstream_w = await asyncio.wait_for(
            asyncio.open_connection(px_host, px_port), timeout=20)
    else:
        ## Step 1: connect to Tor SOCKS
        upstream_r, upstream_w = await asyncio.wait_for(
            asyncio.open_connection(tor_socks_addr, tor_socks_port),
            timeout=10)
        ## Step 2: through Tor, CONNECT to exit proxy
        ## Use isolation_key as SOCKS5 username so Tor assigns
        ## a different circuit per key (IsolateSOCKSAuth)
        log.debug('  chain step1: Tor→%s:%d (iso=%s)',
                  px_host, px_port, isolation_key or '-')
        await _socks5_handshake(upstream_r, upstream_w, px_host, px_port,
                                username=isolation_key,
                                password=isolation_key)

    ## Step 3: through exit proxy, CONNECT to destination
    log.debug('  chain step2: proxy→%s:%d', dst_host, dst_port)
    if px_scheme in ('socks5', 'socks'):
        await _socks5_handshake(upstream_r, upstream_w,
                                dst_host, dst_port, px_user, px_pass)
    elif px_scheme in ('http', 'https'):
        await _http_connect(upstream_r, upstream_w,
                            dst_host, dst_port, px_user, px_pass)
    else:
        raise RuntimeError('Unsupported proxy scheme: %s' % px_scheme)

    return upstream_r, upstream_w


def _get_proxy_candidates(proxy_source, dst_host):
    """Return a list of proxy dicts to try for this connection.

    Order: domain-bound proxy first, then alive proxies (round-robin),
    then dead proxies as last resort.  This ensures connections
    preferentially use known-good proxies.
    """
    if isinstance(proxy_source, dict):
        return [proxy_source]

    candidates = []

    ## Helper to check proxy health
    def _is_alive(px):
        if not hasattr(proxy_source, 'is_proxy_alive'):
            return True
        disp = px.get('display', '%s:%s' % (px['host'], px['port']))
        return proxy_source.is_proxy_alive(disp)

    ## 1) Check domain binding — but only use if alive
    bound_px = None
    if hasattr(proxy_source, 'get_proxy_for_domain'):
        bound_px = proxy_source.get_proxy_for_domain(dst_host)
        if bound_px and _is_alive(bound_px):
            candidates.append(bound_px)
        elif bound_px:
            bound_px = None  # dead, will be added at the end

    ## 2) Split remaining proxies into alive and dead
    all_px = getattr(proxy_source, '_proxies', [])
    if not all_px:
        return candidates

    alive = []
    dead = []
    for px in all_px:
        if px in candidates or px is bound_px:
            continue
        if _is_alive(px):
            alive.append(px)
        else:
            dead.append(px)

    ## 3) Round-robin among alive proxies, then dead as fallback
    start = getattr(proxy_source, '_proxy_idx', 0)
    if alive:
        start_a = start % len(alive)
        proxy_source._proxy_idx = start + 1
        for i in range(len(alive)):
            candidates.append(alive[(start_a + i) % len(alive)])
    ## Dead domain-bound proxy tried before other dead proxies
    if bound_px and bound_px not in candidates:
        dead.insert(0, bound_px)
    for px in dead:
        candidates.append(px)

    return candidates


async def _connect_direct_tor(dst_host, dst_port,
                              tor_socks_addr, tor_socks_port, is_whonix):
    """Connect to destination directly through Tor (no external proxy).

    Used in selective proxy mode for domains not in the proxy list.
    """
    if is_whonix:
        return await asyncio.open_connection(dst_host, dst_port)
    r, w = await asyncio.open_connection(tor_socks_addr, tor_socks_port)
    await _socks5_handshake(r, w, dst_host, dst_port)
    return r, w


async def _handle_client(client_reader, client_writer, proxy_source,
                         tor_socks_addr, tor_socks_port, is_whonix):
    """Handle one incoming SOCKS5 client connection.

    proxy_source: either ExitProxyServer instance (uses domain binding +
                  round-robin) or a plain proxy dict.
    """
    peer = client_writer.get_extra_info('peername')
    upstream_w = None
    try:
        ## --- SOCKS5 server handshake (accept no-auth or user/pass) ---
        ## Tor Browser uses IsolateSOCKSAuth: sends per-domain username
        ## to get different Tor circuits.  We must accept method 0x02
        ## (and consume the auth) so Firefox doesn't reject our response.
        greeting = await asyncio.wait_for(
            client_reader.readexactly(2), timeout=10)
        ver, nmethods = greeting
        if ver != 0x05:
            return
        methods = await client_reader.readexactly(nmethods)
        if 0x02 in methods:
            ## Accept username/password auth (consume and accept it)
            client_writer.write(b'\x05\x02')
            await client_writer.drain()
            auth_ver = (await client_reader.readexactly(1))[0]
            ulen = (await client_reader.readexactly(1))[0]
            _uname = await client_reader.readexactly(ulen)
            plen = (await client_reader.readexactly(1))[0]
            _passwd = await client_reader.readexactly(plen)
            ## Always accept (local proxy, no real auth needed)
            client_writer.write(b'\x01\x00')
            await client_writer.drain()
        else:
            ## No auth
            client_writer.write(b'\x05\x00')
            await client_writer.drain()

        ## --- CONNECT request ---
        req_hdr = await asyncio.wait_for(
            client_reader.readexactly(4), timeout=10)
        ver, cmd, _, atype = req_hdr
        if ver != 0x05 or cmd != 0x01:
            client_writer.write(b'\x05\x07\x00\x01' + b'\x00' * 6)
            return

        if atype == 0x01:  # IPv4
            raw = await client_reader.readexactly(4)
            dst_host = socket.inet_ntoa(raw)
        elif atype == 0x03:  # Domain
            alen = (await client_reader.readexactly(1))[0]
            dst_host = (await client_reader.readexactly(alen)).decode()
        elif atype == 0x04:  # IPv6
            raw = await client_reader.readexactly(16)
            dst_host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            client_writer.write(b'\x05\x08\x00\x01' + b'\x00' * 6)
            return
        dst_port = struct.unpack('!H',
                                 await client_reader.readexactly(2))[0]

        ## --- Selective proxy mode: bypass proxy for non-listed domains ---
        _proxy_mode = getattr(proxy_source, '_proxy_mode', 'all')
        _sel_domains = getattr(proxy_source, '_selective_domains', set())
        if _proxy_mode == 'selective' and _sel_domains:
            _d = dst_host.lower()
            _match = False
            for pat in _sel_domains:
                if _d == pat or _d.endswith('.' + pat):
                    _match = True
                    break
            if not _match:
                ## Direct Tor connection (bypass proxy)
                log.debug('DIRECT %s:%d (selective mode, no match)',
                          dst_host, dst_port)
                upstream_r, upstream_w = await asyncio.wait_for(
                    _connect_direct_tor(dst_host, dst_port,
                                        tor_socks_addr, tor_socks_port,
                                        is_whonix),
                    timeout=20)
                client_writer.write(b'\x05\x00\x00\x01' + b'\x00' * 4 +
                                    struct.pack('!H', 0))
                await client_writer.drain()
                _conn_id = None
                if hasattr(proxy_source, '_register_connection'):
                    _conn_id = proxy_source._register_connection(
                        dst_host, dst_port, 'direct-tor')
                try:
                    await _relay(client_reader, client_writer,
                                 upstream_r, upstream_w)
                finally:
                    if _conn_id and hasattr(
                            proxy_source, '_unregister_connection'):
                        proxy_source._unregister_connection(_conn_id)
                return

        ## --- Try proxy candidates (retry on failure) ---
        candidates = _get_proxy_candidates(proxy_source, dst_host)
        if not candidates:
            log.warning('No proxies available for %s:%d', dst_host, dst_port)
            client_writer.write(b'\x05\x01\x00\x01' + b'\x00' * 6)
            return

        ## Build isolation key for domain rotation.
        ## Different domains get different Tor circuits via IsolateSOCKSAuth.
        ## Key = hash of base domain so subdomains share the same circuit.
        iso_key = None
        if hasattr(proxy_source, '_domain_rotation') and \
                proxy_source._domain_rotation:
            _parts = dst_host.rsplit('.', 2)
            _base = '.'.join(_parts[-2:]) if len(_parts) >= 2 else dst_host
            iso_key = 'ep-%s' % _base

        last_err = None
        ## Try up to 5 alive proxies (or all if fewer).
        ## Candidates are already sorted: alive first, dead last.
        max_tries = min(len(candidates), 5)
        for attempt, px in enumerate(candidates[:max_tries]):
            px_display = px.get('display', '%s:%s' % (px['host'], px['port']))
            log.debug('CONNECT %s:%d via %s (attempt %d/%d)',
                      dst_host, dst_port, px_display, attempt + 1, max_tries)
            try:
                upstream_r, upstream_w = await asyncio.wait_for(
                    _try_chain_one_proxy(px, dst_host, dst_port,
                                         tor_socks_addr, tor_socks_port,
                                         is_whonix,
                                         isolation_key=iso_key),
                    timeout=25)
                ## Success! Report health + register connection
                log.debug('CONNECTED %s:%d via %s', dst_host, dst_port,
                          px_display)
                if hasattr(proxy_source, 'report_proxy_success'):
                    proxy_source.report_proxy_success(px_display)
                _conn_id = None
                if hasattr(proxy_source, '_register_connection'):
                    _conn_id = proxy_source._register_connection(
                        dst_host, dst_port, px_display)
                break
            except Exception as e:
                last_err = e
                log.debug('Proxy %s failed for %s:%d: %s',
                          px_display, dst_host, dst_port, e)
                if hasattr(proxy_source, 'report_proxy_failure'):
                    proxy_source.report_proxy_failure(px_display)
                continue
        else:
            ## All proxies failed
            log.warning('All %d proxies failed for %s:%d, last: %s',
                        max_tries, dst_host, dst_port, last_err)
            client_writer.write(b'\x05\x05\x00\x01' + b'\x00' * 6)
            return

        ## --- Success: tell the client ---
        client_writer.write(b'\x05\x00\x00\x01' + b'\x00' * 4 +
                            struct.pack('!H', 0))
        await client_writer.drain()

        ## --- Relay data ---
        try:
            await _relay(client_reader, client_writer,
                         upstream_r, upstream_w)
        finally:
            if _conn_id and hasattr(proxy_source, '_unregister_connection'):
                proxy_source._unregister_connection(_conn_id)

    except asyncio.CancelledError:
        pass
    except asyncio.TimeoutError:
        log.warning('Timeout handling %s', peer)
        try:
            client_writer.write(b'\x05\x04\x00\x01' + b'\x00' * 6)
        except Exception:
            pass
    except Exception as e:
        log.warning('Error handling %s: %s', peer, e)
        try:
            client_writer.write(b'\x05\x01\x00\x01' + b'\x00' * 6)
        except Exception:
            pass
    finally:
        for _w in (upstream_w, client_writer):
            if _w is not None:
                try:
                    _w.close()
                except Exception:
                    pass


## ---------------------------------------------------------------------------
## Public API — ExitProxyServer
## ---------------------------------------------------------------------------

def parse_proxy_url(url):
    """Parse a proxy URL like socks5://user:pass@host:port into a dict."""
    if '://' not in url:
        url = 'socks5://' + url
    p = urlparse(url)
    return {
        'scheme': (p.scheme or 'socks5').lower(),
        'host': p.hostname or '',
        'port': p.port or 1080,
        'user': p.username or '',
        'pass': p.password or '',
        'display': url,
    }


def find_available_port(start=9060, end=9160):
    """Find an available TCP port on localhost."""
    import errno
    for port in range(start, end):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('127.0.0.1', port))
            s.close()
            return port
        except OSError as e:
            s.close()
            if e.errno in (errno.EADDRINUSE, errno.EACCES):
                continue
            raise
    ## Fallback: let OS assign
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


class ExitProxyServer:
    """Runs a local SOCKS5 proxy that chains traffic through Tor and
    then through an external exit proxy.

    Usage::

        srv = ExitProxyServer(
            exit_proxies=['socks5://user:pass@host:port'],
            tor_socks_addr='127.0.0.1',
            tor_socks_port=9050)
        srv.start()   # non-blocking, runs in background thread
        ...
        srv.stop()

    For transparent interception (take over Tor's SocksPort)::

        srv = ExitProxyServer(
            exit_proxies=[...],
            listen_bindings=[('127.0.0.1', 9050),
                             ('10.152.152.10', 9050)],
            tor_socks_addr='127.0.0.1',
            tor_socks_port=19050)  # Tor moved to internal port
        srv.start()
    """

    def __init__(self, exit_proxies, local_port=0,
                 tor_socks_addr='127.0.0.1', tor_socks_port=9050,
                 is_whonix=None, listen_bindings=None,
                 dead_proxy_threshold=3):
        self._proxies = [parse_proxy_url(u) if isinstance(u, str) else u
                         for u in exit_proxies]
        self._proxy_idx = 0
        self.tor_socks_addr = tor_socks_addr
        self.tor_socks_port = tor_socks_port
        self.is_whonix = _WHONIX if is_whonix is None else is_whonix

        ## Listen bindings: list of (addr, port) tuples
        if listen_bindings:
            self._listen_bindings = list(listen_bindings)
        else:
            p = local_port or find_available_port()
            self._listen_bindings = [('127.0.0.1', p)]
        self.local_port = self._listen_bindings[0][1]

        self._loop = None
        self._servers = []
        self._thread = None
        self._running = False
        self._conn_count = 0
        self._active_connections = {}  # id → {proxy, dst, start}
        self._connection_history = {}   # id → {proxy, dst, start, ended}
        self._conn_id_seq = 0
        self._conn_lock = threading.Lock()
        self._client_writers = set()  # track writers for clean shutdown

        ## Domain rotation: use different Tor circuits per domain
        self._domain_rotation = False

        ## Selective proxy mode: 'all' = proxy everything,
        ## 'selective' = only proxy domains in _selective_domains
        self._proxy_mode = 'all'
        self._selective_domains = set()

        ## Proxy health tracking: key = proxy display URL
        ## value = {'consecutive_fails': int, 'alive': bool,
        ##          'last_success': float, 'last_fail': float}
        self._proxy_health = {}
        self._dead_threshold = dead_proxy_threshold
        self._health_lock = threading.Lock()

    @property
    def connection_count(self):
        return self._conn_count

    def _next_proxy(self):
        """Round-robin proxy rotation."""
        if not self._proxies:
            return None
        px = self._proxies[self._proxy_idx % len(self._proxies)]
        self._proxy_idx += 1
        return px

    def report_proxy_success(self, proxy_display):
        """Mark a proxy as successful (reset failure counter)."""
        import time as _t
        with self._health_lock:
            h = self._proxy_health.setdefault(
                proxy_display, {'consecutive_fails': 0, 'alive': True,
                                'last_success': 0, 'last_fail': 0})
            h['consecutive_fails'] = 0
            h['alive'] = True
            h['last_success'] = _t.time()

    def report_proxy_failure(self, proxy_display):
        """Mark a proxy as failed. After threshold consecutive fails,
        mark it dead so it's deprioritized in candidate selection."""
        import time as _t
        with self._health_lock:
            h = self._proxy_health.setdefault(
                proxy_display, {'consecutive_fails': 0, 'alive': True,
                                'last_success': 0, 'last_fail': 0})
            h['consecutive_fails'] += 1
            h['last_fail'] = _t.time()
            if h['consecutive_fails'] >= self._dead_threshold:
                h['alive'] = False

    def is_proxy_alive(self, proxy_display):
        """Check if a proxy is considered alive."""
        with self._health_lock:
            h = self._proxy_health.get(proxy_display)
            if h is None:
                return True  # unknown = assume alive
            return h['alive']

    def get_proxy_health(self):
        """Return a snapshot of proxy health data."""
        with self._health_lock:
            return dict(self._proxy_health)

    def get_alive_proxies(self):
        """Return list of proxy dicts that are considered alive."""
        return [px for px in self._proxies
                if self.is_proxy_alive(
                    px.get('display', '%s:%s' % (px['host'], px['port'])))]

    def get_dead_proxies(self):
        """Return list of proxy dicts that are considered dead."""
        return [px for px in self._proxies
                if not self.is_proxy_alive(
                    px.get('display', '%s:%s' % (px['host'], px['port'])))]

    def _register_connection(self, dst_host, dst_port, proxy_display):
        """Register an active connection. Returns connection id."""
        import time
        with self._conn_lock:
            self._conn_id_seq += 1
            cid = self._conn_id_seq
            self._active_connections[cid] = {
                'proxy': proxy_display,
                'dst': '%s:%d' % (dst_host, dst_port),
                'dst_host': dst_host,
                'dst_port': dst_port,
                'start': time.time(),
            }
        return cid

    def _unregister_connection(self, cid):
        import time as _time
        with self._conn_lock:
            info = self._active_connections.pop(cid, None)
            if info:
                info['ended'] = _time.time()
                self._connection_history[cid] = info
            ## Prune history older than 120 seconds
            cutoff = _time.time() - 120
            self._connection_history = {
                k: v for k, v in self._connection_history.items()
                if v.get('ended', 0) > cutoff}

    def get_active_connections(self):
        """Return a snapshot of active connections."""
        with self._conn_lock:
            return dict(self._active_connections)

    def get_connection_history(self):
        """Return active + recently-finished connections for display."""
        with self._conn_lock:
            merged = dict(self._connection_history)
            merged.update(self._active_connections)
            return merged

    async def _client_cb(self, reader, writer):
        self._client_writers.add(writer)
        self._conn_count += 1
        try:
            await _handle_client(reader, writer, self,
                                 self.tor_socks_addr, self.tor_socks_port,
                                 self.is_whonix)
        finally:
            self._client_writers.discard(writer)

    async def _run_server(self):
        self._servers = []
        try:
            for addr, port in self._listen_bindings:
                ## Retry binding a few times (Tor may still be releasing)
                last_err = None
                for attempt in range(8):
                    try:
                        srv = await asyncio.start_server(
                            self._client_cb, addr, port,
                            reuse_address=True)
                        self._servers.append(srv)
                        log.info(
                            'Exit proxy listening on %s:%d '
                            '(Whonix=%s, proxies=%d, '
                            'tor_upstream=%s:%d)',
                            addr, port, self.is_whonix,
                            len(self._proxies),
                            self.tor_socks_addr,
                            self.tor_socks_port)
                        last_err = None
                        break
                    except OSError as e:
                        last_err = e
                        log.debug('Bind %s:%d attempt %d failed: %s',
                                  addr, port, attempt + 1, e)
                        await asyncio.sleep(0.5)
                if last_err:
                    raise last_err
        except Exception as e:
            self._start_error = str(e)
            self._start_event.set()
            self._loop.stop()
            return

        ## Signal successful start
        self._start_event.set()

        try:
            await asyncio.gather(
                *(srv.serve_forever() for srv in self._servers))
        except asyncio.CancelledError:
            pass

    async def _async_shutdown(self):
        """Gracefully close servers, client connections, and tasks."""
        ## Close servers (stop accepting new connections)
        for srv in self._servers:
            srv.close()
        for srv in self._servers:
            try:
                await srv.wait_closed()
            except Exception:
                pass
        ## Close all active client writers to unblock relay loops
        for w in list(self._client_writers):
            try:
                w.close()
            except Exception:
                pass
        self._client_writers.clear()
        ## Cancel all remaining tasks except this one
        current = asyncio.current_task()
        tasks = [t for t in asyncio.all_tasks()
                 if t is not current]
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        ## All cleaned up — stop the event loop
        self._loop.stop()

    def _thread_main(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.create_task(self._run_server())
        try:
            self._loop.run_forever()
        except Exception as e:
            log.error('Exit proxy server error: %s', e)
        finally:
            try:
                self._loop.run_until_complete(
                    self._loop.shutdown_asyncgens())
            except Exception:
                pass
            self._loop.close()

    def start(self, wait_ready=True, timeout=10):
        """Start the proxy server in a background daemon thread.

        If wait_ready=True (default), blocks until the server is
        actually listening or raises on failure.
        """
        if self._running:
            return
        if not self._proxies:
            raise ValueError('No exit proxies configured')
        self._start_error = None
        self._start_event = threading.Event()
        self._running = True
        self._conn_count = 0
        self._thread = threading.Thread(target=self._thread_main,
                                        daemon=True,
                                        name='ExitProxyServer')
        self._thread.start()
        if wait_ready:
            self._start_event.wait(timeout=timeout)
            if self._start_error:
                self._running = False
                raise RuntimeError(
                    'Proxy server failed to start: %s'
                    % self._start_error)

    def stop(self):
        """Stop the proxy server gracefully.

        Schedules _async_shutdown on the event loop which closes servers,
        client connections, cancels tasks, then stops the loop.
        """
        if not self._running:
            return
        self._running = False
        loop = self._loop
        if loop and not loop.is_closed():
            try:
                asyncio.run_coroutine_threadsafe(
                    self._async_shutdown(), loop)
            except Exception:
                ## Fallback: force stop
                try:
                    loop.call_soon_threadsafe(loop.stop)
                except Exception:
                    pass
        if self._thread:
            self._thread.join(timeout=8)
            self._thread = None
        self._servers = []
        self._loop = None
        log.info('Exit proxy server stopped')

    @property
    def running(self):
        return self._running and self._thread is not None and \
               self._thread.is_alive()

    def update_proxies(self, proxy_urls):
        """Update the proxy list without restart.

        Also cleans domain bindings that reference proxies no longer
        in the list.
        """
        self._proxies = [parse_proxy_url(u) if isinstance(u, str) else u
                         for u in proxy_urls]
        self._proxy_idx = 0
        ## Clean stale domain bindings
        self._clean_domain_bindings()

    def _clean_domain_bindings(self):
        """Remove domain bindings that reference proxies not in list."""
        bindings = getattr(self, '_domain_bindings', {})
        if not bindings or not self._proxies:
            return
        current_displays = set()
        for px in self._proxies:
            current_displays.add(px.get('display', ''))
            current_displays.add(
                '%s://%s:%s' % (px.get('scheme', 'socks5'),
                                px.get('host', ''),
                                px.get('port', '')))
        stale = [d for d, px in bindings.items()
                 if px.get('display', '') not in current_displays]
        for d in stale:
            del bindings[d]

    def set_domain_bindings(self, bindings):
        """Set domain→proxy bindings.

        bindings: dict  domain_str → proxy_url_str
        """
        self._domain_bindings = {}
        for domain, url in bindings.items():
            px = parse_proxy_url(url) if isinstance(url, str) else url
            self._domain_bindings[domain.lower()] = px
        self._clean_domain_bindings()

    def get_proxy_for_domain(self, domain):
        """Return the bound proxy for a domain.

        If no explicit binding exists, auto-assigns one via consistent
        hashing so the same domain always routes through the same proxy.
        """
        d = domain.lower()
        bindings = getattr(self, '_domain_bindings', {})

        ## Exact match first
        if d in bindings:
            return bindings[d]
        ## Wildcard / suffix match  (e.g. ".example.com")
        for pattern, px in bindings.items():
            if d.endswith('.' + pattern) or d == pattern:
                return px

        ## Auto-bind: consistently hash domain to a proxy
        if self._proxies:
            import hashlib
            h = int(hashlib.md5(d.encode()).hexdigest(), 16)
            px = self._proxies[h % len(self._proxies)]
            bindings[d] = px
            return px

        return None


## ---------------------------------------------------------------------------
## Proxy validation
## ---------------------------------------------------------------------------

async def _get_ip_via_proxy(proxy_dict, tor_socks_addr='127.0.0.1',
                            tor_socks_port=9050, is_whonix=False,
                            timeout=20):
    """Connect through Tor → proxy → IP-check service, return exit IP.

    Tries each IP-check service in _IP_CHECK_SERVICES until one works.
    Returns (ip_string, latency_ms) on success, raises on failure.
    """
    import re as _re
    import random as _rand
    px = proxy_dict
    px_host = px['host']
    px_port = px['port']
    px_user = px.get('user') or None
    px_pass = px.get('pass') or None
    px_scheme = px.get('scheme', 'socks5')

    ## Shuffle services so we spread load across them
    services = list(_IP_CHECK_SERVICES)
    _rand.shuffle(services)
    last_err = None

    for svc_host, svc_port, svc_req in services:
        try:
            t0 = time.monotonic()

            if is_whonix:
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(px_host, px_port),
                    timeout=timeout)
            else:
                ## Step 1: connect to Tor SOCKS
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(tor_socks_addr, tor_socks_port),
                    timeout=timeout)
                ## Step 2: SOCKS5 CONNECT to exit proxy through Tor
                await _socks5_handshake(r, w, px_host, px_port)

            ## Step 3: through exit proxy, connect to IP check service
            if px_scheme in ('socks5', 'socks'):
                await _socks5_handshake(r, w, svc_host, svc_port,
                                        px_user, px_pass)
            elif px_scheme in ('http', 'https'):
                await _http_connect(r, w, svc_host, svc_port,
                                    px_user, px_pass)
            else:
                raise RuntimeError('Unsupported scheme: %s' % px_scheme)

            ## Step 4: HTTP request to get our IP
            w.write(svc_req.encode())
            await w.drain()
            resp_data = b''
            try:
                while len(resp_data) < 4096:
                    chunk = await asyncio.wait_for(
                        r.read(4096), timeout=10)
                    if not chunk:
                        break
                    resp_data += chunk
            except (asyncio.TimeoutError, ConnectionError):
                pass
            finally:
                try:
                    w.close()
                except Exception:
                    pass

            latency = int((time.monotonic() - t0) * 1000)
            body = resp_data.decode('utf-8', errors='replace')
            if '\r\n\r\n' in body:
                body = body.split('\r\n\r\n', 1)[1]
            ip_match = _re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body)
            if ip_match:
                return ip_match.group(1), latency
            last_err = RuntimeError(
                'No IP in %s response: %s' % (svc_host, body[:100]))
        except Exception as e:
            last_err = e
            try:
                w.close()
            except Exception:
                pass
            continue

    raise last_err or RuntimeError('All IP-check services failed')


## Hosts used for TLS MITM detection — diverse CDNs/CAs to catch
## selective interception.  If ANY host fails cert verification,
## the proxy is flagged as MITM.
_TLS_CHECK_HOSTS = [
    'www.google.com',
    'www.cloudflare.com',
    'duckduckgo.com',
    'api.ipify.org',
]


async def _check_tls_one_host(proxy_dict, tls_host,
                               tor_socks_addr, tor_socks_port,
                               is_whonix, timeout):
    """Try TLS handshake to one host through the proxy.

    Returns:
      'ok'    – valid certificate
      'mitm'  – certificate verification failed (MITM)
      'error' – connection/other error (not necessarily MITM)
    Along with an error message string (empty on 'ok').
    """
    import ssl
    px = proxy_dict
    px_host = px['host']
    px_port = px['port']
    px_user = px.get('user') or None
    px_pass = px.get('pass') or None
    px_scheme = px.get('scheme', 'socks5')
    tls_port = 443

    try:
        if is_whonix:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(px_host, px_port), timeout=timeout)
        else:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(tor_socks_addr, tor_socks_port),
                timeout=timeout)
            await _socks5_handshake(r, w, px_host, px_port)

        if px_scheme in ('socks5', 'socks'):
            await _socks5_handshake(r, w, tls_host, tls_port,
                                    px_user, px_pass)
        elif px_scheme in ('http', 'https'):
            await _http_connect(r, w, tls_host, tls_port,
                                px_user, px_pass)

        ctx = ssl.create_default_context()
        loop = asyncio.get_event_loop()
        transport = w.transport
        protocol = transport.get_protocol()
        new_transport = await asyncio.wait_for(
            loop.start_tls(transport, protocol, ctx,
                           server_hostname=tls_host),
            timeout=timeout)
        new_transport.close()
        return 'ok', ''
    except ssl.SSLCertVerificationError as e:
        return 'mitm', '%s: %s' % (tls_host, e)
    except ssl.SSLError as e:
        return 'mitm', '%s: %s' % (tls_host, e)
    except Exception as e:
        return 'error', '%s: %s' % (tls_host, e)
    finally:
        try:
            w.close()
        except Exception:
            pass


async def _check_tls_safety(proxy_dict, tor_socks_addr='127.0.0.1',
                            tor_socks_port=9050, is_whonix=False,
                            timeout=15):
    """Check if a proxy intercepts/modifies TLS (MITM).

    Tests against multiple diverse HTTPS hosts.  If ANY host fails
    certificate verification, the proxy is flagged as MITM.
    Connection errors to individual hosts are tolerated (might be
    routing issues), but cert failures are definitive.

    Returns True if TLS is clean, raises RuntimeError if MITM detected.
    """
    mitm_errors = []
    ok_count = 0
    for host in _TLS_CHECK_HOSTS:
        try:
            status, msg = await asyncio.wait_for(
                _check_tls_one_host(proxy_dict, host,
                                    tor_socks_addr, tor_socks_port,
                                    is_whonix, timeout),
                timeout=timeout)
        except asyncio.TimeoutError:
            continue  # host unreachable — not necessarily MITM
        if status == 'mitm':
            mitm_errors.append(msg)
        elif status == 'ok':
            ok_count += 1
            ## One confirmed-good host is enough if no MITM seen yet
            ## but keep checking to catch selective interception

    if mitm_errors:
        raise RuntimeError('TLS MITM on %d/%d hosts: %s' % (
            len(mitm_errors), len(_TLS_CHECK_HOSTS),
            '; '.join(mitm_errors[:2])))

    if ok_count == 0:
        ## Could not verify any host (all errored/timed out)
        raise RuntimeError('TLS check inconclusive: '
                           'no host reachable for verification')

    return True


async def check_proxy(proxy_url, tor_socks_addr='127.0.0.1',
                      tor_socks_port=9050, is_whonix=False, timeout=15,
                      check_tls=False):
    """Validate a single proxy.  Returns dict with results.

    {
      'url': 'socks5://host:port',
      'alive': True/False,
      'exit_ip': '1.2.3.4' or None,
      'latency_ms': 1234 or None,
      'error': None or 'error message',
    }

    Note: TLS MITM detection has been removed.  Public free proxies
    almost always trigger false-positive MITM warnings.  For secure
    and clean IP use your own trusted proxies.
    """
    px = parse_proxy_url(proxy_url) if isinstance(proxy_url, str) \
         else proxy_url
    url = px.get('display', proxy_url)
    try:
        ip, lat = await asyncio.wait_for(
            _get_ip_via_proxy(px, tor_socks_addr, tor_socks_port,
                              is_whonix, timeout=timeout),
            timeout=timeout)
    except asyncio.TimeoutError:
        return {'url': url, 'alive': False, 'exit_ip': None,
                'latency_ms': None, 'error': 'timeout'}
    except ConnectionRefusedError:
        return {'url': url, 'alive': False, 'exit_ip': None,
                'latency_ms': None, 'error': 'refused'}
    except Exception as e:
        msg = str(e)
        if 'general failure' in msg:
            msg = 'connect failed'
        elif 'host unreachable' in msg:
            msg = 'unreachable'
        elif 'connection refused' in msg.lower():
            msg = 'refused'
        elif not msg:
            msg = type(e).__name__
        return {'url': url, 'alive': False, 'exit_ip': None,
                'latency_ms': None, 'error': msg[:50]}

    return {'url': url, 'alive': True, 'exit_ip': ip,
            'latency_ms': lat, 'error': None}


async def check_proxies(proxy_urls, tor_socks_addr='127.0.0.1',
                        tor_socks_port=9050, is_whonix=False,
                        timeout=15, concurrency=100,
                        progress_cb=None):
    """Check multiple proxies concurrently.

    progress_cb(done_count, total, result_dict) is called per proxy.
    Returns list of result dicts.
    """
    sem = asyncio.Semaphore(concurrency)
    results = []
    total = len(proxy_urls)
    done = [0]

    async def _check_one(url):
        async with sem:
            res = await check_proxy(url, tor_socks_addr, tor_socks_port,
                                    is_whonix, timeout)
            done[0] += 1
            if progress_cb:
                try:
                    progress_cb(done[0], total, res)
                except Exception:
                    pass
            return res

    tasks = [_check_one(u) for u in proxy_urls]
    results = await asyncio.gather(*tasks)
    return list(results)


def check_proxies_sync(proxy_urls, tor_socks_addr='127.0.0.1',
                       tor_socks_port=9050, is_whonix=False,
                       timeout=15, concurrency=50, progress_cb=None):
    """Synchronous wrapper for check_proxies — for use from Qt threads."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(
            check_proxies(proxy_urls, tor_socks_addr, tor_socks_port,
                          is_whonix, timeout, concurrency, progress_cb))
    finally:
        loop.close()


async def verify_exit_ip(local_port, timeout=30):
    """Connect through the running local proxy server and return exit IP.

    This verifies the full chain: app → local:port → Tor → proxy → dest.
    Tries multiple IP-check services for reliability.
    Returns (exit_ip, latency_ms) or raises.
    """
    import re as _re
    import random as _rand
    services = list(_IP_CHECK_SERVICES)
    _rand.shuffle(services)
    last_err = None

    for svc_host, svc_port, svc_req in services:
        try:
            t0 = time.monotonic()

            r, w = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', local_port),
                timeout=10)

            ## SOCKS5 client handshake to our local server
            w.write(b'\x05\x01\x00')
            await w.drain()
            resp = await r.readexactly(2)
            if resp != b'\x05\x00':
                raise RuntimeError('Local proxy bad greeting: %r' % resp)

            ## CONNECT to IP check service
            host_bytes = svc_host.encode()
            req = (b'\x05\x01\x00\x03' +
                   bytes([len(host_bytes)]) + host_bytes +
                   struct.pack('!H', svc_port))
            w.write(req)
            await w.drain()

            resp = await asyncio.wait_for(
                r.readexactly(4), timeout=timeout)
            if resp[1] != 0x00:
                raise RuntimeError(
                    'CONNECT failed status=0x%02x' % resp[1])
            ## consume bound address
            atype = resp[3]
            if atype == 0x01:
                await r.readexactly(6)
            elif atype == 0x04:
                await r.readexactly(18)
            elif atype == 0x03:
                alen = (await r.readexactly(1))[0]
                await r.readexactly(alen + 2)

            ## HTTP request
            w.write(svc_req.encode())
            await w.drain()
            data = b''
            while len(data) < 4096:
                chunk = await asyncio.wait_for(
                    r.read(4096), timeout=15)
                if not chunk:
                    break
                data += chunk
            try:
                w.close()
            except Exception:
                pass

            latency = int((time.monotonic() - t0) * 1000)
            body = data.decode('utf-8', errors='replace')
            if '\r\n\r\n' in body:
                body = body.split('\r\n\r\n', 1)[1]
            m = _re.search(
                r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', body)
            if m:
                return m.group(1), latency
            last_err = RuntimeError(
                'No IP in %s response: %s' % (svc_host, body[:100]))
        except Exception as e:
            last_err = e
            try:
                w.close()
            except Exception:
                pass
            continue

    raise last_err or RuntimeError('All IP-check services failed')


def verify_exit_ip_sync(local_port, timeout=30):
    """Synchronous wrapper for verify_exit_ip."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(verify_exit_ip(local_port, timeout))
    finally:
        loop.close()


def auto_bind_domains(proxy_urls, domains):
    """Algorithmically bind domains to proxies using consistent hashing.

    Returns dict: domain → proxy_url.
    Each domain always maps to the same proxy (deterministic).
    """
    if not proxy_urls or not domains:
        return {}
    import hashlib
    bindings = {}
    for domain in domains:
        h = int(hashlib.md5(domain.lower().encode()).hexdigest(), 16)
        idx = h % len(proxy_urls)
        bindings[domain.lower()] = proxy_urls[idx]
    return bindings


## ---------------------------------------------------------------------------
## Tor SocksPort interception — swap Tor's SocksPort so our proxy
## transparently handles ALL traffic.
## ---------------------------------------------------------------------------

def _save_intercept_state(state):
    """Save intercept state to disk for crash recovery."""
    d = os.path.dirname(_INTERCEPT_STATE_FILE)
    os.makedirs(d, exist_ok=True)
    with open(_INTERCEPT_STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)


def _load_intercept_state():
    """Load saved intercept state, or None."""
    try:
        with open(_INTERCEPT_STATE_FILE, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _clear_intercept_state():
    """Remove intercept state file."""
    try:
        os.remove(_INTERCEPT_STATE_FILE)
    except FileNotFoundError:
        pass


def intercept_tor_socks(get_controller_func, internal_port=None):
    """Swap Tor's SocksPort to an internal port so our proxy can
    take over the original port(s).

    All applications that were using Tor's SOCKS port will now
    transparently go through our exit proxy.

    Args:
        get_controller_func: callable returning an authenticated
                             stem Controller
        internal_port: optional specific port for Tor's new
                       internal SocksPort (auto-found if None)

    Returns: dict {
        'original_conf': list of original SocksPort config strings,
        'internal_port': int,
        'listen_bindings': list of [addr, port] pairs,
    }
    """
    import stem.control

    ctrl = get_controller_func()

    ## Get current SOCKS listeners (addr, port)
    try:
        listeners = ctrl.get_listeners(stem.control.Listener.SOCKS)
    except Exception:
        listeners = []
    if not listeners:
        ctrl.close()
        raise RuntimeError('No Tor SocksPort listeners found')

    ## Get full config strings for restoration — NEVER fall back to
    ## a hardcoded port; use the actual listeners instead.
    try:
        original_conf = ctrl.get_conf('SocksPort', multiple=True)
    except Exception:
        original_conf = None
    if not original_conf:
        ## Build from actual listeners so we restore to the right port
        original_conf = ['%s:%d' % (str(a), int(p))
                         for a, p in listeners]

    ## Verify: check that the ports we'll take over belong to THIS
    ## Tor instance and aren't occupied by another process.
    for addr, port in listeners:
        port = int(port)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((str(addr), port))
            s.close()
        except (ConnectionRefusedError, OSError):
            ctrl.close()
            raise RuntimeError(
                'Port %s:%d not reachable — may belong to '
                'another Tor instance' % (addr, port))

    ## Determine internal port
    if internal_port is None:
        internal_port = find_available_port(start=19050, end=19150)

    ## Build listen bindings from current listeners
    listen_bindings = [[str(addr), int(port)]
                       for addr, port in listeners]

    log.info('Intercepting Tor SocksPort: original=%s, '
             'listeners=%s, moving to 127.0.0.1:%d',
             original_conf, listen_bindings, internal_port)

    ## Save torrc path BEFORE modifying — needed for crash recovery
    ## if Tor persists the internal port to disk (e.g. Tor Browser SAVECONF)
    torrc_path = None
    torrc_had_socks_port = True  # assume yes by default (safe)
    try:
        torrc_path = ctrl.get_info('config-file')
    except Exception:
        pass
    ## Check if the torrc file originally had a SocksPort line.
    ## Tor Browser sets SocksPort via command-line (+__SocksPort), NOT
    ## in the torrc.  If we add one via SETCONF and Tor persists it,
    ## the torrc line + command-line create a DUPLICATE bind on the
    ## same port → "Failed to bind one of the listener ports".
    ## We record this so crash recovery can DELETE the line instead
    ## of replacing it.
    if torrc_path:
        try:
            with open(torrc_path, 'r') as _f:
                torrc_had_socks_port = any(
                    re.match(r'^\s*SocksPort\s', line)
                    for line in _f)
        except Exception:
            pass

    ## Swap: set Tor to internal-only port
    ctrl.set_conf('SocksPort', '127.0.0.1:%d' % internal_port)
    ctrl.close()

    ## Wait for Tor to fully release the ports
    for addr, port in listeners:
        _wait_port_free(str(addr), int(port), timeout=5)

    state = {
        'original_conf': original_conf,
        'internal_port': internal_port,
        'listen_bindings': listen_bindings,
        'torrc_path': torrc_path,
        'torrc_had_socks_port': torrc_had_socks_port,
    }
    _save_intercept_state(state)

    return state


def _wait_port_free(addr, port, timeout=5):
    """Wait until a port is free (not listening)."""
    import time as _t
    deadline = _t.monotonic() + timeout
    while _t.monotonic() < deadline:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((addr, port))
            s.close()
            ## Still accepting connections — wait
            _t.sleep(0.3)
        except (ConnectionRefusedError, OSError):
            ## Port is free
            return
    log.warning('Port %s:%d still in use after %.1fs', addr, port, timeout)


def _repair_torrc_file(torrc_path, original_conf,
                       torrc_had_socks_port=True):
    """Repair a torrc file where Tor persisted the internal intercept port.

    Tor Browser (and other Tor instances that call SAVECONF) may write
    the intercepted SocksPort (e.g. 19050) to disk.  If the panel
    crashes, the torrc stays corrupted and Tor Browser won't work on
    next launch.

    If torrc_had_socks_port is False (Tor Browser case), the SocksPort
    line is DELETED entirely — Tor Browser sets SocksPort via
    command-line (+__SocksPort) and a duplicate in torrc causes
    "Failed to bind one of the listener ports".
    """
    if not torrc_path:
        return
    try:
        with open(torrc_path, 'r') as f:
            lines = f.readlines()

        new_socks = None
        if original_conf:
            new_socks = original_conf[0]

        changed = False
        new_lines = []
        for line in lines:
            m = re.match(r'^(\s*SocksPort\s+)(\S+)(.*)', line)
            if m:
                current_val = m.group(2)
                ## Only fix if the port is in the internal range
                try:
                    port_str = current_val.rsplit(':', 1)[-1]
                    port_num = int(port_str)
                except (ValueError, IndexError):
                    new_lines.append(line)
                    continue
                if 19050 <= port_num <= 19199:
                    if not torrc_had_socks_port:
                        ## Original torrc had no SocksPort — delete line
                        changed = True
                        log.info('Repaired torrc %s: removed SocksPort %s '
                                 '(originally set via command-line)',
                                 torrc_path, current_val)
                        continue  # skip this line
                    elif new_socks:
                        ## Replace with original value
                        new_lines.append('%s%s%s\n' % (
                            m.group(1), new_socks, m.group(3)))
                        changed = True
                        log.info('Repaired torrc %s: SocksPort %s → %s',
                                 torrc_path, current_val, new_socks)
                        continue
            new_lines.append(line)

        if changed:
            with open(torrc_path, 'w') as f:
                f.writelines(new_lines)
    except Exception as e:
        log.warning('Failed to repair torrc %s: %s', torrc_path, e)


def restore_tor_socks(get_controller_func, original_conf=None):
    """Restore Tor's original SocksPort configuration.

    If original_conf is None, loads from the saved intercept state
    file (crash recovery).  Retries a few times if ports are still
    held by dying proxy processes.

    Also repairs the torrc file if Tor persisted the internal port.
    """
    state = _load_intercept_state()
    torrc_path = None
    torrc_had_socks_port = True  # safe default
    if state:
        torrc_path = state.get('torrc_path')
        torrc_had_socks_port = state.get('torrc_had_socks_port', True)
        if original_conf is None:
            original_conf = state.get('original_conf')
    if not original_conf:
        log.warning('No original SocksPort config to restore')
        _clear_intercept_state()
        return

    import time as _t
    last_err = None
    for attempt in range(6):
        try:
            ctrl = get_controller_func()
            log.info('Restoring Tor SocksPort (attempt %d): %s',
                     attempt + 1, original_conf)
            if len(original_conf) == 1:
                ctrl.set_conf('SocksPort', original_conf[0])
            else:
                ctrl.set_options(
                    [('SocksPort', v) for v in original_conf])
            ## Also get torrc path if we don't have it
            if not torrc_path:
                try:
                    torrc_path = ctrl.get_info('config-file')
                except Exception:
                    pass
            ctrl.close()
            ## Repair the torrc file so Tor doesn't start with
            ## the internal port on next launch
            _repair_torrc_file(torrc_path, original_conf,
                               torrc_had_socks_port)
            _clear_intercept_state()
            return
        except Exception as e:
            last_err = e
            log.debug('Restore attempt %d failed: %s', attempt + 1, e)
            try:
                ctrl.close()
            except Exception:
                pass
            _t.sleep(1.0)

    ## Even if runtime restore failed, try to repair the torrc file
    _repair_torrc_file(torrc_path, original_conf, torrc_had_socks_port)
    log.error('Failed to restore Tor SocksPort after retries: %s',
              last_err)
    _clear_intercept_state()
    raise RuntimeError('Restore failed: %s' % last_err)


def has_pending_intercept():
    """Check if there's a pending intercept state from a crash."""
    return _load_intercept_state() is not None


## ------------------------------------------------------------------ ##
##  Whonix Gateway nftables helpers                                    ##
## ------------------------------------------------------------------ ##
## Whonix uses nftables with tables in the `inet` family               ##
## (handles both IPv4 and IPv6).  The relevant chains:                 ##
##   inet filter input  — policy DROP, only INTERNAL_OPEN_PORTS open   ##
##   inet nat prerouting — transparent proxy rules                     ##
## We MUST insert rules into these *specific* chains; iptables-nft     ##
## creates separate `ip` family tables which are evaluated AFTER the   ##
## inet tables, so packets are already dropped before they reach       ##
## iptables rules.                                                     ##
## ------------------------------------------------------------------ ##

def _helper_run(args, capture=False, timeout=10):
    """Run the privileged firewall helper script.

    Search order for helper script:
      1. /usr/libexec/tor-control-panel/tcp-firewall-helper (Installed)
      2. Relative to this file (Development/Source)

    Execution strategy:
      1. If root: Execute directly.
      2. If user: Try `sudo -n` (requires sudoers config).
      3. Fallback: Try `pkexec` (interactive GUI prompt).
    """
    import subprocess
    import os
    import sys

    ## 1. Locate helper script
    candidates = [
        '/usr/libexec/tor-control-panel/tcp-firewall-helper',
    ]
    
    ## Add source-relative path for development
    ## __file__ = .../usr/lib/python3/dist-packages/tor_control_panel/exit_proxy.py
    ## Target   = .../usr/libexec/tor-control-panel/tcp-firewall-helper
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up 4 levels: tor_control_panel -> dist-packages -> python3 -> lib -> usr
        base_dir = os.path.abspath(os.path.join(current_dir, '../../../../'))
        dev_path = os.path.join(base_dir, 'usr/libexec/tor-control-panel/tcp-firewall-helper')
        if os.path.exists(dev_path):
            candidates.append(dev_path)
    except Exception:
        pass

    helper_path = None
    for p in candidates:
        if os.path.exists(p):
            helper_path = p
            break
    
    if not helper_path:
        raise RuntimeError(
            'Firewall helper script not found. Checked: %s' % ', '.join(candidates))

    def _exec(cmd_list):
        if capture:
            return subprocess.check_output(
                cmd_list, stderr=subprocess.STDOUT, text=True, timeout=timeout)
        subprocess.check_call(
            cmd_list, timeout=timeout,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True

    ## 2. Execute
    # Case A: Root
    if os.geteuid() == 0:
        return _exec([helper_path] + list(args))

    # Case B: User via sudo -n (preferred, silent)
    try:
        return _exec(['sudo', '-n', helper_path] + list(args))
    except (subprocess.CalledProcessError, PermissionError):
        pass  # Fallback to pkexec

    # Case C: User via pkexec (interactive)
    # Increase timeout for user interaction
    pk_timeout = None if timeout is None else timeout + 30
    cmd = ['pkexec', helper_path] + list(args)
    try:
        if capture:
            return subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, text=True, timeout=pk_timeout)
        subprocess.check_call(
            cmd, timeout=pk_timeout,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError as e:
        err_out = getattr(e, 'output', '').strip()
        if 'dismissed' in err_out.lower() or e.returncode == 126:
            raise RuntimeError('Authentication cancelled.')
        raise RuntimeError('Firewall helper failed (pkexec): %s' % err_out)
    except FileNotFoundError:
        raise RuntimeError('pkexec not found. Please install policykit-1.')


def _helper_gw_input(iface, port):
    """Add GW INPUT accept rule."""
    out = _helper_run(
        ['gw-input', '--interface', iface, '--port', str(port)],
        capture=True)
    ## Output format: "... # handle 123"
    import re
    m = re.search(r'#\s*handle\s+(\d+)', out)
    if m:
        return int(m.group(1))
    return None


def _helper_gw_redirect(iface, src_port, dst_port):
    """Add GW PREROUTING redirect rule."""
    out = _helper_run(
        ['gw-redirect', '--interface', iface,
         '--src-port', str(src_port), '--dst-port', str(dst_port)],
        capture=True)
    import re
    m = re.search(r'#\s*handle\s+(\d+)', out)
    if m:
        return int(m.group(1))
    return None


def _helper_ws_init():
    """Initialize WS dedicated table."""
    _helper_run(['ws-init'])


def _helper_ws_redirect(dst_addr, dst_port, proxy_port):
    """Add WS OUTPUT redirect rule."""
    _helper_run(['ws-redirect',
                 '--dst-addr', dst_addr,
                 '--dst-port', str(dst_port),
                 '--proxy-port', str(proxy_port)])


def _helper_ws_clear():
    """Clear WS dedicated table."""
    _helper_run(['ws-clear'])


def _helper_delete_rule(family, table, chain, handle):
    """Delete a rule by handle."""
    _helper_run(['delete-rule',
                 '--family', family,
                 '--table', table,
                 '--chain', chain,
                 '--handle', str(handle)])


def _detect_whonix_int_if():
    """Detect the internal network interface on Whonix Gateway.

    Returns interface name for nft rules:
      - Qubes-Whonix: 'vif*'  (nft wildcard for all vif interfaces)
      - Non-Qubes:    'eth1'  (standard Whonix internal interface)
    """
    import os
    if os.path.isfile('/usr/share/qubes/marker-vm'):
        return 'vif*'
    return 'eth1'


def _find_port_free_on_addrs(addrs, start=9060, end=9200):
    """Find a TCP port free on ALL given addresses (IPv4 + IPv6)."""
    import errno
    for port in range(start, end):
        all_free = True
        for addr in addrs:
            try:
                family = socket.AF_INET6 if ':' in addr else socket.AF_INET
                s = socket.socket(family, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.settimeout(0.3)
                if family == socket.AF_INET6:
                    s.setsockopt(socket.IPPROTO_IPV6,
                                 socket.IPV6_V6ONLY, 1)
                    s.bind((addr, port, 0, 0))
                else:
                    s.bind((addr, port))
                s.close()
            except OSError as e:
                try:
                    s.close()
                except Exception:
                    pass
                if e.errno in (errno.EADDRINUSE, errno.EACCES):
                    all_free = False
                    break
                all_free = False
                break
        if all_free:
            return port
    raise RuntimeError(
        'No free port in %d–%d on addresses: %s' % (start, end, addrs))


def intercept_whonix_gw(get_controller_func):
    """Set up nft redirect on Whonix Gateway using privileged helper.

    Returns: dict with state for cleanup.
    """
    import stem.control

    ctrl = get_controller_func()
    try:
        listeners = ctrl.get_listeners(stem.control.Listener.SOCKS)
    except Exception:
        listeners = []
    ctrl.close()

    if not listeners:
        raise RuntimeError('No Tor SocksPort listeners found')

    ext_addrs = set()
    ext_ports = set()
    for addr, port in listeners:
        addr = str(addr).strip('[]')
        port = int(port)
        if addr in ('127.0.0.1', '::1', 'localhost'):
            continue
        ext_addrs.add(addr)
        ext_ports.add(port)

    if not ext_addrs:
        raise RuntimeError(
            'No non-loopback Tor SOCKS listeners found. '
            'Cannot redirect Workstation traffic.')

    ext_ports = sorted(ext_ports)
    bind_addrs = sorted(ext_addrs) + ['127.0.0.1']
    proxy_port = _find_port_free_on_addrs(bind_addrs)
    log.info('Whonix GW: proxy port %d (free on %s)', proxy_port, bind_addrs)

    int_if = _detect_whonix_int_if()
    handles = []

    ## 1. Allow INPUT
    try:
        h = _helper_gw_input(int_if, proxy_port)
        if h is not None:
            handles.append(('inet', 'filter', 'input', h))
        log.info('nft: INPUT accept :%d from %s', proxy_port, int_if)
    except Exception as e:
        raise RuntimeError('Failed to add INPUT rule: %s' % e)

    ## 2. Redirect PREROUTING
    for sport in ext_ports:
        try:
            h = _helper_gw_redirect(int_if, sport, proxy_port)
            if h is not None:
                handles.append(('inet', 'nat', 'prerouting', h))
            log.info('nft: PREROUTING redirect :%d → :%d from %s',
                     sport, proxy_port, int_if)
        except Exception as e:
            log.error('nft PREROUTING rule for port %d failed: %s',
                      sport, e)

    if not handles:
        raise RuntimeError('Failed to add any nft rules.')

    listen_bindings = [('127.0.0.1', proxy_port)]
    for addr in sorted(ext_addrs):
        listen_bindings.append((addr, proxy_port))

    state = {
        'whonix_gw': True,
        'proxy_port': proxy_port,
        'nft_handles': handles,
        'int_if': int_if,
        'listen_bindings': listen_bindings,
        'ext_ports': ext_ports,
    }
    _save_intercept_state(state)
    return state


def restore_whonix_gw():
    """Remove nft redirect rules on Whonix Gateway."""
    state = _load_intercept_state()
    if not state or not state.get('whonix_gw'):
        _clear_intercept_state()
        return

    for entry in state.get('nft_handles', []):
        family, table, chain, handle = entry
        try:
            _helper_delete_rule(family, table, chain, handle)
            log.info('nft: deleted rule handle %d from %s %s %s',
                     handle, family, table, chain)
        except Exception as e:
            log.warning('nft: failed to delete handle %d: %s', handle, e)
    _clear_intercept_state()


def intercept_whonix_ws(proxy_port, get_controller_func):
    """Set up nft redirect on Whonix Workstation using privileged helper.

    Uses a dedicated nft table 'inet tor_control_panel'.
    Returns list of (addr, port) pairs that were redirected.
    """
    import stem.control

    ctrl = get_controller_func()
    try:
        listeners = ctrl.get_listeners(stem.control.Listener.SOCKS)
    except Exception:
        listeners = []
    ctrl.close()

    if not listeners:
        raise RuntimeError('No Tor SocksPort listeners on Gateway')

    ## 1. Create dedicated table and chain via helper
    try:
        _helper_ws_init()
    except Exception as e:
        raise RuntimeError('Failed to initialize nft table: %s' % e)

    rules_added = []
    for addr, port in listeners:
        addr = str(addr).strip('[]')
        port = int(port)
        if addr in ('127.0.0.1', '::1', 'localhost'):
            continue
        
        try:
            _helper_ws_redirect(addr, port, proxy_port)
            rules_added.append([addr, port])
            log.info('nft redirect (WS): %s:%d → :%d',
                     addr, port, proxy_port)
        except Exception as e:
            log.error('nft redirect failed for %s:%d: %s',
                      addr, port, e)

    state = {
        'whonix_ws': True,
        'proxy_port': proxy_port,
        'rules': rules_added,
    }
    _save_intercept_state(state)
    return rules_added


def restore_whonix_ws():
    """Remove nft redirect rules on Whonix Workstation."""
    state = _load_intercept_state()
    if not state or not state.get('whonix_ws'):
        _clear_intercept_state()
        return

    try:
        _helper_ws_clear()
        log.info('nft table tor_control_panel deleted')
    except Exception as e:
        log.debug('Failed to delete nft table: %s', e)

    _clear_intercept_state()
