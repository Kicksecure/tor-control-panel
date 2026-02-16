#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import sys
import os
import json
from subprocess import call
from . import info

from anon_connection_wizard.edit_etc_resolv_conf import edit_etc_resolv_conf_add
from anon_connection_wizard.edit_etc_resolv_conf import edit_etc_resolv_conf_remove
from anon_connection_wizard.tor_status import tor_status
from anon_connection_wizard.tor_status import write_to_temp_then_move

whonix = os.path.exists('/usr/share/anon-gw-base-files/gateway')

## Platform-aware torrc paths
##
## torrc_file_path — the SYSTEM torrc (read-only for parsing existing config)
## torrc_user_file_path — where we WRITE our config (circuit settings, etc.)
##
## On all platforms we ALWAYS apply config via set_conf (immediate).
## The torrc write is for persistence only (survives Tor restart).
## If the user_path is outside Tor's include path, config still works
## via set_conf — it just won't persist across Tor restarts.

_user_config_dir = os.path.join(
    os.path.expanduser('~'), '.config', 'tor-control-panel')

if os.path.isdir('/usr/local/etc/torrc.d'):
    ## Whonix / Kicksecure
    torrc_file_path = '/usr/local/etc/torrc.d/40_tor_control_panel.conf'
    torrc_user_file_path = '/usr/local/etc/torrc.d/50_user.conf'
elif os.path.isdir('/etc/tor/torrc.d'):
    ## Distros with torrc.d drop-in directory (Debian, etc.)
    torrc_file_path = '/etc/tor/torrc.d/40_tor_control_panel.conf'
    torrc_user_file_path = '/etc/tor/torrc.d/50_user.conf'
elif os.path.isfile('/etc/tor/torrc'):
    ## Generic Linux (Fedora, Arch, etc.) — system torrc exists
    ## but no drop-in dir.  Read from system torrc, write to
    ## user-local config (never overwrite /etc/tor/torrc).
    torrc_file_path = '/etc/tor/torrc'
    torrc_user_file_path = os.path.join(
        _user_config_dir, 'user_torrc.conf')
else:
    ## Fallback: user-local config
    torrc_file_path = os.path.join(_user_config_dir, 'torrc.conf')
    torrc_user_file_path = os.path.join(
        _user_config_dir, 'user_torrc.conf')

bridges_default_path = '/usr/share/anon-connection-wizard/bridges_default'

command_useBridges = 'UseBridges 1\n'
command_use_custom_bridge = '# Custom Bridge is used:'

bridges_command = [ 'ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n',

                    'ClientTransportPlugin snowflake exec /usr/bin/snowflake-client\n',

                    'ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy\n',
                    'ClientTransportPlugin scramblesuit exec /usr/bin/obfs4proxy\n',
                    'ClientTransportPlugin fte exec /usr/bin/fteproxy --managed\n']

bridges_type = ['obfs4', 'snowflake', 'meek', 'scramblesuit', 'fte', 'plain']

bridges_display = ['obfs4', 'snowflake',
                   'meek', 'plain']

meek_address = 'www.phpmyadmin.net'

proxy_torrc =   ['HTTPSProxy',
                'Socks4Proxy',
                'Socks5Proxy']

proxies =      ['HTTP/HTTPS',
                'SOCKS4',
                'SOCKS5']

proxy_auth =   ['HTTPSProxyAuthenticator',
                'Socks5ProxyUsername',
                'Socks5ProxyPassword']

def torrc_path():
    return(torrc_file_path)

def user_path():
    return(torrc_user_file_path)


def detect_torrc_write_path(controller):
    """Detect the correct torrc write path from a running Tor instance.

    Queries GETINFO config-file to find the REAL torrc, then determines
    the best writable path for our circuit config:
      1. If the torrc has a %include pointing to a writable dir → use that
      2. If the torrc dir itself has a writable torrc.d/ → use that
      3. If the torrc itself is writable → append-safe path alongside it
      4. Fallback → user-local config dir (set_conf still works)

    Returns (torrc_read_path, torrc_write_path) tuple.
    """
    ## Step 1: Ask the running Tor for its config file
    try:
        real_torrc = controller.get_info('config-file')
    except Exception:
        return torrc_file_path, torrc_user_file_path

    if not real_torrc or not os.path.isfile(real_torrc):
        return torrc_file_path, torrc_user_file_path

    torrc_dir = os.path.dirname(real_torrc)

    ## Step 2: Parse %include directives from the torrc
    include_dirs = []
    try:
        with open(real_torrc, 'r') as f:
            for line in f:
                line = line.strip()
                if line.lower().startswith('%include'):
                    inc_path = line.split(None, 1)[1].strip()
                    ## Resolve relative paths
                    if not os.path.isabs(inc_path):
                        inc_path = os.path.join(torrc_dir, inc_path)
                    ## Handle glob patterns (e.g. %include /etc/tor/torrc.d/*.conf)
                    inc_dir = os.path.dirname(inc_path) if '*' in inc_path \
                        else inc_path
                    if os.path.isdir(inc_dir):
                        include_dirs.append(inc_dir)
    except Exception:
        pass

    ## Step 3: Find best writable path
    ## 3a: Check %include directories
    for inc_dir in include_dirs:
        candidate = os.path.join(inc_dir, '50_user.conf')
        if os.access(inc_dir, os.W_OK):
            return real_torrc, candidate

    ## 3b: Check for torrc.d/ alongside the torrc
    torrc_d = os.path.join(torrc_dir, 'torrc.d')
    if os.path.isdir(torrc_d) and os.access(torrc_d, os.W_OK):
        return real_torrc, os.path.join(torrc_d, '50_user.conf')

    ## 3c: If torrc dir is writable, create a sibling file
    if os.access(torrc_dir, os.W_OK):
        return real_torrc, os.path.join(
            torrc_dir, '50_tor_control_panel_user.conf')

    ## 3d: Fallback to user-local config dir
    return real_torrc, os.path.join(
        _user_config_dir, 'user_torrc.conf')

def gen_torrc(args):
    bridge_type = str(args[0]) if len(args) > 0 else 'None'
    custom_bridges = str(args[1]) if len(args) > 1 else 'error-unknown-bridge-type'
    proxy_type = str(args[2]) if len(args) > 2 else 'None'

    proxy_ip = proxy_port = proxy_username = proxy_password = ''

    if proxy_type != 'None' and len(args) >= 7:
        proxy_ip = str(args[3])
        proxy_port = str(args[4])
        proxy_username = str(args[5])
        proxy_password = str(args[6])

    torrc_content = []

    print(f"gen_torrc: bridge_type: '{bridge_type}'")

    torrc_content.append('%s# %s\n' % (info.torrc_text(), torrc_user_file_path))
    torrc_content.append('DisableNetwork 0\n')

    if bridge_type in bridges_type:
        print(f"gen_torrc: (if 1) valid bridge type")
        torrc_content.append(command_useBridges)
        torrc_content.append(bridges_command[bridges_type.index(bridge_type)])
        with open(bridges_default_path) as _bf:
            bridges = json.loads(_bf.read())
        for bridge in bridges['bridges'][bridge_type]:
            if bridge.strip():
                torrc_content.append('{0}\n'.format(bridge))

    elif bridge_type == 'Custom bridges':
        print(f"gen_torrc: bridge_type is 'Custom bridges'")
        bridge = str(custom_bridges.split()[0]).lower()
        torrc_content.append(command_useBridges)
        torrc_content.append(bridges_command[bridges_type.index(bridge)])
        bridge_custom_list = custom_bridges.split('\n')
        for bridge in bridge_custom_list:
            if bridge.strip():
                torrc_content.append('Bridge {0}\n'.format(bridge))

    if bridge_type.startswith('meek'):
        # Required for meek and snowflake only.
        # https://forums.whonix.org/t/censorship-circumvention-tor-pluggable-transports/2601/9
        edit_etc_resolv_conf_add()
    if bridge_type.startswith('snowflake'):
        edit_etc_resolv_conf_add()

    if proxy_type in proxies and proxy_ip and proxy_port:
        torrc_content.append('{0} {1}:{2}\n'.format(proxy_torrc[proxies.index(proxy_type)],
                                                    proxy_ip, proxy_port))
        if proxy_username:
            if proxy_type == proxies[0]:
                torrc_content.append('{0} {1}:{2}\n'.format(proxy_auth[0], proxy_username,
                                                           proxy_password))
            if proxy_type == proxies[2]:
                torrc_content.append('{0} {1}\n'.format(proxy_auth[1], proxy_username))
                if proxy_password:
                    torrc_content.append('{0} {1}\n'.format(proxy_auth[2], proxy_password))

    # Convert the list of strings to a single string
    final_torrc_content = ''.join(torrc_content)

    # Use write_to_temp_then_move to write and move the content
    write_to_temp_then_move(final_torrc_content)

def parse_torrc():
    ## Make sure Torrc exists.
    try:
        call(['leaprun', 'tor-config-sane'])
    except FileNotFoundError:
        pass

    if os.path.exists(torrc_file_path):
        with open(torrc_file_path) as _tf:
            _content = _tf.read()
        use_bridge = 'UseBridges' in _content
        use_proxy = 'Proxy' in _content

        bridge_type = ''
        if use_bridge:
            with open(torrc_file_path, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        #print("parse_torrc: skipping comment line, OK: " + line)
                        continue
                    if line.startswith('ClientTransportPlugin'):
                        bridge_type = bridges_type[bridges_command.index(line)]
                    if meek_address in line:
                        bridge_type = 'meek'
                if bridge_type == '':
                        bridge_type = 'plain'
                bridge_type = bridges_display[bridges_type.index(bridge_type)]
        else:
            bridge_type = 'None'
        print(f"parse_torrc: bridge_type: '{bridge_type}'")

        if use_proxy:
            auth_check = False
            proxy_type = proxy_ip = proxy_port = proxy_username = proxy_password = ''
            with open(torrc_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    parts = line.split()
                    if len(parts) < 2:
                        continue

                    key, value = parts[0], parts[1]

                    if key in proxy_torrc:
                        proxy_type = proxies[proxy_torrc.index(key)]
                        if ':' in value:
                            ip_port = value.split(':', 1)
                            proxy_ip = ip_port[0]
                            proxy_port = ip_port[1] if len(ip_port) > 1 else ''
                        continue

                    if key == proxy_auth[0]:  # HTTPSProxyAuthenticator
                        auth_check = True
                        if ':' in value:
                            user_pass = value.split(':', 1)
                            proxy_username = user_pass[0]
                            proxy_password = user_pass[1] if len(user_pass) > 1 else ''
                        continue

                    if key == proxy_auth[1]:  # Socks5ProxyUsername
                        auth_check = True
                        proxy_username = value
                        continue

                    if key == proxy_auth[2]:  # Socks5ProxyPassword
                        auth_check = True
                        proxy_password = value
                        continue

            if not auth_check:
                proxy_username = ''
                proxy_password = ''
        else:
            proxy_type = 'None'
            proxy_ip = ''
            proxy_port = ''
            proxy_username = ''
            proxy_password = ''

        return (bridge_type, proxy_type, proxy_ip, proxy_port, proxy_username, proxy_password)
