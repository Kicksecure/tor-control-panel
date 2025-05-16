#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
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

torrc_file_path = '/usr/local/etc/torrc.d/40_tor_control_panel.conf'
torrc_user_file_path = '/usr/local/etc/torrc.d/50_user.conf'

bridges_default_path = '/usr/share/anon-connection-wizard/bridges_default'

command_useBridges = 'UseBridges 1\n'
command_use_custom_bridge = '# Custom Bridge is used:'

bridges_command = [ 'ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n',

                    'ClientTransportPlugin snowflake exec /usr/bin/snowflake-client\n',

                    'ClientTransportPlugin meek_lite exec /usr/bin/obfs4proxy\n',
                    'ClientTransportPlugin scramblesuit exec /usr/bin/obfs4proxy\n',
                    'ClientTransportPlugin fte exec /usr/bin/fteproxy --managed\n']

bridges_type = ['obfs4', 'snowflake', 'meek-azure', 'scramblesuit', 'fte', 'plain']

bridges_display = ['obfs4', 'snowflake',
                   'meek-azure', 'plain']

meek_azure_address = 'ajax.aspnetcdn.com\n'

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
        bridges = json.loads(open(bridges_default_path).read())
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

    if bridge_type.startswith('meek-azure'):
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
    command = 'leaprun tor-config-sane'
    call(command, shell=True)

    if os.path.exists(torrc_file_path):
        use_bridge = 'UseBridges' in open(torrc_file_path).read()
        use_proxy = 'Proxy' in open(torrc_file_path).read()

        bridge_type = ''
        if use_bridge:
            with open(torrc_file_path, 'r') as f:
                for line in f:
                    if line.startswith('#'):
                        #print("parse_torrc: skipping comment line, OK: " + line)
                        continue
                    if line.startswith('ClientTransportPlugin'):
                        bridge_type = bridges_type[bridges_command.index(line)]
                    if line.endswith(meek_azure_address):
                        bridge_type = 'meek-azure'
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
