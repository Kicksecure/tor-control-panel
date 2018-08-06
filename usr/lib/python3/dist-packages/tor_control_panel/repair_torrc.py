#!/usr/bin/python3 -u

## Copyright (C) 2018 Patrick Schleizer <adrelanos@riseup.net>
## See the file COPYING for copying conditions.

import fileinput, os, shutil

from . import torrc_gen, info

'''repair_torrc() function will be called when we want to gurantee the existence of:
1. /etc/torrc.d/95_whonix.conf
2. /etc/tor/torrc
3. "%include /etc/torrc.d/95_whonix.conf" line in /etc/tor/torrc file

In addition, we create 40_tor_control_panel.conf
and 50_user.conf here if they do not exist.
'''

whonix = os.path.exists('/usr/share/anon-gw-base-files/gateway')

def repair_torrc():
    repair_torrc_d()

    torrc_path = torrc_gen.torrc_path()
    torrc_user_path = torrc_gen.user_path()
    whonix_torrcd_path = '/etc/torrc.d/95_whonix.conf'

    if not os.path.exists('/etc/tor/torrc'):
        with open('/etc/tor/torrc', "w+") as f:
            if whonix:
                f.write('%include {0}\n'.format(whonix_torrcd_path))
            else:
                f.write('%include {0}\n'.format(torrc_path))
                f.write('%include {0}\n'.format(torrc_user_path))

    else:
        torrcd_line_exists = 'include /etc/torrc.d' in open('/etc/tor/torrc', "r").read()
        if not torrcd_line_exists:
            with open('/etc/tor/torrc', "a") as f:
                if whonix:
                    f.write('%include {0}\n'.format(whonix_torrcd_path))
                else:
                    f.write('%include {0}\n'.format(torrc_path))
                    f.write('%include {0}\n'.format(torrc_user_path))

    if whonix and not os.path.exists(whonix_torrcd_path):
        with open(whonix_torrcd_path, "w+") as f:
            f.write('%include {0}\n'.format(torrc_path))
            f.write('%include {0}\n'.format(torrc_user_path))

    torrc_text = '%s# %s\n' % (info.torrc_text(), torrc_user_path)
    if not whonix:
        torrc_text = (torrc_text +
            'DisableNetwork 0\n' +
            'Log notice file /var/run/tor/log\n')

    user_text = info.user_torrc_text()

    if not os.path.exists(torrc_path):
        with open(torrc_path, "w+") as f:
            f.write(torrc_text)

    if not os.path.exists(torrc_user_path):
        with open(torrc_user_path, "w+") as f:
            f.write(user_text)

'''repair_torrc_d() will guarantee the existence of /etc/torrc.d/
and the existence of /usr/local/etc/torrc.d/ if required.
'''
def repair_torrc_d():
    if not os.path.exists('/etc/torrc.d/'):
        os.makedirs('/etc/torrc.d/')
    if whonix and not os.path.exists('/usr/local/etc/torrc.d/'):
        os.makedirs('/usr/local/etc/torrc.d/')
