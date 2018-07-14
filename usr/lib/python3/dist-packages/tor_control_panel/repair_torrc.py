#!/usr/bin/python3 -u

import fileinput, os, shutil

'''repair_torrc() function will be called when we want to gurantee the existence of:
1. /etc/torrc.d/95_whonix.conf
2. /etc/tor/torrc
3. "%include /etc/torrc.d/95_whonix.conf" line in /etc/tor/torrc file
'''

if os.path.exists('/usr/share/anon-gw-base-files/gateway'):
    whonix=True
else:
    whonix=False

def repair_torrc():
    repair_torrc_d()

    if not os.path.exists('/etc/torrc.d/95_whonix.conf'):
        with open('/etc/torrc.d/95_whonix.conf', "w+") as f:
            f.write("%include /usr/local/etc/torrc.d/40_anon_connection_wizard.conf")
            f.write('\n')
            f.write("%include /usr/local/etc/torrc.d/50_user.conf")
            f.write('\n')

    if not os.path.exists('/etc/tor/torrc'):
        with open('/etc/tor/torrc', "w+") as f:
            f.write("%include /etc/torrc.d/95_whonix.conf")
            f.write('\n')
    else:
        with open('/etc/tor/torrc', "r") as f:
            lines = f.readlines()
            f.close()

        torrcd_line_exists = False
        for line in lines:
            str = line.strip()
            if (str == '%include /etc/torrc.d/95_whonix.conf'):
                torrcd_line_exists = True

        if not torrcd_line_exists:
            with open('/etc/tor/torrc', "a") as f:
                f.write("%include /etc/torrc.d/95_whonix.conf\n")
                f.write('\n')


'''repair_torrc_d() will gurantee the existence of /etc/torrc.d/
and if anon-connection-wizard is in Whonix,
then also gurantee the existence of /usr/local/etc/torrc.d/
'''
def repair_torrc_d():
    if not os.path.exists('/etc/torrc.d/'):
        os.makedirs('/etc/torrc.d/')
    if whonix and not os.path.exists('/usr/local/etc/torrc.d/'):
        os.makedirs('/usr/local/etc/torrc.d/')
