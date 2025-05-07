#!/usr/bin/python3 -su
# -*- coding: utf-8 -*-

## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

import sys
import signal

import os
import re
import time

from PyQt5.QtCore import *
from PyQt5.QtWidgets import QApplication

class TorBootstrap(QThread):
    signal = pyqtSignal(str, int)

    def __init__(self, main):
        super(TorBootstrap, self).__init__(main)

        self.control_cookie_path = '/run/tor/control.authcookie'
        self.control_socket_path = '/run/tor/control'
        self.previous_status = ''
        #self.is_running = False
        '''The TAG to phase mapping is mainly according to:
        https://gitweb.torproject.org/tor-launcher.git/tree/src/chrome/locale/en/torlauncher.properties
        '''
        self.tag_phase = {'starting': 'Starting',
                    'conn': 'Connecting to a relay',
                    'conn_dir': 'Connecting to a relay directory',
                    'conn_done_pt': "Connected to pluggable transport",
                    'handshake_dir': 'Finishing handshake with directory server',
                    'onehop_create': 'Establishing an encrypted directory connection',
                    'requesting_status': 'Retrieving network status',
                    'loading_status': 'Loading network status',
                    'loading_keys': 'Loading authority certificates',
                    'enough_dirinfo': 'Loaded enough directory info to build circuits',
                    'ap_conn': 'Connecting to a relay to build circuits',
                    'ap_conn_done': 'Connected to a relay to build circuits',
                    'ap_conn_done_pt': 'Connected to pluggable transport to build circuits',
                    'ap_handshake': 'Finishing handshake with a relay to build circuits',
                    'ap_handshake_done': 'Handshake finished with a relay to build circuits',
                    'requesting_descriptors': 'Requesting relay information',
                    'loading_descriptors': 'Loading relay information',
                    'conn_or': 'Connecting to the Tor network',
                    'conn_done': "Connected to a relay",
                    'handshake': "Handshaking with a relay",
                    'handshake_or': 'Finishing handshake with first hop',
                    'circuit_create': 'Establishing a Tor circuit',
                    'done': 'Connected to the Tor network!'}

    def connect_to_control_port(self):
        import stem
        import stem.control
        import stem.socket
        from stem.connection import connect

        '''Step 1: Construct a Tor controller'''
        # In case something wrong happened when trying to start Tor,
        # causing /run/tor/control never be generated.
        # We set up a time counter and hardcode the wait time limitation as 10s.

        bootstrap_phase = 'Constructing Tor Controller...'
        bootstrap_percent = 0
        self.signal.emit(bootstrap_phase, bootstrap_percent)

        count=0
        while not os.path.exists(self.control_socket_path) and count < 5:
            count += 0.2
            time.sleep(0.2)

        if not os.access(self.control_socket_path, os.R_OK):
            print(f"[ERROR] Cannot read control socket at {self.control_socket_path} - permission denied.")
            bootstrap_phase = 'socket_error'
            bootstrap_percent = 0
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(10)
            return None

        try:
            tor_controller = stem.control.Controller.from_socket_file(self.control_socket_path)
        except stem.SocketError:
            print('Construct Tor Controller Failed: unable to establish a connection')
            bootstrap_phase = 'no_controller'
            bootstrap_percent = 0
            ## After emitting the `no_controller`,
            ## update_bootstrap() will pop the messagebox and quit
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            ## suspend is really useful because we have to wait for our
            ## emitted signal really reach update_bootstrap()
            time.sleep(10)
            return None

        '''Step 2: Controller Authentication
        In order to interact with Tor, we have to do the authentication.
        '''
        bootstrap_phase = 'Authenticating the Tor Controller...'
        bootstrap_percent = 0
        self.signal.emit(bootstrap_phase, bootstrap_percent)

        try:
            tor_controller.authenticate(self.control_cookie_path)
        except stem.connection.IncorrectCookieSize:
            return None  #if # TODO: the cookie file's size is wrong
        except stem.connection.UnreadableCookieFile:
            # TODO: can we let Tor generate a cookie to fix this situation?
            print('Tor allows for authentication by reading it a cookie file, \
            but we cannot read that file (probably due to permissions)')
            bootstrap_phase = 'cookie_authentication_failed'
            bootstrap_percent = 0
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(10)
            return None
        except stem.connection.CookieAuthRejected:
            return None  #if cookie authentication is attempted but the socket doesn't accept it
        except stem.connection.IncorrectCookieValue:
            return None  #if the cookie file's value is rejected
        except:
            return None

        return tor_controller

    def run(self):
        self.tor_controller = self.connect_to_control_port()
        '''if DisableNetwork is 1, then toggle it to 0
        because we really want Tor connect to the network'''

        if self.tor_controller == None:
            sys.stdout.write('Controller connection failed.\n')
            sys.stdout.flush()
            sys.exit(1)

        if self.tor_controller.get_conf('DisableNetwork') == '1':
            self.tor_controller.set_conf('DisableNetwork', '0')
            sys.stdout.write('Toggle DisableNetwork value to 0. Tor is now allowed to connect to the network.\n')
            sys.stdout.flush()
            sys.exit(1)

        bootstrap_percent = 0
        while bootstrap_percent < 100:
            bootstrap_phase = ''
            bootstrap_status = self.tor_controller.get_info("status/bootstrap-phase")

            if bootstrap_status != self.previous_status:
                bootstrap_percent = int(re.match('.* PROGRESS=([0-9]+).*', bootstrap_status).group(1))
                bootstrap_tag = re.search(r'TAG=(.*) +SUMMARY', bootstrap_status).group(1)
                ''' Use TAG= keyword for bootstrap_phase, according to:
                https://gitweb.torproject.org/tor-launcher.git/plain/README-BOOTSTRAP
                '''
                if bootstrap_tag in self.tag_phase:
                    bootstrap_phase = self.tag_phase[bootstrap_tag]
                else:
                    '''Use a static message to cover unknown bootstrap tag to avoid potential
                    misleading/harmful info shown.'''
                    bootstrap_phase = "Unknown Bootstrap TAG. This is harmless. Please run this program from command line to view console output and report this."
                    sys.stdout.write('Unknown Bootstrap TAG. Full message is shown in the very next line:\n')
                    sys.stdout.flush()
                sys.stdout.write('{0}\n'.format(bootstrap_status))
                sys.stdout.flush()
                self.previous_status = bootstrap_status
                self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(0.2)
        # This will guarantee bootstrap_percent 100 is emitted.
        self.signal.emit(bootstrap_phase, bootstrap_percent)


def main():
    app = QApplication(sys.argv)
    thread = TorBootstrap()
    thread.start()
    app.exec_()
