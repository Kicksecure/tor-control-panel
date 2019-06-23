#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

## Copyright (C) 2018 - 2019 ENCRYPTED SUPPORT LP <adrelanos@riseup.net>
## See the file COPYING for copying conditions.

import os, re, sys, time
from PyQt5.QtCore import *


class TorBootstrap(QThread):
    '''signal will receive the emit from TorBootstrap with two values:
    bootstrap_phase and bootstrap_percent.
    It will pass them to the update_bootstrap()
    '''
    signal = pyqtSignal(str, int)

    def __init__(self, main):
        super(TorBootstrap, self).__init__(main)

        self.control_cookie_path = '/var/run/tor/control.authcookie'
        self.control_socket_path = '/var/run/tor/control'
        self.previous_status = ''
        bootstrap_percent = 0
        #self.is_running = False
        '''The TAG to phase mapping is mainly according to:
        https://gitweb.torproject.org/tor-launcher.git/tree/src/chrome/locale/en/torlauncher.properties
        '''
        self.tag_phase = {'starting': 'Starting',
                    'conn_dir': 'Connecting to a relay directory...',
                    'handshake_dir': 'Finishing handshake with directory server...',
                    'onehop_create': 'Establishing an encrypted directory connection...',
                    'requesting_status': 'Retrieving network status...',
                    'loading_status': 'Loading network status...',
                    'loading_keys': 'Loading authority certificates...',
                    'requesting_descriptors': 'Requesting relay information...',
                    'loading_descriptors': 'Loading relay information...',
                    'conn_or': 'Connecting to the Tor network...',
                    'handshake_or': 'Finishing handshake with first hop...',
                    'circuit_create': 'Establishing a Tor circuit...',
                    'done': 'Connected to the Tor network.'}

    def connect_to_control_port(self):
        import stem
        import stem.control
        import stem.socket
        from stem.connection import connect

        '''Step 1: Construct a Tor controller'''
        # In case something wrong happened when trying to start Tor,
        # causing /run/tor/control never be generated.
        # We set up a time counter and hardcode the wait time limitation as 10s.

        bootstrap_phase =  'Constructing Tor Controller...'
        bootstrap_percent = 0
        self.signal.emit(bootstrap_phase, bootstrap_percent)

        count=0
        while not os.path.exists(self.control_socket_path) and count < 5:
            count += 0.2
            time.sleep(0.2)

        try:
            tor_controller = stem.control.Controller.from_socket_file(self.control_socket_path)
        except stem.SocketError:
            print('Construct Tor Controller Failed: unable to establish a connection')
            bootstrap_phase =  'no_controller'
            bootstrap_percent = 0
            ## After emiting the `no_controller`,
            ## update_bootstrap() will pop the messagebox and quit
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            ## suspend is really useful because we have to wait for our
            ## emited siganl really reach update_bootstrap()
            time.sleep(10)

        '''Step 2: Controller Authentication
        In order to interact with Tor, we have to do the authentication.
        '''
        bootstrap_phase =  'Authenticating the Tor Controller...'
        bootstrap_percent = 0
        self.signal.emit(bootstrap_phase, bootstrap_percent)

        try:
            tor_controller.authenticate(self.control_cookie_path)
        except stem.connection.IncorrectCookieSize:
            pass  #if # TODO: the cookie file's size is wrong
        except stem.connection.UnreadableCookieFile:
            # TODO: can we let Tor generate a cookie to fix this situation?
            print('Tor allows for authentication by reading it a cookie file, \
            but we cannot read that file (probably due to permissions)')
            bootstrap_phase =  'cookie_authentication_failed'
            bootstrap_percent = 0
            self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(10)
        except stem.connection.CookieAuthRejected:
            pass  #if cookie authentication is attempted but the socket doesn't accept it
        except stem.connection.IncorrectCookieValue:
            pass  #if the cookie file's value is rejected

        return tor_controller

    def run(self):
        self.tor_controller = self.connect_to_control_port()
        '''if DisableNetwork is 1, then toggle it to 0
        because we really want Tor connect to the network'''
        if self.tor_controller.get_conf('DisableNetwork') is '1':
            self.tor_controller.set_conf('DisableNetwork', '0')
            sys.stdout.write('Toggle DisableNetwork value to 0. Tor is now allowed to connect to the network.\n')
            sys.stdout.flush()

        bootstrap_percent = 0
        while bootstrap_percent < 100:
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
                    bootstrap_phase = "Unknown Bootstrap TAG. In most cases this is harmless. Please report this."
                    sys.stdout.write('Unknown Bootstrap TAG. Full message is shown in the very next line:\n')
                    sys.stdout.flush()
                sys.stdout.write('{0}\n'.format(bootstrap_status))
                sys.stdout.flush()
                self.previous_status = bootstrap_status
                self.signal.emit(bootstrap_phase, bootstrap_percent)
            time.sleep(0.2)
        # This will guarantee bootstrap_percent 100 is emited.
        self.signal.emit(bootstrap_phase, bootstrap_percent)


def main():
    thread = TorBootstrap()
    sys.exit(app.exec_())

