#!/usr/bin/python3 -u

## Copyright (C) 2018 - 2019 ENCRYPTED SUPPORT LP <adrelanos@riseup.net>
## See the file COPYING for copying conditions.

from PyQt5 import QtCore
from PyQt5.QtWidgets import *

import sys, os
import re
from subprocess import Popen, PIPE
import time

from tor_control_panel import tor_bootstrap, info

class RestartTor(QWidget):
    def __init__(self):
        super().__init__()

        self.text = QLabel(self)
        self.bootstrap_progress = QProgressBar(self)
        self.layout = QGridLayout()

        self.setupUI()

    def setupUI(self):
        self.setGeometry(300, 150, 450, 150)
        self.setWindowTitle('Restart tor')

        self.text.setWordWrap(True)
        self.text.setAlignment(QtCore.Qt.AlignLeft|QtCore.Qt.AlignTop)
        self.text.setMinimumSize(0, 120)

        self.bootstrap_progress.setMinimumSize(400, 0)
        self.bootstrap_progress.setMinimum(0)
        self.bootstrap_progress.setMaximum(100)

        self.layout.addWidget(self.text, 0, 1, 1, 2)
        self.layout.addWidget(self.bootstrap_progress, 1, 1, 1, 1)
        self.setLayout(self.layout)

        self.restart_tor()

    def center(self):
        rectangle = self.frameGeometry()
        center_point = QDesktopWidget().availableGeometry().center()
        rectangle.moveCenter(center_point)
        self.move(rectangle.topLeft())

    def update_bootstrap(self, bootstrap_phase, bootstrap_percent):
        self.bootstrap_progress.show()
        if bootstrap_percent == 100:
            self.bootstrap_progress.setValue(100)
            self.text.setText('<p><b>Tor bootstrapping done</b></p>Bootstrap phase: {0}'.format(bootstrap_phase))
        else:
            self.bootstrap_progress.setValue(bootstrap_percent)
            self.text.setText('<p><b>Bootstrapping Tor...</b></p>Bootstrap phase: {0}'.format(bootstrap_phase))

        if bootstrap_phase == 'no_controller':
            self.text.setText = info.no_controller()

        elif bootstrap_phase == 'cookie_authentication_failed':
            self.text.setText = info.cookie_error()

    def close(self):
        time.sleep(2)
        sys.exit()

    def restart_tor(self):
        '''
        Restart tor.
        Use subprocess.Popen instead of subprocess.call in order to catch
        possible errors from "restart tor" command.
        '''
        command = Popen(['sudo', 'systemctl', 'restart', 'tor@default'], stdout=PIPE, stderr=PIPE)
        stdout, stderr = command.communicate()

        std_err = stderr.decode()
        command_success = std_err == ''

        if not command_success:
            error = QMessageBox(QMessageBox.Critical, 'Restart tor', std_err, QMessageBox.Ok)
            error.exec_()
            self.close()

        self.bootstrap_thread = tor_bootstrap.TorBootstrap(self)
        self.bootstrap_thread.signal.connect(self.update_bootstrap)
        self.bootstrap_thread.finished.connect(self.close)
        self.bootstrap_thread.start()

        self.show()
        self.center()

def main():
    app = QApplication(sys.argv)
    restart_tor = RestartTor()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
