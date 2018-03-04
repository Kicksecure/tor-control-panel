#!/usr/bin/python3 -u

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QCursor
from PyQt5.QtWidgets import *

from subprocess import Popen, PIPE
import os, re, time
import glob

from tor_control_panel import tor_status
from tor_control_panel import tor_bootstrap


class TorControlPanel(QDialog):
    def __init__(self):
        super(TorControlPanel, self).__init__()

        self.setMinimumSize(575, 430)
        self.setMaximumSize(575, 430)

        self.refresh_icon = QtGui.QIcon('/usr/share/tor-control-panel/refresh.png')
        self.exit_icon = QtGui.QIcon('/usr/share/tor-control-panel/Exit.png')

        self.restart_icon = QtGui.QIcon('/usr/share/tor-control-panel/restart.png')
        self.stop_icon = QtGui.QIcon('/usr/share/tor-control-panel/stop.png')
        self.tool_icon = QtGui.QIcon('/usr/share/tor-control-panel/tools.png')
        self.stopicon = '/usr/share/tor-control-panel/stop.png'

        self.tor_icon = [
            '/usr/share/icons/oxygen/base/32x32/actions/dialog-ok-apply.png',
            '/usr/share/icons/oxygen/base/32x32/actions/window-close.png',
            '/usr/share/icons/oxygen/base/32x32/actions/window-close.png',
            '/usr/share/icons/oxygen/base/32x32/status/dialog-warning',
            '/usr/share/icons/oxygen/base/32x32/status/dialog-warning',
            '/usr/share/icons/oxygen/base/32x32/actions/window-close.png']

        self.tor_status_color = ['green', '#AF0000', '#AF0000', 'orange',
                                 'orange', '#AF0000']
        self.tor_status_list = ['running', 'stopped', 'disabled',
                                'disabled-running','acquiring','no_controller']

        self. message = ''
        self.tor_message = ['',
            '<b>Tor is not running.</b> <p> \
            If Tor was stopped intentionally, you can restart it from the \
            button [Restart Tor] below, or run in a terminal: \
            <blockquote>sudo service tor@default restart</blockquote> \
            Otherwise you have to fix this error before you can use Tor. <br> \
            Please restart Tor after fixing it. <p> Hints:<br>  \
            In the <b>Logs</b> tab, check the content of torrc  (the default \
            file is /usr/local/etc/torrc.d/40_anon_connection_wizard.conf) and \
            inspect Tor log and systemd journal <br><br>',

            '<b>Tor is disabled</b>. <br><br>A line <i>DisableNetwork 1</i> \
            exists in torrc <br> Therefore you most likely  can not connect to \
            the internet. <p> Run the <b>Connection Wizard</b> to connect to \
            or  configure the Tor network.',

            '<b>Tor is running but is disabled.</b><p> \
            A line <i>DisableNetwork 1</i> exists in torrc <p> \
            Run <b>Anon Connection Wizard</b> \
            to connect to or configure the Tor network.']

        self.tor_path = '/var/run/tor'
        self.tor_running_path = '/var/run/tor/tor.pid'

        self.paths = ['/usr/local/etc/torrc.d/40_anon_connection_wizard.conf',
                      '/var/log/tor/log']

        self.button_name = ['&torrc', 'Tor &log', 'systemd &journal']

        self.journal_command = ['journalctl', '-n', '200', '-u', 'tor@default.service']
        QApplication.setOverrideCursor(Qt.WaitCursor)

        self.bootstrap_done = True

        self.tabs = QTabWidget()
        self.tabs.setMaximumHeight(380)
        self.tabs.setGeometry(10, 10, 410, 380)
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()

        self.button_box = QFrame(self)
        self.refresh_button = QPushButton(self.refresh_icon, ' Refresh', self)
        self.refresh_button.setGeometry(QtCore.QRect(10, 397, 83, 23))
        self.refresh_button.clicked.connect(lambda: self.refresh(True))

        self.quit_button = QPushButton(self.exit_icon, ' Exit', self)
        self.quit_button.setIconSize(QtCore.QSize(20, 20))
        self.quit_button.setGeometry(QtCore.QRect(480, 397, 83, 23))
        self.quit_button.clicked.connect(self.quit)

        self.layout =  QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.tabs)
        self.layout.addWidget(self.button_box)
        self.setLayout(self.layout)

        self.status = QPushButton(self.tab1)
        self.status.setEnabled(False)
        self.status.setGeometry(QtCore.QRect(10, 18, 100, 24))

        self.tor_message_browser = QTextBrowser(self.tab1)
        self.tor_message_browser.setGeometry(QtCore.QRect(112, 20, 425, 148))

        self.bootstrap_progress = QtWidgets.QProgressBar(self.tab1)
        self.bootstrap_progress.setGeometry(120, 45, 410, 15)
        self.bootstrap_progress.setMinimum(0)
        self.bootstrap_progress.setMaximum(100)
        self.bootstrap_progress.setVisible(False)

        self.user_frame = QFrame(self.tab1)
        self.user_frame.setLineWidth(2)
        self.user_frame.setGeometry(10, 190, 530, 152)
        self.user_frame.setFrameShape(QFrame.Panel | QFrame.Raised)

        self.config_frame = QGroupBox(self.user_frame)
        self.config_frame.setGeometry(10, 8, 300, 133)

        self.bridges_label = QLabel(self.config_frame)
        self.bridges_label.setGeometry(10, 33, 90, 20)
        self.bridges_type = QLabel(self.config_frame)
        self.bridges_type.setGeometry(110, 32, 250, 23)
        self.bridges_type.setText('<b>None</b>')

        self.proxy_label = QLabel(self.config_frame)
        self.proxy_label.setGeometry(10, 63, 90, 20)
        self.proxy_type = QLabel(self.config_frame)
        self.proxy_type.setGeometry(110, 62, 250, 23)
        self.proxy_type.setText('<b>None</b>')
        self.proxy_address = QLabel(self.config_frame)
        self.proxy_address.setGeometry(10, 80, 90, 20)
        self.proxy_address.setVisible(False)
        self.proxy_socket = QLabel(self.config_frame)
        self.proxy_socket.setGeometry(110, 80, 250, 20)
        self.proxy_socket.setVisible(False)

        self.control_box = QGroupBox(self.user_frame)
        self.control_box.setGeometry(QtCore.QRect(320, 8, 200, 133))

        self.restart_button = QPushButton(self.restart_icon, '   Restart Tor', self.control_box)
        self.restart_button.setIconSize(QtCore.QSize(28, 28))
        self.restart_button.setFlat(True)
        self.restart_button.setGeometry(QtCore.QRect(15, 28, 115, 32))
        self.restart_button.clicked.connect(self.restart_tor)

        self.stop_button = QPushButton(self.stop_icon, '   Stop Tor', self.control_box)
        self.stop_button.setIconSize(QtCore.QSize(28, 28))
        self.stop_button.setFlat(True)
        self.stop_button.setGeometry(QtCore.QRect(15, 63, 96, 32))
        self.stop_button.clicked.connect(self.stop_tor)

        self.acw_button = QPushButton(self.tool_icon, '   Connection Wizard', self.control_box)
        self.acw_button.setIconSize(QtCore.QSize(28, 28))
        self.acw_button.setFlat(True)
        self.acw_button.setGeometry(QtCore.QRect(13, 98, 160, 25))
        self.acw_button.clicked.connect(self.run_acw)

        self.views_label = QLabel(self.tab2)
        self.views_label.setGeometry(QtCore.QRect(10, 20, 64, 15))

        self.files_box = QGroupBox(self.tab2)
        self.files_box.setGeometry(QtCore.QRect(70, 20, 230, 65))

        self.torrc_button = QRadioButton(self.files_box)
        self.torrc_button.setGeometry(QtCore.QRect(10, 20, 50, 21))
        self.torrc_button.toggled.connect(self.refresh_logs)
        self.radioButton_2 = QRadioButton(self.files_box)
        self.radioButton_2.setGeometry(QtCore.QRect(90, 20, 106, 21))
        self.radioButton_2.toggled.connect(self.refresh_logs)
        self.radioButton_3 = QRadioButton(self.files_box)
        self.radioButton_3.setGeometry(QtCore.QRect(90, 40, 141, 21))
        self.radioButton_3.toggled.connect(self.refresh_logs)

        self.file_browser = QTextBrowser(self.tab2)
        self.file_browser.setGeometry(QtCore.QRect(10, 95, 530, 247))

        self.setup_ui()

    def setup_ui(self):
        self.tabs.addTab(self.tab1,'Status')
        self.tabs.addTab(self.tab2,'Logs')
        self.tabs.addTab(self.tab3,'Utilities')
        self.status.setText('Tor status')
        self.tor_message_browser.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.tor_message_browser.setStyleSheet('background-color:rgba(0, 0, 0, 0)')
        self.config_frame.setTitle('User configuration')
        self.bridges_label.setText('Bridges type :')
        self.proxy_label.setText('Proxy type :')
        self.proxy_address.setText('Proxy socket :')
        self.control_box.setTitle('Control')
        self.views_label.setText('<b>Views</b>')
        self.files_box.setTitle('  File               Logs')
        self.torrc_button.setText('&torrc')
        self.radioButton_2.setText('Tor &log')
        self.radioButton_3.setText('systemd &journal')
        self.torrc_button.setChecked(True)
        self.refresh_button.setFlat(True)

    def update_bootstrap(self, bootstrap_phase, bootstrap_percent):
        self.bootstrap_progress.setVisible(True)
        self.bootstrap_progress.setValue(bootstrap_percent)
        self.bootstrap_done = False
        if bootstrap_percent == 100:
            message = '<p><b>Tor bootstrapping done</b></p>Bootstrap phase: {0}'.format(bootstrap_phase)
            self.message = message.split(':')[1]
            self.bootstrap_progress.setVisible(False)
            self.control_box.setEnabled(True)
            self.refresh(False)
            self.bootstrap_done = True
        else:
            message = '<p><b>Tor bootstrapping done</b></p>Bootstrap phase: {0}'.format(bootstrap_phase)
            self.message = message.split(':')[1]
            self.tor_status = 'acquiring'
            self.refresh_status()

        if bootstrap_phase == 'no_controller':
            self.bootstrap_thread.terminate()
            self.tor_status = 'no_controller'
            self.message = '<b>Tor Controller Not Constructed</b><p>Tor \
            controller cannot be constructed.This is very likely because \
            you have a \"DisableNetwork 1\" line in some torrc file(s).\
            Please manually remove or comment those lines and then run \
            anon-connection-wizard or restart Tor.'
            self.bootstrap_progress.setVisible(False)
            self.control_box.setEnabled(True)
            self.refresh_status()

        elif bootstrap_phase == 'cookie_authentication_failed':
            self.bootstrap_thread.terminate()
            self.message = '<b>Tor Controller Authentication Failed</b> \
            <p>Tor allows for authentication by reading it a cookie file, \
            but we cannot read that file (probably due to permissions)'
            self.bootstrap_progress.setVisible(False)
            #self.stop_thread_button.setVisible(False)
            self.control_box.setEnabled(True)
            self.refresh_status()

    def start_bootstrap(self):
        self.bootstrap_thread = tor_bootstrap.TorBootstrap(self)
        self.bootstrap_thread.signal.connect(self.update_bootstrap)
        self.bootstrap_thread.start()

    def refresh_status(self):
        self.tor_message_browser.setText(self.message)

        ## update [Tor status] color and icon in Logs tab
        color = self.tor_status_color[self.tor_status_list.index(self.tor_status)]
        self.status.setStyleSheet('background-color:%s; color:white; font:bold' % color)
        #image = QtGui.QImage(self.tor_icon[self.tor_status_list.index(self.tor_status)])
        #self.status_icon.setPixmap(QPixmap.fromImage(image))

    def refresh_logs(self):
        for button in self.files_box.findChildren(QRadioButton):
            if button.isChecked():
                if button.text() == 'systemd &journal':
                    p = Popen(self.journal_command, stdout=PIPE, stderr=PIPE)
                    stdout, stderr = p.communicate()
                    text = stdout.decode()
                else:
                    with open(self.paths[self.button_name.index(button.text())]) as f:
                        text = f.read()
                self.file_browser.setText(text)
                self.file_browser.moveCursor(QtGui.QTextCursor.End)

    def refresh_user_configuration(self):
        use_bridge = False
        use_proxy = False
        if 'UseBridges' in open(self.paths[0]).read():
            use_bridge = True
        if 'Proxy' in open(self.paths[0]).read():
            use_proxy = True

        if use_bridge:
            with open(self.paths[0], 'r') as f:
                for line in f:
                    if 'ClientTransportPlugin' in line:
                        self.bridges_type.setText('<b>' + line.split()[1])
        else:
            self.bridges_type.setText('<b>None')

        if use_proxy:
            with open(self.paths[0], 'r') as f:
                for line in f:
                    if 'Proxy' in line:
                        self.proxy_type.setText('<b>' + line.split()[0])
                        self.proxy_socket.setText(line.split()[1])
                        self.proxy_address.setVisible(True)
                        self.proxy_socket.setVisible(True)
        else:
            self.proxy_type.setText('<b>None')
            self.proxy_address.setVisible(False)
            self.proxy_socket.setVisible(False)

    def refresh(self, check_boostrap):
        use_bridge = False
        use_proxy = False

        QApplication.setOverrideCursor(Qt.BusyCursor)
        ## get status
        tor_is_enabled = tor_status.tor_status() == 'tor_enabled'
        tor_is_running = os.path.exists(self.tor_running_path)

        if tor_is_enabled and tor_is_running:
            self.tor_status = 'running'
            ## when refresh is called from update_bootstrap, the thread would be
            ## destroyed while running, crashing the program.
            if check_boostrap:
                self.start_bootstrap()
        else:
            if not tor_is_running:
                self.tor_status =  'stopped'
            if not tor_is_enabled:
                if tor_is_running:
                    self.tor_status =  'disabled-running'
                elif not tor_is_running:
                    self.tor_status =  'disabled'
            self.message = self.tor_message[self.tor_status_list.index(self.tor_status)]

        self.refresh_status()
        self.refresh_logs()
        self.refresh_user_configuration()

    def restart_tor(self):
        self.control_box.setEnabled(False)
        ## if running restart tor directly stem returns
        ## bootstrap_percent 100 or  a socket error, randomly.
        self.stop_tor()

        restart_command = 'sudo systemctl restart tor@default'
        p = Popen(restart_command, shell=True)
        self.start_bootstrap()

    def stop_tor(self):
        if not self.bootstrap_done:
            self.bootstrap_progress.setVisible(False)
            self.bootstrap_thread.terminate()
        stop_command = 'sudo systemctl stop tor@default'
        p = Popen(stop_command, shell=True)
        p.wait()
        self.refresh(True)

    def run_acw(self):
        if not self.bootstrap_done:
            self.bootstrap_thread.terminate()
        acw_command = 'sudo anon-connection-wizard'
        p = Popen(acw_command, shell=True)
        p.wait()
        self.refresh(True)

    def quit(self):
        if not self.bootstrap_done:
            self.bootstrap_thread.terminate()
        self.accept()


def main():
    import sys
    app = QApplication(sys.argv)
    tor_controller = TorControlPanel()
    tor_controller.show()
    tor_controller.refresh(True)
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
