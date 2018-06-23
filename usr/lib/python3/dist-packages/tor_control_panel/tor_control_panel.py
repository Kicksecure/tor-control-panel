#!/usr/bin/python3 -u

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import *

from subprocess import call, Popen, PIPE
import os, re, time
import glob

from . import tor_status, tor_bootstrap, torrc_gen, info


class TorControlPanel(QDialog):
    def __init__(self):
        super(TorControlPanel, self).__init__()

        self.setMinimumSize(650, 465)
        #self.setMaximumHeight(450)

        icons_path = '/usr/share/tor-control-panel/'
        self.refresh_icon = QtGui.QIcon(icons_path + 'refresh.png')
        self.exit_icon = QtGui.QIcon(icons_path + 'Exit.png')

        self.restart_icon = QtGui.QIcon(icons_path + 'restart.png')
        self.stop_icon = QtGui.QIcon(icons_path + 'stop.png')
        self.tool_icon = QtGui.QIcon(icons_path + 'tools.png')
        self.info_icon = QtGui.QIcon(icons_path + 'help.png')
        self.back_icon = QtGui.QIcon(icons_path + 'prev.png')
        self.accept_icon = QtGui.QIcon(icons_path + 'accept_icon.png')
        self.onions_icon = QtGui.QIcon(icons_path + 'onion.png')
        self.newid_icon = QtGui.QIcon(icons_path + 'silhouette2.png')

        self.tor_status_color = ['green', '#AF0000', '#AF0000', 'orange',
                                 'orange', '#AF0000']
        self.tor_status_list = ['running', 'stopped', 'disabled',
                                'disabled-running','acquiring','no_controller']

        self. message = ''
        self.tor_message = info.tor_stopped()
        self.tor_path = '/var/run/tor'
        self.tor_running_path = '/var/run/tor/tor.pid'

        self.paths = ['/usr/local/etc/torrc.d/40_anon_connection_wizard.conf',
                      #'/var/log/tor/log']
                      '/home/user/tmp']

        self.button_name = ['systemd &journal', 'Tor &log', '&torrc']

        self.journal_command = ['journalctl', '-n', '200', '-u',
                                'tor@default.service']

        self.bridges = ['None',
                        'obfs4 (recommended)',
                        'obfs3',
                        'snowflake',
                        #'meek-amazon (works in China)',
                        'meek-azure (works in China)',
                        'Custom bridges']

        self.proxies = ['None',
                        'HTTP/HTTPS',
                        'SOCKS4',
                        'SOCKS5']

        self.tor_log = '/var/run/tor/log'
        self.tor_log_html = '/home/user/tmp'
        ## tor log HTML style
        self.warn_style = '<span style="background-color:yellow">{}'\
                        .format('[warn]')
        self.error_style = '<span style="background-color:red">{}'\
                        .format('[error]')

        self.bootstrap_done = True

        self.tabs = QTabWidget()
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tab3 = QWidget()

        self.button_layout = QHBoxLayout()
        self.quit_button = QPushButton(self.exit_icon, ' Exit')
        self.quit_button.clicked.connect(self.quit)

        self.button_layout.addWidget(self.quit_button)
        self.button_layout.setAlignment(Qt.AlignRight)

        self.layout =  QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.tabs)
        self.layout.addLayout(self.button_layout)
        self.setLayout(self.layout)

        self.control_layout = QVBoxLayout(self.tab1)
        self.info_frame = QFrame()
        self.frame_layout = QGridLayout(self.info_frame)
        self.frame_layout.setVerticalSpacing(2)
        self.frame_layout.setAlignment(Qt.AlignTop)

        self.status = QPushButton()
        self.status.setEnabled(False)
        self.frame_layout.addWidget(self.status, 1, 0, 1, 1)
        self.tor_message_browser = QTextBrowser()
        self.frame_layout.addWidget(self.tor_message_browser, 1, 1, 2, 1)
        self.bootstrap_progress = QtWidgets.QProgressBar()
        self.frame_layout.addWidget(self.bootstrap_progress, 2, 1, 1, 1)

        self.user_frame = QFrame()
        self.user_layout = QHBoxLayout(self.user_frame)
        self.config_frame = QGroupBox()

        self.bridges_label = QLabel(self.config_frame)
        self.bridges_type = QLabel(self.config_frame)
        self.bridges_combo = QComboBox(self.config_frame)
        for bridge in self.bridges:
            self.bridges_combo.addItem(bridge)
        self.bridges_combo.insertSeparator(1)
        self.bridges_combo.insertSeparator(7)
        self.bridges_combo.addItem('Disable Tor')
        self.bridge_info_button = QPushButton(self.info_icon, '',
                                              self.config_frame)
        self.bridge_info_button.clicked.connect(info.show_help_censorship)
        self.bridge_info_label = QLabel()

        self.proxy_label = QLabel(self.config_frame)
        self.proxy_type = QLabel(self.config_frame)
        self.proxy_combo = QComboBox(self.config_frame)
        for proxy in self.proxies:
            self.proxy_combo.addItem(proxy)
        self.proxy_combo.insertSeparator(1)
        self.proxy_combo.currentIndexChanged.connect(
            lambda: self.proxy_settings_show(self.proxy_combo.currentText()))

        self.proxy_info_button = QPushButton(self.info_icon, '',
                                             self.config_frame)
        self.proxy_info_button.clicked.connect(info.show_proxy_help)

        self.prev_button = QPushButton(self.back_icon, '',self.config_frame)
        self.prev_button.clicked.connect(self.exit_configuration)

        self.proxy_ip_label = QLabel(self.config_frame)
        self.proxy_ip_edit = QLineEdit(self.config_frame)
        self.proxy_port_label = QLabel(self.config_frame)
        self.proxy_port_edit = QLineEdit(self.config_frame)

        self.proxy_user_label = QLabel(self.config_frame)
        self.proxy_user_edit = QLineEdit(self.config_frame)
        self.proxy_pwd_label = QLabel(self.config_frame)
        self.proxy_pwd_edit = QLineEdit(self.config_frame)

        self.user_layout.addWidget(self.config_frame)

        self.control_box = QGroupBox()
        self.restart_button = QPushButton(self.restart_icon, ' Restart Tor',
                                          self.control_box)
        self.restart_button.clicked.connect(self.restart_tor)
        self.stop_button = QPushButton(self.stop_icon, ' Stop Tor',
                                       self.control_box)
        self.stop_button.clicked.connect(self.stop_tor)
        self.configure_button = QPushButton(self.tool_icon, ' Configure',
                                            self.control_box)
        self.configure_button.clicked.connect(self.configure)

        self.user_layout.addWidget(self.control_box)

        self.control_layout.addWidget(self.info_frame)
        self.control_layout.addWidget(self.user_frame)

        self.log_layout = QVBoxLayout(self.tab2)
        self.view_layout = QHBoxLayout()
        self.view_layout.setAlignment(Qt.AlignBottom)
        self.log_layout.addLayout(self.view_layout)

        self.view_frame = QFrame()
        self.view_frame.setMinimumHeight(70)
        self.files_box = QGroupBox(self.view_frame)
        self.refresh_button = QPushButton(self.refresh_icon, ' Refresh')
        self.refresh_button.clicked.connect(lambda: self.refresh(False))
        self.view_layout.setAlignment(Qt.AlignTop)
        self.view_layout.addWidget(self.view_frame)
        self.view_layout.addWidget(self.refresh_button)

        self.torrc_button = QRadioButton(self.files_box)
        self.torrc_button.toggled.connect(self.refresh_logs)
        self.log_button = QRadioButton(self.files_box)
        self.log_button.toggled.connect(self.refresh_logs)
        self.journal_button = QRadioButton(self.files_box)
        self.journal_button.toggled.connect(self.refresh_logs)

        self.file_browser = QTextBrowser()
        self.file_browser.setLineWrapMode(QTextBrowser.NoWrap)
        self.log_layout.addWidget(self.file_browser)

        self.custom_bridges_frame = QFrame(self.tab1)
        self.custom_bridges_help = QLabel(self.custom_bridges_frame)
        self.custom_bridges = QtWidgets.QTextEdit(self.custom_bridges_frame)

        self.custom_cancel_button = QPushButton(QtGui.QIcon(
            self.back_icon), 'Cancel', self .custom_bridges_frame)
        self.custom_cancel_button.clicked.connect(self.hide_custom_bridges)
        self.custom_accept_button = QPushButton(QtGui.QIcon(
            self.accept_icon), 'Accept', self .custom_bridges_frame)
        self.custom_accept_button.clicked.connect(self.accept_custom_bridges)

        self.utils_layout = QtWidgets.QVBoxLayout(self.tab3)

        self.onioncircuits_box = QFrame()
        self.onions_layout = QVBoxLayout(self.onioncircuits_box)
        self.onioncircuits_button = QPushButton(self.onions_icon,
                                                ' Onion &Circuits')
        self.onioncircuits_button.clicked.connect(self.onioncircuits)
        self.onions_label = QLabel()
        self.onions_layout.addWidget(self.onioncircuits_button)
        self.onions_layout.addWidget(self.onions_label)

        self.newnym_box = QFrame()
        self.newnym_layout = QVBoxLayout(self.newnym_box)
        self.newnym_button = QPushButton(self.newid_icon, ' New &Identity  ')
        self.newnym_button.clicked.connect(self.newnym)
        self.newnym_label = QLabel()
        self.newnym_layout.addWidget(self.newnym_button)
        self.newnym_layout.addWidget(self.newnym_label)

        self.dummy1 = QFrame()
        self.dummy2 = QFrame()

        self.utils_layout.addWidget(self.onioncircuits_box)
        self.utils_layout.addWidget(self.newnym_box)
        self.utils_layout.addWidget(self.dummy1)
        self.utils_layout.addWidget(self.dummy2)

        self.newnym_box.setFrameShape(QFrame.Panel | QFrame.Raised)
        self.onioncircuits_box.setFrameShape(QFrame.Panel | QFrame.Raised)

        self.setup_ui()

    def setup_ui(self):
        self.tabs.addTab(self.tab1,'Control')
        self.tabs.addTab(self.tab3,'Utilities')
        self.tabs.addTab(self.tab2,'Logs')

        self.quit_button.setIconSize(QtCore.QSize(20, 20))
        self.quit_button.setMaximumWidth(70)

        self.status.setText('Tor status')

        self.tor_message_browser.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.tor_message_browser.setStyleSheet('background-color:rgba(0, 0, 0, 0)')

        self.bootstrap_progress.setMinimum(0)
        self.bootstrap_progress.setMaximum(100)
        self.bootstrap_progress.hide()

        self.user_frame.setLineWidth(2)
        self.user_frame.setMaximumHeight(160)
        self.user_frame.setMinimumHeight(160)
        self.user_frame.setFrameShape(QFrame.Panel | QFrame.Raised)

        self.config_frame.setTitle('User configuration')

        self.bridges_label.setGeometry(10, 26, 90, 20)
        self.bridges_label.setText('Bridges type :')
        self.bridges_type.setGeometry(100, 26, 250, 20)
        self.bridges_type.setStyleSheet('font:bold')
        self.bridges_combo.setGeometry(100, 26, 250, 20)
        self.bridges_combo.setMaximumWidth(220)
        self.bridges_combo.hide()
        self.bridge_info_button.setGeometry(380, 26, 20, 20)
        self.bridge_info_button.setFlat(True)
        self.bridge_info_button.hide()
        self.bridge_info_button.setToolTip('Show bridges help')
        self.bridge_info_label.setMinimumSize(575, 400)
        self.bridge_info_label.setWordWrap(True)
        self.bridge_info_label.setText

        self.proxy_label.setText('Proxy type :')
        self.proxy_label.setGeometry(10, 53, 90, 20)
        self.proxy_type.setGeometry(100, 53, 250, 20)
        self.proxy_type.setStyleSheet('font:bold')
        self.proxy_combo.setGeometry(100, 53, 250, 20)
        self.proxy_combo.setMaximumWidth(220)
        self.proxy_combo.hide()

        self.proxy_ip_label.setText('Address:')
        self.proxy_ip_label.setGeometry(10, 80, 60, 20)
        self.proxy_ip_label.hide()
        self.proxy_ip_edit.setGeometry(70, 80, 120, 20)
        self.proxy_ip_edit.setPlaceholderText('ex : 127.0.0.1')
        self.proxy_ip_edit.hide()
        self.proxy_ip_edit.setEnabled(False)

        self.proxy_port_label.setText('Port:')
        self.proxy_port_label.setGeometry(210, 80, 250, 20)
        self.proxy_port_label.hide()
        self.proxy_port_edit.setGeometry(245, 80, 75, 20)
        self.proxy_port_edit.setPlaceholderText('1-65535')
        self.proxy_port_edit.hide()
        self.proxy_port_edit.setEnabled(False)

        self.proxy_user_label.setText('User: ')
        self.proxy_user_label.setGeometry(10, 105, 90, 20)
        self.proxy_user_label.hide()
        self.proxy_user_edit.setGeometry(48, 105, 90, 20)
        self.proxy_user_edit.setPlaceholderText('Optional')
        self.proxy_user_edit.hide()
        self.proxy_user_edit.setEnabled(False)

        self.proxy_pwd_label.setText('Password: ')
        self.proxy_pwd_label.setGeometry(150, 105, 60, 20)
        self.proxy_pwd_label.hide()
        self.proxy_pwd_edit.setGeometry(218, 105, 102, 20)
        self.proxy_pwd_edit.setPlaceholderText('Optional')
        self.proxy_pwd_edit.hide()
        self.proxy_pwd_edit.setEnabled(False)

        self.proxy_info_button.setGeometry(380, 53, 20, 20)
        self.proxy_info_button.setFlat(True)
        self.proxy_info_button.hide()
        self.proxy_info_button.setToolTip('Show proxies help')

        self.prev_button.setGeometry(380, 105, 20,20)
        self.prev_button.setFlat(True)
        self.prev_button.hide()
        self.prev_button.setToolTip('Quit configuration')

        self.control_box.setGeometry(0, 140, 0, 160)
        self.control_box.setMaximumWidth(140)
        self.control_box.setTitle('Control')
        self.restart_button.setIconSize(QtCore.QSize(28, 28))
        self.restart_button.setFlat(True)
        self.restart_button.setGeometry(QtCore.QRect(10, 28, 113, 32))
        self.stop_button.setIconSize(QtCore.QSize(28, 28))
        self.stop_button.setFlat(True)
        self.stop_button.setGeometry(QtCore.QRect(10, 63, 96, 32))
        self.configure_button.setIconSize(QtCore.QSize(28, 28))
        self.configure_button.setFlat(True)
        self.configure_button.setGeometry(QtCore.QRect(10, 98, 102, 32))
        self.configure_button.setDefault(True)

        self.custom_bridges_frame.setGeometry(10, 10, 530, 332)
        self.custom_bridges_frame.setLineWidth(2)
        self.custom_bridges_frame.setFrameShape(QFrame.Panel |
                                                QFrame.Raised)
        self.custom_bridges_frame.hide()
        self.custom_cancel_button.setGeometry(380, 300, 65, 25)
        self.custom_cancel_button.setFlat(True)
        self.custom_accept_button.setGeometry(455, 300, 65 ,25)
        self.custom_accept_button.setFlat(True)
        self.custom_bridges_help.setGeometry(10, 10, 510, 175)
        self.custom_bridges_help.setWordWrap(True)
        self.custom_bridges_help.setTextInteractionFlags(
            Qt.TextSelectableByMouse)
        self.custom_bridges_help.setText(info.custom_bridges_help())
        self.custom_bridges.setGeometry(10, 190, 510, 105)

        self.newnym_box.setMaximumHeight(130)
        self.newnym_button.setMaximumWidth(120)
        self.newnym_button.setIconSize(QtCore.QSize(20, 20))
        self.newnym_label.setWordWrap(True)
        self.newnym_label.setTextFormat(Qt.RichText)
        self.newnym_label.setText(info.newnym_text())

        self.onioncircuits_box.setMaximumHeight(80)
        self.onioncircuits_button.setMaximumWidth(120)
        self.onioncircuits_button.setIconSize(QtCore.QSize(20, 20))
        self.onions_label.setWordWrap(True)
        self.onions_label.setText(info.onions_text())

        self.files_box.setGeometry(QtCore.QRect(0, 0, 230, 65))
        self.files_box.setTitle('  Files             Logs')
        self.torrc_button.setGeometry(QtCore.QRect(10, 20, 50, 21))
        self.torrc_button.setText('&torrc')
        self.log_button.setGeometry(QtCore.QRect(90, 20, 106, 21))
        self.log_button.setText('Tor &log')
        self.journal_button.setGeometry(QtCore.QRect(90, 40, 141, 21))
        self.journal_button.setText('systemd &journal')
        self.log_button.setChecked(True)

        self.refresh_button.setMaximumWidth(70)
        self.refresh_button.setFlat(True)

    def newnym(self):
        from stem import Signal
        from stem.control import Controller
        with Controller.from_socket_file('/var/run/tor/control') as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)

    def onioncircuits(self):
        command = '/usr/bin/onioncircuits &'
        call(command, shell=True)

    def update_bootstrap(self, bootstrap_phase, bootstrap_percent):
        self.bootstrap_progress.show()
        self.bootstrap_progress.setValue(bootstrap_percent)
        self.bootstrap_done = False
        if bootstrap_percent == 100:
            self.message = bootstrap_phase
            self.bootstrap_progress.hide()
            self.restart_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.refresh(False)
            self.bootstrap_done = True
        else:
            self.message = bootstrap_phase
            self.tor_status = 'acquiring'
            self.refresh_status()

        if bootstrap_phase == 'no_controller':
            self.bootstrap_thread.terminate()
            self.tor_status = 'no_controller'
            self.message = info.no_controller()
            self.bootstrap_progress.hide()
            self.restart_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.refresh_status()

        elif bootstrap_phase == 'cookie_authentication_failed':
            self.bootstrap_thread.terminate()
            self.message = info.cookie_error()
            self.bootstrap_progress.hide()
            self.control_box.setEnabled(True)
            self.refresh_status()

    def start_bootstrap(self):
        self.bootstrap_thread = tor_bootstrap.TorBootstrap(self)
        self.bootstrap_thread.signal.connect(self.update_bootstrap)
        self.bootstrap_thread.start()

    def hide_custom_bridges(self):
        self.status.show()
        self.tor_message_browser.show()
        self.user_frame.show()
        self.custom_bridges_frame.hide()
        self.exit_configuration()

    def accept_custom_bridges(self):
        args = []
        args.append(self.bridges_combo.currentText())
        if not str(self.custom_bridges.toPlainText()) == '':
            args.append(str(self.custom_bridges.toPlainText()))
        else:
            return()
        proxy = self.proxy_combo.currentText()
        args.append(proxy)
        if not proxy == None:
            if self.check_proxy_ip(self.proxy_ip_edit.text()) and \
                self.check_proxy_port(self.proxy_port_edit.text()):
                args.append(proxy)
                args.append(self.proxy_ip_edit.text())
                args.append(self.proxy_port_edit.text())
                args.append(self.proxy_user_edit.text())
                args.append(self.proxy_pwd_edit.text())
        torrc_gen.gen_torrc(args)
        self.restart_tor()
        self.hide_custom_bridges()

    def check_proxy_ip(self, address):
        import socket
        try:
            sock = socket.gethostbyname(address)
            return(True)
        except:
            return(False)

    def check_proxy_port(self, port):
        r = range(1, 65535)
        try:
            return(int(port) in r)
        except ValueError:  # not a integer
            return(False)

    def proxy_settings_show(self, proxy):
        if proxy == 'None':
            self.proxy_ip_label.hide()
            self.proxy_ip_edit.hide()
            self.proxy_port_label.hide()
            self.proxy_port_edit.hide()
            self.proxy_user_label.hide()
            self.proxy_user_edit.hide()
            self.proxy_pwd_label.hide()
            self.proxy_pwd_edit.hide()
        elif not proxy == 'None':
            self.proxy_ip_label.show()
            self.proxy_ip_edit.show()
            self.proxy_port_label.show()
            self.proxy_port_edit.show()
            self.proxy_user_label.show()
            self.proxy_user_edit.show()
            self.proxy_pwd_label.show()
            self.proxy_pwd_edit.show()
            enable_auth = not proxy == 'SOCKS4' and 'Accept' in \
                self.configure_button.text()
            self.proxy_user_label.setEnabled(enable_auth)
            self.proxy_user_edit.setEnabled(enable_auth)
            self.proxy_pwd_label.setEnabled(enable_auth)
            self.proxy_pwd_edit.setEnabled(enable_auth)

    def configure(self):
        if 'Configure' in self.configure_button.text():
            self.configure_button.setText(' Accept    ')
            self.configure_button.setIcon(self.accept_icon)
            self.restart_button.setEnabled(False)
            self.stop_button.setEnabled(False)
            self.bridges_combo.show()
            self.proxy_combo.show()
            self.proxy_ip_edit.setEnabled(True)
            self.proxy_port_edit.setEnabled(True)
            self.proxy_user_edit.setEnabled(True)
            self.proxy_pwd_edit.setEnabled(True)
            self.proxy_settings_show(self.proxy_combo.currentText())
            self.bridge_info_button.show()
            self.proxy_info_button.show()
            self.prev_button.show()

            bridge = self.bridges_type.text()
            index = self.bridges_combo.findText(bridge,
                                                QtCore.Qt.MatchFixedString)
            self.bridges_combo.setCurrentIndex(index)
            proxy = self.proxy_type.text()
            index = self.proxy_combo.findText(proxy, QtCore.Qt.MatchFixedString)
            self.proxy_combo.setCurrentIndex(index)
            self.proxy_settings_show(proxy)

        elif 'Accept' in self.configure_button.text():
            print(self.proxy_ip_edit.text())
            if self.bridges_combo.currentText() == 'Custom bridges':
                self.status.hide()
                self.tor_message_browser.hide()
                self.user_frame.hide()
                self.custom_bridges_frame.show()
            else:
                args = []
                args.append(self.bridges_combo.currentText().split()[0])
                args.append('')  # custom bridges argument
                proxy = self.proxy_combo.currentText()
                if not proxy == 'None':
                    if self.check_proxy_ip(str(self.proxy_ip_edit.text())) and\
                        self.check_proxy_port(self.proxy_port_edit.text()):
                        args.append(proxy)
                        args.append(self.proxy_ip_edit.text())
                        args.append(self.proxy_port_edit.text())
                        if not self.proxy_user_edit.text() == None:
                            args.append(self.proxy_user_edit.text())
                        else:
                            args.append('')
                        if not self.proxy_pwd_edit.text() == None:
                            args.append(self.proxy_pwd_edit.text())
                        else:
                            args.append('')
                    else:
                        self.reply = QMessageBox(QMessageBox.NoIcon, 'Warning',
                                                info.invalid_ip_port(),
                                                QtWidgets.QMessageBox.Ok)
                        self.reply.exec_()
                        return()

                args.append(proxy)
                torrc_gen.gen_torrc(args)
                self.restart_tor()
                self.exit_configuration()

    def exit_configuration(self):
        self.configure_button.setText(' Configure')
        self.configure_button.setIcon(self.tool_icon)
        self.prev_button.hide()
        self.restart_button.setEnabled(True)
        self.stop_button.setEnabled(True)
        self.bridges_combo.hide()
        self.proxy_combo.hide()
        self.bridge_info_button.hide()
        self.proxy_info_button.hide()
        self.proxy_settings_show(self.proxy_type.text())
        self.proxy_ip_edit.setEnabled(False)
        self.proxy_port_edit.setEnabled(False)
        self.proxy_user_edit.setEnabled(False)
        self.proxy_pwd_edit.setEnabled(False)

    def refresh_status(self):
        self.tor_message_browser.setText(self.message)
        color = self.tor_status_color[self.tor_status_list.index(
            self.tor_status)]
        self.status.setStyleSheet('background-color:%s; color:white; \
                                  font:bold' % color)

    def refresh_logs(self):
        for button in self.files_box.findChildren(QRadioButton):
            if button.isChecked():
                if button.text() == self.button_name[0]:
                    p = Popen(self.journal_command, stdout=PIPE, stderr=PIPE)
                    stdout, stderr = p.communicate()
                    text = stdout.decode()

                elif button.text() == self.button_name[1]:
                    # Copy Tor log to a new file, HTML format for highlighting
                    # warnings and errors, use the new file in text browser.
                    with open(self.tor_log, 'r') as fr:
                        with open(self.tor_log_html, 'w') as fw:
                            for line in fr:
                                line = re.sub(line[12:19], '...', line)
                                line = line.replace('[warn]', self.warn_style)
                                line = line.replace('[error]', self.error_style)
                                if '[warn]' in line or '[error]' in line:
                                    line = line.replace('\n', '</span><br>')
                                else:
                                    line = line.replace('\n', '<br>')
                                fw.write(line)
                    with open(self.tor_log_html, 'r') as f:
                        text = f.read()

                elif button.text() == self.button_name[2]:
                    with open(self.paths[0]) as f:
                        text = f.read()

                self.file_browser.setText(text)
                self.file_browser.moveCursor(QtGui.QTextCursor.End)

    def refresh_user_configuration(self):
        args = torrc_gen.parse_torrc()

        self.bridges_type.setText(args[0])
        index = self.bridges_combo.findText(args[0], QtCore.Qt.MatchFixedString)
        self.bridges_combo.setCurrentIndex(index)

        self.proxy_type.setText(args[1])
        index = self.proxy_combo.findText(args[1], QtCore.Qt.MatchFixedString)
        self.proxy_combo.setCurrentIndex(index)
        if not args[1] == 'None':
            self.proxy_ip_edit.setText(args[2])
            self.proxy_port_edit.setText(args[3])
            self.proxy_user_edit.setText(args[4])
            self.proxy_pwd_edit.setText(args[5])

    def refresh(self, bootstrap):
        ## get status
        tor_is_enabled = tor_status.tor_status() == 'tor_enabled'
        tor_is_running = os.path.exists(self.tor_running_path)

        if tor_is_enabled and tor_is_running:
            self.tor_status = 'running'
            ## when refresh is called from update_bootstrap, the thread
            ## would be destroyed while running, crashing the program.
            if bootstrap:
                self.start_bootstrap()
        else:
            if not tor_is_running:
                self.tor_status =  'stopped'
            if not tor_is_enabled:
                if tor_is_running:
                    self.tor_status =  'disabled-running'
                elif not tor_is_running:
                    self.tor_status =  'disabled'
            self.message = self.tor_message[self.tor_status_list.index
                                            (self.tor_status)]
        self.refresh_status()
        self.refresh_logs()
        self.refresh_user_configuration()

    def restart_tor(self):
        if not self.bootstrap_done:
            self.bootstrap_thread.terminate()
        ## if running restart tor directly stem returns
        ## bootstrap_percent 100 or a socket error, randomly.
        self.stop_tor()
        self.restart_button.setEnabled(False)

        restart_command = 'systemctl --no-pager restart tor@default'
        p = Popen(restart_command, shell=True)
        self.start_bootstrap()

    def stop_tor(self):
        self.restart_button.setEnabled(True)
        if not self.bootstrap_done:
            self.bootstrap_progress.hide()
            self.bootstrap_thread.terminate()
        stop_command = 'systemctl --no-pager stop tor@default'
        p = Popen(stop_command, shell=True)
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
    tor_controller.refresh(True)
    tor_controller.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
