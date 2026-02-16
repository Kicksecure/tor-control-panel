#!/usr/bin/python3 -su

## Copyright (C) 2018 - 2026 ENCRYPTED SUPPORT LLC
## See the file COPYING for copying conditions.

import sys
import signal

from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from subprocess import call, Popen, PIPE

import os
import re
import tempfile

from anon_connection_wizard import tor_status
from . import tor_bootstrap, torrc_gen, info, tor_network_status
from .circuit_view import CircuitGraphicsView


class RelayTableModel(QtCore.QAbstractTableModel):
    """Model for relay data — avoids creating QTableWidgetItem objects."""
    HEADERS = ['Nickname', 'Fingerprint', 'Country', 'Bandwidth',
               'Flags', 'IP', 'OR Port']
    ## Column indices
    COL_NICK, COL_FP, COL_CC, COL_BW, COL_FLAGS, COL_IP, COL_PORT = range(7)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._relays = []  # list of relay dicts

    def set_relays(self, relays):
        self.beginResetModel()
        self._relays = relays
        self.endResetModel()

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self._relays)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return 7

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self._relays[index.row()]
        col = index.column()
        if role == Qt.DisplayRole:
            if col == self.COL_NICK:
                return r['nickname']
            if col == self.COL_FP:
                return r['fingerprint'][:8] + '...'
            if col == self.COL_CC:
                return tor_network_status.country_label(r['country'])
            if col == self.COL_BW:
                return tor_network_status.format_bandwidth(r['bandwidth'])
            if col == self.COL_FLAGS:
                return ', '.join(r['flags'])
            if col == self.COL_IP:
                return r['address']
            if col == self.COL_PORT:
                return str(r['or_port'])
        elif role == Qt.UserRole:
            if col == self.COL_FP:
                return r['fingerprint']
            if col == self.COL_CC:
                return r['country']
            if col == self.COL_BW:
                return r['bandwidth']
            return None
        elif role == Qt.ToolTipRole:
            if col == self.COL_FP:
                return r['fingerprint']
        return None

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.HEADERS[section]
        return None

    def relay_at(self, row):
        if 0 <= row < len(self._relays):
            return self._relays[row]
        return None


class RelayFilterProxyModel(QtCore.QSortFilterProxyModel):
    """Proxy model for fast filtering and sorting of relay data."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._text = ''
        self._req_flags = []
        self._req_countries = []
        self._min_bw = 0

    def set_filter(self, text='', req_flags=None, req_countries=None,
                   min_bw=0):
        self._text = text.lower()
        self._req_flags = req_flags or []
        self._req_countries = req_countries or []
        self._min_bw = min_bw
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        m = self.sourceModel()
        r = m.relay_at(source_row)
        if r is None:
            return False
        ## Text filter — match any visible field or full fingerprint
        if self._text:
            haystack = (r['nickname'] + ' ' + r['fingerprint'] + ' ' +
                        r['address'] + ' ' +
                        tor_network_status.country_label(r['country']) + ' ' +
                        ', '.join(r['flags'])).lower()
            if self._text not in haystack:
                return False
        ## Flag filter
        if self._req_flags:
            for rf in self._req_flags:
                if rf not in r['flags']:
                    return False
        ## Country filter
        if self._req_countries:
            if r['country'] not in self._req_countries:
                return False
        ## Bandwidth filter
        if self._min_bw > 0 and r['bandwidth'] < self._min_bw:
            return False
        return True

    def lessThan(self, left, right):
        col = left.column()
        if col == RelayTableModel.COL_BW:
            lv = left.data(Qt.UserRole)
            rv = right.data(Qt.UserRole)
            if lv is not None and rv is not None:
                return lv < rv
        return super().lessThan(left, right)


class TorControlPanel(QDialog):
    ## Cross-thread signal for INFO lookup results (thread → main)
    _whois_result_signal = QtCore.pyqtSignal(object)

    def __init__(self):
        super(TorControlPanel, self).__init__()

        ## Make sure torrc exists.
        try:
            call(['leaprun', 'tor-config-sane'])
        except Exception:
            pass

        ## Whonix detection
        self.is_whonix = os.path.exists('/usr/share/anon-gw-base-files/gateway') or \
                         os.path.exists('/usr/share/anon-ws-base-files/workstation')

        self.setMinimumSize(1000, 720)
        self.resize(1050, 780)

        self.control_method = 'socket'
        self.control_socket_path_setting = '/run/tor/control'
        self.control_address_setting = '127.0.0.1'
        self.control_port_setting = 9051
        self.control_password = ''
        self.network_data = None
        self._whois_result_signal.connect(self._on_whois_result)

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
        self.newid_icon = QtGui.QIcon(icons_path + 'silhouette.png')

        self.tor_status_color = ['green', '#AF0000', '#AF0000', 'orange',
                                 'orange', '#AF0000']
        self.tor_status_list = ['running', 'stopped', 'disabled',
                                'disabled-running','acquiring','no_controller']

        self.message = ''
        self.tor_message = info.tor_stopped()
        #self.tor_path = '/run/tor'
        self.tor_running_path = '/run/tor/tor.pid'

        self.button_name = ['systemd &journal', 'Tor &log', '&torrc']

        self.journal_command = ['leaprun',
                                'tor-control-panel-read-tor-default-log']

        self.bridges = ['None',
                        'obfs4',
                        'snowflake',
                        'meek',
                        'Custom bridges']

        self.proxies = ['None',
                        'HTTP/HTTPS',
                        'SOCKS4',
                        'SOCKS5']

        self.tor_log = '/run/tor/log'

        #self.tor_log_html = '/run/tor/html-log'
        self.tor_log_tempfile = tempfile.NamedTemporaryFile()
        self.tor_log_html = self.tor_log_tempfile.name

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

        ## Apply Config button (left of Exit, visible when config changes)
        self.bottom_apply_btn = QPushButton('\u2714 Apply Circuit Config')
        self.bottom_apply_btn.setVisible(False)
        self._config_dirty = False
        self.bottom_apply_btn.clicked.connect(self.apply_circuit_config)

        self.quit_button = QPushButton(self.exit_icon, ' Exit')
        self.quit_button.clicked.connect(self.quit)

        self.button_box = QFrame()

        self.layout =  QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.tabs)
        self.layout.addLayout(self.button_layout)
        self.setLayout(self.layout)

        self.tab1_layout = QVBoxLayout(self.tab1)
        self.info_frame = QFrame()
        self.frame_layout = QGridLayout(self.info_frame)
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

        self.bridges_label = QLabel()
        self.bridges_type = QLabel()
        self.bridges_combo = QComboBox()
        for bridge in self.bridges:
            self.bridges_combo.addItem(bridge)
        self.bridges_combo.insertSeparator(1)
        self.bridges_combo.insertSeparator(7)
        self.bridges_combo.addItem('Disable network')
        self.bridge_info_button = QPushButton(self.info_icon, '')
        self.bridge_info_button.clicked.connect(info.show_help_censorship)

        self.proxy_label = QLabel()
        self.proxy_type = QLabel()
        self.proxy_combo = QComboBox()
        for proxy in self.proxies:
            self.proxy_combo.addItem(proxy)
        self.proxy_combo.insertSeparator(1)
        self.proxy_combo.currentIndexChanged.connect(
            lambda: self.proxy_settings_show(self.proxy_combo.currentText()))

        self.proxy_info_button = QPushButton(self.info_icon, '')
        self.proxy_info_button.clicked.connect(info.show_proxy_help)

        self.config_frame_layout = QGridLayout()
        self.config_frame_layout.addWidget(self.bridges_label, 1, 0)
        self.config_frame_layout.addWidget(self.bridges_type, 1, 1)
        self.config_frame_layout.addWidget(self.bridges_combo, 1, 1)
        self.config_frame_layout.addWidget(self.bridge_info_button, 1, 2)
        self.config_frame_layout.addWidget(self.proxy_label, 2, 0)
        self.config_frame_layout.addWidget(self.proxy_type, 2, 1)
        self.config_frame_layout.addWidget(self.proxy_combo, 2, 1)
        self.config_frame_layout.addWidget(self.proxy_info_button, 2, 2)
        self.config_frame_layout.setAlignment(Qt.AlignTop)
        self.config_frame_layout.setVerticalSpacing(6)

        self.proxy_ip_label = QLabel()
        self.proxy_ip_edit = QLineEdit()
        self.proxy_port_label = QLabel()
        self.proxy_port_edit = QLineEdit()

        self.proxy_user_label = QLabel()
        self.proxy_user_edit = QLineEdit()
        self.proxy_pwd_label = QLabel()
        self.proxy_pwd_edit = QLineEdit()

        self.prev_button = QPushButton(self.back_icon, '')
        self.prev_button.clicked.connect(self.exit_configuration)

        #self.proxy_frame = QFrame()
        self.proxy_settings_layout = QGridLayout() #(self.proxy_frame)
        self.proxy_settings_layout.addWidget(self.proxy_ip_label, 1, 0)
        self.proxy_settings_layout.addWidget(self.proxy_ip_edit, 1, 1)
        self.proxy_settings_layout.addWidget(self.proxy_port_label, 1, 2)
        self.proxy_settings_layout.addWidget(self.proxy_port_edit, 1, 3)
        self.proxy_settings_layout.addWidget(self.proxy_user_label, 2, 0)
        self.proxy_settings_layout.addWidget(self.proxy_user_edit, 2, 1)
        self.proxy_settings_layout.addWidget(self.proxy_pwd_label, 2, 2)
        self.proxy_settings_layout.addWidget(self.proxy_pwd_edit, 2, 3)
        self.proxy_settings_layout.addWidget(self.prev_button, 2, 4)
        self.proxy_settings_layout.setAlignment(Qt.AlignRight)


        self.config_layout = QVBoxLayout(self.config_frame)
        self.config_layout.addLayout(self.config_frame_layout)
        self.config_layout.addLayout(self.proxy_settings_layout)
        #self.config_layout.addWidget(self.proxy_frame)

        self.user_layout.addWidget(self.config_frame)

        self.control_box = QGroupBox()
        self.restart_button = QPushButton(self.restart_icon, ' Restart Tor',
                                          self.control_box)
        self.stop_button = QPushButton(self.stop_icon, ' Stop Tor',
                                       self.control_box)
        self.stop_button.clicked.connect(self.stop_tor)
        self.configure_button = QPushButton(self.tool_icon, ' Configure',
                                            self.control_box)

        #self.control_layout = QVBoxLayout(self.control_box)
        #self.control_layout.addWidget(self.restart_button)
        #self.control_layout.addWidget(self.stop_button)
        #self.control_layout.addWidget(self.configure_button)
        #self.control_layout.setAlignment(Qt.AlignRight)

        self.restart_button.clicked.connect(self.restart_tor)
        self.stop_button.clicked.connect(self.stop_tor)
        self.configure_button.clicked.connect(self.configure)

        self.user_layout.addWidget(self.control_box)

        self.tab1_layout.addWidget(self.info_frame)
        self.tab1_layout.addWidget(self.user_frame)

        ## Exit Proxy shortcut button (Non-Whonix only)
        if not self.is_whonix:
            self.exit_proxy_shortcut_btn = QPushButton(
                '\u26a0 Exit Proxy Settings')
            self.exit_proxy_shortcut_btn.setToolTip(
                'Open exit proxy configuration in Circuit Config tab')
            self.exit_proxy_shortcut_btn.clicked.connect(
                self._goto_exit_proxy_settings)
            self.tab1_layout.addWidget(self.exit_proxy_shortcut_btn)

        ## -- Nyx-like Dashboard (shown after bootstrap completes) --
        self.dash_frame = QFrame()
        self.dash_layout = QVBoxLayout(self.dash_frame)
        self.dash_layout.setContentsMargins(2, 2, 2, 2)

        ## System info line
        self.dash_info_label = QLabel('')
        self.dash_info_label.setWordWrap(True)
        self.dash_info_label.setStyleSheet('font-size: 10px;')
        self.dash_layout.addWidget(self.dash_info_label)

        ## Bandwidth graph
        self.dash_bw_graph = tor_network_status.BandwidthGraphWidget()
        self.dash_layout.addWidget(self.dash_bw_graph)

        ## Bandwidth stats line
        self.dash_bw_label = QLabel('')
        self.dash_bw_label.setStyleSheet('font-size: 10px;')
        self.dash_layout.addWidget(self.dash_bw_label)

        ## Events log
        self.dash_events = QTextBrowser()
        self.dash_events.setMaximumHeight(120)
        self.dash_events.setStyleSheet('font-size: 10px; font-family: monospace;')
        self.dash_layout.addWidget(self.dash_events)

        self.dash_frame.hide()
        self.tab1_layout.addWidget(self.dash_frame)
        self._dashboard_poller = None

        self.tab2_layout = QVBoxLayout(self.tab2)
        self.view_layout = QHBoxLayout()
        self.view_layout.setAlignment(Qt.AlignBottom)

        self.view_frame = QFrame()
        self.view_frame.setMinimumHeight(70)
        self.files_box = QGroupBox(self.view_frame)
        self.refresh_button = QPushButton(self.refresh_icon, ' Refresh')
        self.view_layout.setAlignment(Qt.AlignTop)
        self.view_layout.addWidget(self.view_frame)
        self.view_layout.addWidget(self.refresh_button)

        self.files_box_layout = QGridLayout(self.files_box)
        self.torrc_button = QRadioButton(self.files_box)
        self.log_button = QRadioButton(self.files_box)
        self.journal_button = QRadioButton(self.files_box)
        self.panel_log_button = QRadioButton('Panel log', self.files_box)
        self.files_box_layout.addWidget(self.torrc_button, 1, 0)
        self.files_box_layout.addWidget(self.log_button, 1, 1)
        self.files_box_layout.addWidget(self.journal_button, 2, 1)
        self.files_box_layout.addWidget(self.panel_log_button, 2, 0)

        self.torrc_button.toggled.connect(self.refresh_logs)
        self.log_button.toggled.connect(self.refresh_logs)
        self.journal_button.toggled.connect(self.refresh_logs)
        self.panel_log_button.toggled.connect(self.refresh_logs)
        self.refresh_button.clicked.connect(self.refresh_logs)
        self._panel_log_lines = []

        self.file_browser = QTextBrowser()
        self.file_browser.setLineWrapMode(QTextBrowser.NoWrap)

        self.tab2_layout.addLayout(self.view_layout)
        self.tab2_layout.addWidget(self.file_browser)

        self.custom_bridges_frame = QFrame(self.tab1)
        self.custom_bridges_layout = QVBoxLayout(self.custom_bridges_frame)
        self.custom_bridges_help = QLabel(self.custom_bridges_frame)
        self.custom_bridges = QtWidgets.QTextEdit(self.custom_bridges_frame)
        self.custom_bridges_layout.addWidget(self.custom_bridges_help)
        self.custom_bridges_layout.addWidget(self.custom_bridges)

        self.custom_buttons = QHBoxLayout()
        self.custom_cancel_button = QPushButton(QtGui.QIcon(
            self.back_icon), 'Cancel', self .custom_bridges_frame)
        self.custom_cancel_button.clicked.connect(self.hide_custom_bridges)
        self.custom_accept_button = QPushButton(QtGui.QIcon(
            self.accept_icon), 'Accept', self .custom_bridges_frame)
        self.custom_accept_button.clicked.connect(self.accept_custom_bridges)
        self.custom_buttons.addWidget(self.custom_cancel_button)
        self.custom_buttons.addWidget(self.custom_accept_button)
        self.custom_buttons.setAlignment(Qt.AlignRight)
        self.custom_bridges_layout.addLayout(self.custom_buttons)

        self.tab1_layout.addWidget(self.custom_bridges_frame)

        _utils_scroll = QtWidgets.QScrollArea()
        _utils_scroll.setWidgetResizable(True)
        _utils_inner = QWidget()
        self.utils_layout = QtWidgets.QVBoxLayout(_utils_inner)
        _utils_scroll.setWidget(_utils_inner)
        _tab3_lay = QtWidgets.QVBoxLayout(self.tab3)
        _tab3_lay.setContentsMargins(0, 0, 0, 0)
        _tab3_lay.addWidget(_utils_scroll)

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

        ## ── Donations section ────────────────────────────────
        donate_grp = QGroupBox('Support Development')
        donate_lay = QVBoxLayout(donate_grp)
        self.donate_browser = QTextBrowser()
        self.donate_browser.setOpenLinks(False)
        self.donate_browser.setOpenExternalLinks(False)
        self.donate_browser.setMinimumHeight(180)
        self.donate_browser.anchorClicked.connect(
            self._on_donate_link_clicked)
        _xmr = ('42ook1NieVQiA2Z6hXKBG1aTzQfWYKWifMELsBxKX2WJd'
                 'FsF9BuD4KTJok4gs8RBJ3V99fLfpoTK5JSoWcSfQCeF'
                 'DX6JERK')
        self._donate_xmr_addr = _xmr
        ## Resolve QR image path — try dev tree then installed path
        import os as _os
        _pkg_dir = _os.path.dirname(_os.path.abspath(__file__))
        _candidates = [
            _os.path.join(_os.path.dirname(_os.path.dirname(
                _os.path.dirname(_os.path.dirname(_pkg_dir)))),
                'share', 'tor-control-panel', 'moneroqr.jpg'),
            _os.path.join(_os.path.dirname(_os.path.dirname(
                _os.path.dirname(_os.path.dirname(
                    _os.path.dirname(_pkg_dir))))),
                'usr', 'share', 'tor-control-panel', 'moneroqr.jpg'),
            '/usr/share/tor-control-panel/moneroqr.jpg',
        ]
        self._donate_qr_path = ''
        for _cand in _candidates:
            if _os.path.isfile(_cand):
                self._donate_qr_path = _cand
                break
        if not self._donate_qr_path:
            self._donate_qr_path = _candidates[-1]
        ## 3-column layout: left (message+wallet) | center (QR) | right (links)
        self.donate_browser.setHtml(
            '<table cellspacing="0" cellpadding="0" width="100%%">'
            '<tr>'
            ## ── Left column: message + wallet ──
            '<td style="vertical-align:top;padding:6px 10px 6px 6px;'
            'width:40%%;">'
            '<div style="font-size:10px;line-height:1.4;">'
            'This panel was refined and brought to its current state '
            'by an independent developer who waited years for the '
            'community to deliver it — and finally did it himself, '
            'in memory of Vidalia.</div>'
            '<div style="margin-top:4px;font-size:9px;color:#666;'
            'line-height:1.3;">'
            'Your donations motivate further development and '
            'improvement of other privacy tools in our beloved OS.'
            '</div>'
            '<div style="margin-top:6px;font-size:10px;">'
            '<b>Monero (XMR):</b></div>'
            '<code style="font-size:8px;word-break:break-all;'
            'color:#333;background:#e8e8e8;padding:3px 5px;'
            'border-radius:3px;'
            'display:inline-block;max-width:300px;'
            'border:1px solid #bbb;">%s</code><br>'
            '<a href="copy:xmr" style="text-decoration:none;'
            'color:#1565C0;font-size:10px;">'
            '\U0001f4cb Copy address</a>'
            '</td>'
            ## ── Center column: QR thumbnail ──
            '<td style="vertical-align:middle;text-align:center;'
            'padding:6px;width:20%%;">'
            '<a href="qr:xmr">'
            '<img src="file://%s" width="80" height="80" '
            'style="border:1px solid #ccc;border-radius:4px;">'
            '</a><br>'
            '<a href="qr:xmr" style="font-size:9px;color:#888;'
            'text-decoration:none;">\U0001f50d Enlarge</a>'
            '</td>'
            ## ── Right column: Kicksecure/Whonix links ──
            '<td style="vertical-align:top;padding:6px 6px 6px 10px;'
            'border-left:1px solid #E0E0E0;width:40%%;">'
            '<div style="font-size:10px;line-height:1.4;">'
            '<b>Main developers of the OS &amp; panel creators:</b>'
            '</div>'
            '<div style="margin-top:4px;">'
            '<a href="copy:https://www.kicksecure.com/wiki/Contribute"'
            ' style="text-decoration:none;color:#1565C0;font-size:10px;">'
            '\U0001f6e1 <b>Kicksecure</b> — '
            '\U0001f4cb Copy donate link</a><br>'
            '<small style="color:#888;font-size:9px;">'
            'Hardened Debian security</small>'
            '</div>'
            '<div style="margin-top:4px;">'
            '<a href="copy:https://www.whonix.org/wiki/Contribute"'
            ' style="text-decoration:none;color:#1565C0;font-size:10px;">'
            '\U0001f9c5 <b>Whonix</b> — '
            '\U0001f4cb Copy donate link</a><br>'
            '<small style="color:#888;font-size:9px;">'
            'Anonymous OS via Tor</small>'
            '</div>'
            '</td>'
            '</tr></table>' % (_xmr, self._donate_qr_path))
        donate_lay.addWidget(self.donate_browser)
        self.utils_layout.addWidget(donate_grp)

        ## Speed Test section (moved from Circuits tab)
        st_grp = QGroupBox('Speed Test — Circuit Comparison')
        st_lay = QVBoxLayout(st_grp)
        st_row1 = QHBoxLayout()
        st_row1.addWidget(QLabel('Target:'))
        self.st_domain_edit = QLineEdit()
        self.st_domain_edit.setPlaceholderText(
            'Domain for test (default: check.torproject.org)')
        self.st_domain_edit.setMaximumWidth(300)
        st_row1.addWidget(self.st_domain_edit, 1)
        st_row1.addWidget(QLabel('Circuits per mode:'))
        self.st_count_spin = QtWidgets.QSpinBox()
        self.st_count_spin.setRange(1, 10)
        self.st_count_spin.setValue(5)
        st_row1.addWidget(self.st_count_spin)
        st_lay.addLayout(st_row1)
        ## 3 test modes
        st_row2 = QHBoxLayout()
        self.st_mode_standard = QtWidgets.QCheckBox('Standard (default Tor)')
        self.st_mode_standard.setChecked(True)
        self.st_mode_user = QtWidgets.QCheckBox('User Config')
        self.st_mode_user.setChecked(True)
        self.st_mode_user.setToolTip(
            'Test with your Circuit Config settings applied')
        self.st_mode_fast = QtWidgets.QCheckBox('Prefer Fast')
        self.st_mode_fast.setChecked(True)
        self.st_mode_fast.setToolTip(
            'Test with fastest nodes from your selected countries')
        st_row2.addWidget(self.st_mode_standard)
        st_row2.addWidget(self.st_mode_user)
        st_row2.addWidget(self.st_mode_fast)
        self.speed_test_button = QPushButton('Run Speed Test')
        self.speed_test_button.clicked.connect(self.run_speed_test)
        st_row2.addWidget(self.speed_test_button)
        st_lay.addLayout(st_row2)
        self.speed_test_browser = QTextBrowser()
        self.speed_test_browser.setMinimumHeight(200)
        self.speed_test_browser.setStyleSheet(
            'QTextBrowser { font-size: 11px; }')
        self.speed_test_browser.setText(
            '<span style="color:#d32f2f">\u26a0 Speed tests send '
            'requests through Tor and may briefly affect your active '
            'connections.</span><br><small>Select modes above and click '
            '"Run Speed Test". Each checked mode will run the specified '
            'number of circuit tests.</small>')
        st_lay.addWidget(self.speed_test_browser)
        self.utils_layout.addWidget(st_grp)

        self.utils_layout.addWidget(self.dummy1)
        self.utils_layout.addWidget(self.dummy2)

        self.newnym_box.setFrameShape(QFrame.Panel | QFrame.Raised)
        self.onioncircuits_box.setFrameShape(QFrame.Panel | QFrame.Raised)

        ## ---- Tab 4: Network Status ----
        self.tab4 = QWidget()
        self.tab4_layout = QVBoxLayout(self.tab4)
        ## Top bar: [Control Port controls] [stretch] [Prefer Fastest] [Collect All]
        _net_top = QHBoxLayout()
        _net_top.addWidget(QLabel('Port:'))
        self.cp_port_combo = QComboBox()
        _net_top.addWidget(self.cp_port_combo)
        self.cp_pass_edit = QLineEdit()
        self.cp_pass_edit.setEchoMode(QLineEdit.Password)
        self.cp_pass_edit.setPlaceholderText('Password')
        self.cp_pass_edit.setMaximumWidth(120)
        _net_top.addWidget(self.cp_pass_edit)
        self.cp_status_label = QLabel('')
        _net_top.addWidget(self.cp_status_label)
        _net_top.addStretch()
        self.net_prefer_fastest_cb = QtWidgets.QCheckBox('Prefer Fastest Nodes')
        self.net_prefer_fastest_cb.setToolTip(
            'Sort relay list by bandwidth (fastest first)')
        self.net_prefer_fastest_cb.toggled.connect(
            self._filter_node_table_flags)
        _net_top.addWidget(self.net_prefer_fastest_cb)
        self.cp_connect_button = QPushButton('\U0001f504 Collect All Nodes')
        self.cp_connect_button.clicked.connect(self.fetch_network_status)
        _net_top.addWidget(self.cp_connect_button)
        self.tab4_layout.addLayout(_net_top)
        self._auto_detect_ports()

        self.tab4_scroll = QtWidgets.QScrollArea()
        self.tab4_scroll.setWidgetResizable(True)
        self.tab4_inner = QWidget()
        self.tab4_inner_layout = QVBoxLayout(self.tab4_inner)
        self.tab4_scroll.setWidget(self.tab4_inner)
        self.tab4_layout.addWidget(self.tab4_scroll)

        ## Network Summary + Charts combined horizontally
        self.net_overview_group = QGroupBox('Network Overview')
        overview_lay = QHBoxLayout(self.net_overview_group)
        ## Left: summary stats
        summary_w = QWidget()
        ns_lay = QGridLayout(summary_w)
        ns_lay.setContentsMargins(0, 0, 0, 0)
        self.net_labels = {}
        for i, (key, label) in enumerate([
            ('total', 'Total:'), ('guards', 'Guards:'), ('exits', 'Exits:'),
            ('fast', 'Fast:'), ('stable', 'Stable:'), ('countries', 'Countries:'),
        ]):
            r, c = divmod(i, 2)
            ns_lay.addWidget(QLabel(label), r, c * 2)
            val = QLabel('<b>\u2014</b>')
            ns_lay.addWidget(val, r, c * 2 + 1)
            self.net_labels[key] = val
        overview_lay.addWidget(summary_w, 1)
        ## Right: charts
        self.country_pie = tor_network_status.PieChartWidget()
        self.bw_bar = tor_network_status.BarChartWidget()
        overview_lay.addWidget(self.country_pie, 2)
        overview_lay.addWidget(self.bw_bar, 2)
        self.net_overview_group.setMaximumHeight(180)
        self.tab4_inner_layout.addWidget(self.net_overview_group)

        ## Node Table (with fingerprint, numeric BW sort)
        self.nodes_group = QGroupBox('Relay List')
        nodes_lay = QVBoxLayout(self.nodes_group)
        filter_row = QHBoxLayout()
        self.nodes_filter_edit = QLineEdit()
        self.nodes_filter_edit.setPlaceholderText(
            'Filter by nickname, fingerprint, country...')
        self.nodes_filter_edit.textChanged.connect(self._filter_node_table)
        filter_row.addWidget(self.nodes_filter_edit, 1)
        ## Flag filter button with checkboxes
        self.flag_filter_btn = QPushButton('Flags \u25bc')
        self.flag_filter_btn.setMaximumWidth(80)
        self.flag_filter_menu = QtWidgets.QMenu()
        self._flag_actions = {}
        for flag in ['Guard', 'Exit', 'Fast', 'Stable', 'Running',
                      'Valid', 'HSDir', 'V2Dir', 'Authority',
                      'BadExit', 'NoEdConsensus']:
            act = QtWidgets.QAction(flag, self.flag_filter_menu)
            act.setCheckable(True)
            act.triggered.connect(self._filter_node_table_flags)
            self.flag_filter_menu.addAction(act)
            self._flag_actions[flag] = act
        self.flag_filter_btn.setMenu(self.flag_filter_menu)
        filter_row.addWidget(self.flag_filter_btn)
        ## Country filter (searchable multi-checkbox menu)
        self.country_filter_btn = QPushButton('Countries \u25bc')
        self.country_filter_btn.setMaximumWidth(130)
        self.country_filter_menu = QtWidgets.QMenu(self)
        self._country_actions = {}
        ## Search field at top of country menu
        self._cc_filter_widget = QtWidgets.QWidgetAction(self)
        self._cc_filter_edit = QLineEdit()
        self._cc_filter_edit.setPlaceholderText('Type to filter countries...')
        self._cc_filter_edit.textChanged.connect(self._filter_country_menu)
        self._cc_filter_widget.setDefaultWidget(self._cc_filter_edit)
        self.country_filter_menu.addAction(self._cc_filter_widget)
        self.country_filter_menu.addSeparator()
        ## "Select All / Clear" actions
        self._cc_select_all_act = QtWidgets.QAction('Select All', self)
        self._cc_select_all_act.triggered.connect(
            lambda: self._set_all_country_checks(True))
        self._cc_clear_all_act = QtWidgets.QAction('Clear All', self)
        self._cc_clear_all_act.triggered.connect(
            lambda: self._set_all_country_checks(False))
        self.country_filter_menu.addAction(self._cc_select_all_act)
        self.country_filter_menu.addAction(self._cc_clear_all_act)
        self.country_filter_menu.addSeparator()
        self.country_filter_btn.setMenu(self.country_filter_menu)
        filter_row.addWidget(self.country_filter_btn)
        ## Speed filter
        self.speed_filter_combo = QComboBox()
        for s in ['Any speed', '> 100 KB/s', '> 500 KB/s',
                   '> 1 MB/s', '> 5 MB/s', '> 10 MB/s']:
            self.speed_filter_combo.addItem(s)
        self.speed_filter_combo.currentIndexChanged.connect(
            self._filter_node_table_flags)
        filter_row.addWidget(self.speed_filter_combo)
        nodes_lay.addLayout(filter_row)
        self._relay_model = RelayTableModel(self)
        self._relay_proxy = RelayFilterProxyModel(self)
        self._relay_proxy.setSourceModel(self._relay_model)
        self._relay_proxy.setDynamicSortFilter(True)
        self.nodes_table = QtWidgets.QTableView()
        self.nodes_table.setModel(self._relay_proxy)
        self.nodes_table.setSortingEnabled(True)
        hdr = self.nodes_table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        self.nodes_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.nodes_table.setSelectionMode(
            QtWidgets.QAbstractItemView.ExtendedSelection)
        self.nodes_table.setEditTriggers(
            QtWidgets.QAbstractItemView.NoEditTriggers)
        self.nodes_table.setMinimumHeight(200)
        self.nodes_table.setAlternatingRowColors(True)
        self.nodes_table.clicked.connect(self._on_node_clicked)
        nodes_lay.addWidget(self.nodes_table)
        self.tab4_inner_layout.addWidget(self.nodes_group)

        ## Node Detail (shown on click) with add-to-layer buttons
        self.node_detail_group = QGroupBox('Node Detail')
        nd_lay = QVBoxLayout(self.node_detail_group)
        ## Add-to-layer buttons row
        nd_btns = QHBoxLayout()
        self._nd_add_entry_btn = QPushButton('+ Entry')
        self._nd_add_middle_btn = QPushButton('+ Middle')
        self._nd_add_exit_btn = QPushButton('+ Exit')
        for btn in [self._nd_add_entry_btn, self._nd_add_middle_btn,
                     self._nd_add_exit_btn]:
            btn.setMaximumWidth(80)
            btn.setEnabled(False)
            nd_btns.addWidget(btn)
        nd_btns.addWidget(QLabel(
            '<small><i>Enable StrictNodes in Circuit Config to apply</i></small>'))
        nd_btns.addStretch()
        nd_lay.addLayout(nd_btns)
        self._nd_add_entry_btn.clicked.connect(
            lambda: self._add_node_to_layer('entry'))
        self._nd_add_middle_btn.clicked.connect(
            lambda: self._add_node_to_layer('middle'))
        self._nd_add_exit_btn.clicked.connect(
            lambda: self._add_node_to_layer('exit'))
        self.node_detail_browser = QTextBrowser()
        self.node_detail_browser.setMinimumHeight(140)
        self.node_detail_browser.setText(
            '<i>Click a relay in the list above to see details...</i>')
        nd_lay.addWidget(self.node_detail_browser)
        ## Notification label for add-to-layer feedback
        self._nd_notify_label = QLabel('')
        self._nd_notify_label.setStyleSheet('font-weight: bold;')
        nd_lay.addWidget(self._nd_notify_label)
        self._current_node_fp = None
        self._current_node_flags = []
        self.tab4_inner_layout.addWidget(self.node_detail_group)

        ## ---- Tab 5: Circuit Config ----
        self.tab5 = QWidget()
        t5_lay = QVBoxLayout(self.tab5)
        t5_scroll = QtWidgets.QScrollArea()
        t5_scroll.setWidgetResizable(True)
        t5_inner = QWidget()
        self.t5_layout = QVBoxLayout(t5_inner)
        t5_scroll.setWidget(t5_inner)
        t5_lay.addWidget(t5_scroll)

        ## Strict Nodes — big and prominent at top
        strict_frame = QFrame()
        strict_frame.setFrameShape(QFrame.StyledPanel)
        strict_frame.setStyleSheet(
            'QFrame { border: 2px solid #1976D2; border-radius: 4px; '
            'padding: 6px; }')
        strict_lay = QHBoxLayout(strict_frame)
        self.strict_nodes_check = QtWidgets.QCheckBox(
            'ENABLE Strict Nodes — Tor will ONLY use nodes matching '
            'your rules below')
        self.strict_nodes_check.setStyleSheet(
            'font-weight: bold; font-size: 12px;')
        strict_lay.addWidget(self.strict_nodes_check)
        self.t5_layout.addWidget(strict_frame)

        ## Circuit length + prefer fastest
        opts_frame = QHBoxLayout()
        opts_frame.addWidget(QLabel('Circuit length:'))
        self.circuit_len_combo = QComboBox()
        for n in ['3 (default)', '4', '5']:
            self.circuit_len_combo.addItem(n)
        opts_frame.addWidget(self.circuit_len_combo)
        self.prefer_fastest_check = QtWidgets.QCheckBox(
            'Prefer fastest nodes')
        self.prefer_fastest_check.setToolTip(
            'Sort selected nodes by bandwidth, preferring fastest.')
        self.prefer_fastest_check.toggled.connect(self._toggle_fast_spins)
        opts_frame.addWidget(self.prefer_fastest_check)
        ## Per-layer fastest node count spinboxes
        self._fast_spin_widget = QWidget()
        fs_lay = QHBoxLayout(self._fast_spin_widget)
        fs_lay.setContentsMargins(0, 0, 0, 0)
        fs_lay.addWidget(QLabel('Entry:'))
        self.fast_entry_spin = QtWidgets.QSpinBox()
        self.fast_entry_spin.setRange(1, 20)
        self.fast_entry_spin.setValue(3)
        self.fast_entry_spin.setToolTip(
            'Total number of entry nodes (distributed across countries)')
        fs_lay.addWidget(self.fast_entry_spin)
        fs_lay.addWidget(QLabel('Mid:'))
        self.fast_middle_spin = QtWidgets.QSpinBox()
        self.fast_middle_spin.setRange(1, 20)
        self.fast_middle_spin.setValue(4)
        self.fast_middle_spin.setToolTip(
            'Total number of middle nodes (distributed across countries)')
        fs_lay.addWidget(self.fast_middle_spin)
        fs_lay.addWidget(QLabel('Exit:'))
        self.fast_exit_spin = QtWidgets.QSpinBox()
        self.fast_exit_spin.setRange(1, 20)
        self.fast_exit_spin.setValue(5)
        self.fast_exit_spin.setToolTip(
            'Total number of exit nodes (distributed across countries)')
        fs_lay.addWidget(self.fast_exit_spin)
        opts_frame.addWidget(self._fast_spin_widget)
        opts_frame.addStretch()
        reset_all_nodes_btn = QPushButton(
            '\u26a0 Reset All')
        reset_all_nodes_btn.setToolTip(
            'Clear ALL selected nodes, countries, and exclude lists '
            'across all circuit layers')
        reset_all_nodes_btn.setStyleSheet(
            'color: #C62828; font-weight: bold;')
        reset_all_nodes_btn.setMaximumWidth(100)
        reset_all_nodes_btn.clicked.connect(self._reset_all_circuit_config)
        opts_frame.addWidget(reset_all_nodes_btn)
        self.t5_layout.addLayout(opts_frame)

        ## Per-layer node selection (multiple countries + fingerprints)
        ## Collapsible: checked = expanded, unchecked = collapsed
        self._layer_widgets = {}
        for layer, title in [('entry', 'Entry Nodes (Guard)'),
                              ('middle', 'Middle Nodes'),
                              ('exit', 'Exit Nodes')]:
            grp = QGroupBox(title)
            grp.setCheckable(True)
            grp.setChecked(False)
            g_content = QWidget()
            g_lay = QVBoxLayout(g_content)
            g_lay.setContentsMargins(4, 4, 4, 4)

            ## Countries row: combo + add + list
            cc_row = QHBoxLayout()
            cc_combo = QComboBox()
            cc_combo.setMinimumWidth(220)
            cc_combo.addItem('Any country')
            cc_add_btn = QPushButton('Add Country')
            cc_add_btn.setMaximumWidth(100)
            cc_list = QtWidgets.QListWidget()
            cc_list.setMaximumHeight(80)
            cc_list.setSelectionMode(
                QtWidgets.QAbstractItemView.MultiSelection)
            cc_rm_btn = QPushButton('Remove')
            cc_rm_btn.setMaximumWidth(70)
            cc_clear_btn = QPushButton('Clear All')
            cc_clear_btn.setMaximumWidth(70)
            cc_row.addWidget(QLabel('Countries:'))
            cc_row.addWidget(cc_combo, 1)
            cc_row.addWidget(cc_add_btn)
            g_lay.addLayout(cc_row)
            cc_list_row = QHBoxLayout()
            cc_list_row.addWidget(cc_list, 1)
            cc_btns = QVBoxLayout()
            cc_btns.addWidget(cc_rm_btn)
            cc_btns.addWidget(cc_clear_btn)
            cc_list_row.addLayout(cc_btns)
            g_lay.addLayout(cc_list_row)

            ## Speed filter
            spd_row = QHBoxLayout()
            spd_row.addWidget(QLabel('Min speed:'))
            spd_combo = QComboBox()
            for s in ['Any speed', '> 100 KB/s', '> 500 KB/s',
                       '> 1 MB/s', '> 5 MB/s', '> 10 MB/s']:
                spd_combo.addItem(s)
            spd_row.addWidget(spd_combo)
            spd_row.addStretch()
            g_lay.addLayout(spd_row)

            ## Specific nodes by fingerprint
            fp_row = QHBoxLayout()
            fp_edit = QLineEdit()
            fp_edit.setPlaceholderText(
                'Paste relay fingerprint (40 hex chars)')
            fp_edit.setMaxLength(40)
            fp_add_btn = QPushButton('Add Node')
            fp_add_btn.setMaximumWidth(80)
            fp_row.addWidget(QLabel('Node:'))
            fp_row.addWidget(fp_edit, 1)
            fp_row.addWidget(fp_add_btn)
            g_lay.addLayout(fp_row)
            fp_list = QtWidgets.QListWidget()
            fp_list.setMaximumHeight(100)
            fp_list.setSelectionMode(
                QtWidgets.QAbstractItemView.MultiSelection)
            fp_rm_btn = QPushButton('Remove')
            fp_rm_btn.setMaximumWidth(70)
            fp_clear_btn = QPushButton('Clear All')
            fp_clear_btn.setMaximumWidth(70)
            fp_list_row = QHBoxLayout()
            fp_list_row.addWidget(fp_list, 1)
            fp_btns = QVBoxLayout()
            fp_btns.addWidget(fp_rm_btn)
            fp_btns.addWidget(fp_clear_btn)
            fp_list_row.addLayout(fp_btns)
            g_lay.addLayout(fp_list_row)

            cc_add_btn.clicked.connect(
                lambda checked, c=cc_combo, l=cc_list:
                    self._add_country_to_list(c, l))
            cc_rm_btn.clicked.connect(
                lambda checked, l=cc_list: self._remove_selected(l))
            cc_clear_btn.clicked.connect(
                lambda checked, l=cc_list: l.clear())
            fp_add_btn.clicked.connect(
                lambda checked, e=fp_edit, l=fp_list:
                    self._add_fp_to_list(e, l))
            fp_rm_btn.clicked.connect(
                lambda checked, l=fp_list: self._remove_selected(l))
            fp_clear_btn.clicked.connect(
                lambda checked, l=fp_list: l.clear())

            self._layer_widgets[layer] = {
                'country': cc_combo, 'cc_list': cc_list,
                'speed': spd_combo,
                'fp_edit': fp_edit, 'fp_list': fp_list,
                'group': grp, 'content': g_content,
            }
            grp_lay = QVBoxLayout(grp)
            grp_lay.setContentsMargins(0, 0, 0, 0)
            grp_lay.addWidget(g_content)
            g_content.setVisible(False)
            grp.toggled.connect(g_content.setVisible)
            self.t5_layout.addWidget(grp)

        ## Track unsaved changes: connect layer list signals
        for layer in self._layer_widgets:
            w = self._layer_widgets[layer]
            w['cc_list'].model().rowsInserted.connect(self._mark_config_dirty)
            w['cc_list'].model().rowsRemoved.connect(self._mark_config_dirty)
            w['fp_list'].model().rowsInserted.connect(self._mark_config_dirty)
            w['fp_list'].model().rowsRemoved.connect(self._mark_config_dirty)
        self.strict_nodes_check.toggled.connect(self._mark_config_dirty)
        self.circuit_len_combo.currentIndexChanged.connect(
            self._mark_config_dirty)

        ## Exclude Countries (collapsible)
        exc_grp = QGroupBox('Exclude Countries')
        exc_grp.setCheckable(True)
        exc_grp.setChecked(False)
        exc_content = QWidget()
        exc_inner = QVBoxLayout(exc_content)
        exc_inner.setContentsMargins(4, 4, 4, 4)
        exc_explain = QLabel(
            '<small>Relays from these countries will <b>never</b> be '
            'used when building circuits. This applies to all layers '
            '(entry, middle, exit).</small>')
        exc_explain.setWordWrap(True)
        exc_inner.addWidget(exc_explain)
        exc_row_w = QWidget()
        exc_lay = QHBoxLayout(exc_row_w)
        exc_lay.setContentsMargins(0, 0, 0, 0)
        exc_inner.addWidget(exc_row_w)
        self.exclude_add_combo = QComboBox()
        self.exclude_add_combo.setMinimumWidth(200)
        self.exclude_add_combo.addItem('Select country...')
        self.exclude_list = QtWidgets.QListWidget()
        self.exclude_list.setMaximumHeight(60)
        self.exclude_list.setSelectionMode(
            QtWidgets.QAbstractItemView.MultiSelection)
        exc_btns = QVBoxLayout()
        self.exclude_add_button = QPushButton('Add')
        self.exclude_add_button.clicked.connect(self.add_exclude_country)
        self.exclude_remove_button = QPushButton('Remove')
        self.exclude_remove_button.clicked.connect(self.remove_exclude_country)
        exc_btns.addWidget(self.exclude_add_combo)
        exc_btns.addWidget(self.exclude_add_button)
        exc_btns.addWidget(self.exclude_remove_button)
        exc_lay.addWidget(self.exclude_list)
        exc_lay.addLayout(exc_btns)
        exc_grp_lay = QVBoxLayout(exc_grp)
        exc_grp_lay.setContentsMargins(0, 0, 0, 0)
        exc_grp_lay.addWidget(exc_content)
        exc_content.setVisible(False)
        exc_grp.toggled.connect(exc_content.setVisible)
        self.t5_layout.addWidget(exc_grp)
        self.exclude_list.model().rowsInserted.connect(self._mark_config_dirty)
        self.exclude_list.model().rowsRemoved.connect(self._mark_config_dirty)

        ## Exit Proxy — traffic exits through proxy, not Tor exit node
        self.exit_proxy_grp = QGroupBox(
            'Exit Proxy (destination sees proxy IP)')
        self.exit_proxy_grp.setCheckable(True)
        self.exit_proxy_grp.setChecked(False)
        px_content = QWidget()
        px_lay = QVBoxLayout(px_content)
        px_lay.setContentsMargins(4, 4, 4, 4)
        px_info = QLabel(
            '<small>When enabled, <b>ALL traffic</b> is '
            'transparently routed through exit proxies. '
            'Tor\'s SocksPort is automatically intercepted — '
            'no browser configuration needed. '
            'Traffic: <b>App \u2192 Tor \u2192 Exit proxy '
            '\u2192 Internet</b>. '
            'The destination sees the <b>proxy IP</b>. '
            'Use <b>Check All</b> to validate and '
            '<b>Remove Dead</b> to filter. '
            'Multiple proxies rotate round-robin.</small>')
        px_info.setWordWrap(True)
        px_lay.addWidget(px_info)
        ## Status line (shows port + instructions when active)
        self.exit_proxy_status_label = QLabel('')
        self.exit_proxy_status_label.setWordWrap(True)
        self.exit_proxy_status_label.setTextInteractionFlags(
            Qt.TextSelectableByMouse)
        px_lay.addWidget(self.exit_proxy_status_label)
        ## Settings row: timeout, concurrency, auto-check
        px_settings_row = QHBoxLayout()
        px_settings_row.addWidget(QLabel('Timeout:'))
        self.exit_proxy_timeout_spin = QtWidgets.QSpinBox()
        self.exit_proxy_timeout_spin.setRange(3, 120)
        self.exit_proxy_timeout_spin.setValue(15)
        self.exit_proxy_timeout_spin.setSuffix('s')
        self.exit_proxy_timeout_spin.setMaximumWidth(70)
        self.exit_proxy_timeout_spin.setToolTip(
            'Max time to wait for each proxy response')
        px_settings_row.addWidget(self.exit_proxy_timeout_spin)
        px_settings_row.addWidget(QLabel('Threads:'))
        self.exit_proxy_threads_spin = QtWidgets.QSpinBox()
        self.exit_proxy_threads_spin.setRange(5, 500)
        self.exit_proxy_threads_spin.setValue(50)
        self.exit_proxy_threads_spin.setMaximumWidth(70)
        self.exit_proxy_threads_spin.setToolTip(
            'Number of parallel proxy checks')
        px_settings_row.addWidget(self.exit_proxy_threads_spin)
        self.exit_proxy_autocheck_ip = QtWidgets.QCheckBox(
            'Check exit IP')
        self.exit_proxy_autocheck_ip.setChecked(True)
        self.exit_proxy_autocheck_ip.setToolTip(
            'Show the exit IP for each proxy during check')
        px_settings_row.addWidget(self.exit_proxy_autocheck_ip)
        self.exit_proxy_auto_remove_dead_cb = QtWidgets.QCheckBox(
            'Auto-remove dead')
        self.exit_proxy_auto_remove_dead_cb.setChecked(True)
        self.exit_proxy_auto_remove_dead_cb.setToolTip(
            'Automatically remove dead proxies after check '
            'and during live traffic (after 3 consecutive failures)')
        self.exit_proxy_auto_remove_dead_cb.toggled.connect(
            lambda v: setattr(self, '_exit_proxy_auto_remove_dead', v))
        self._exit_proxy_auto_remove_dead = True
        px_settings_row.addWidget(self.exit_proxy_auto_remove_dead_cb)
        px_settings_row.addStretch()
        px_lay.addLayout(px_settings_row)
        ## Auto-recheck row
        px_recheck_row = QHBoxLayout()
        self.exit_proxy_auto_recheck_cb = QtWidgets.QCheckBox(
            'Auto-recheck every')
        self.exit_proxy_auto_recheck_cb.setChecked(False)
        self.exit_proxy_auto_recheck_cb.setToolTip(
            'Periodically recheck all proxies and remove dead ones')
        self.exit_proxy_recheck_interval = QtWidgets.QSpinBox()
        self.exit_proxy_recheck_interval.setRange(1, 60)
        self.exit_proxy_recheck_interval.setValue(5)
        self.exit_proxy_recheck_interval.setSuffix(' min')
        self.exit_proxy_recheck_interval.setMaximumWidth(80)
        self.exit_proxy_auto_recheck_cb.toggled.connect(
            self._exit_proxy_toggle_auto_recheck)
        self.exit_proxy_recheck_interval.valueChanged.connect(
            self._exit_proxy_update_recheck_interval)
        px_recheck_row.addWidget(self.exit_proxy_auto_recheck_cb)
        px_recheck_row.addWidget(self.exit_proxy_recheck_interval)
        self.exit_proxy_domain_rotation_cb = QtWidgets.QCheckBox(
            'Domain rotation')
        self.exit_proxy_domain_rotation_cb.setChecked(False)
        self.exit_proxy_domain_rotation_cb.setToolTip(
            'Use different Tor circuits (exit nodes) for different '
            'domains when connecting through the same proxy. '
            'Increases privacy by preventing traffic correlation.')
        self.exit_proxy_domain_rotation_cb.toggled.connect(
            self._exit_proxy_toggle_domain_rotation)
        px_recheck_row.addWidget(self.exit_proxy_domain_rotation_cb)
        px_recheck_row.addStretch()
        px_lay.addLayout(px_recheck_row)
        self._exit_proxy_recheck_timer = QtCore.QTimer(self)
        self._exit_proxy_recheck_timer.timeout.connect(
            self._exit_proxy_auto_recheck_tick)
        ## Add single proxy
        px_add_row = QHBoxLayout()
        self.exit_proxy_type = QComboBox()
        for pt in ['socks5', 'http']:
            self.exit_proxy_type.addItem(pt)
        self.exit_proxy_type.setMaximumWidth(80)
        self.exit_proxy_addr = QLineEdit()
        self.exit_proxy_addr.setPlaceholderText('host:port')
        self.exit_proxy_user = QLineEdit()
        self.exit_proxy_user.setPlaceholderText('user (opt)')
        self.exit_proxy_user.setMaximumWidth(90)
        self.exit_proxy_pass = QLineEdit()
        self.exit_proxy_pass.setPlaceholderText('pass (opt)')
        self.exit_proxy_pass.setEchoMode(QLineEdit.Password)
        self.exit_proxy_pass.setMaximumWidth(90)
        self.exit_proxy_add_btn = QPushButton('Add')
        self.exit_proxy_add_btn.setMaximumWidth(50)
        self.exit_proxy_add_btn.clicked.connect(self._add_exit_proxy)
        px_add_row.addWidget(self.exit_proxy_type)
        px_add_row.addWidget(self.exit_proxy_addr, 1)
        px_add_row.addWidget(self.exit_proxy_user)
        px_add_row.addWidget(self.exit_proxy_pass)
        px_add_row.addWidget(self.exit_proxy_add_btn)
        px_lay.addLayout(px_add_row)
        ## URL list import (space / newline / comma separated)
        px_url_row = QHBoxLayout()
        self.exit_proxy_url_edit = QLineEdit()
        self.exit_proxy_url_edit.setPlaceholderText(
            'Paste proxies (space/comma separated): '
            'socks5://h:p socks5://h:p ...')
        self.exit_proxy_url_import_btn = QPushButton('Import')
        self.exit_proxy_url_import_btn.setMaximumWidth(60)
        self.exit_proxy_url_import_btn.clicked.connect(
            self._import_exit_proxies)
        px_url_row.addWidget(self.exit_proxy_url_edit, 1)
        px_url_row.addWidget(self.exit_proxy_url_import_btn)
        px_lay.addLayout(px_url_row)
        ## Proxy list
        self.exit_proxy_list = QtWidgets.QListWidget()
        self.exit_proxy_list.setMinimumHeight(100)
        self.exit_proxy_list.setSelectionMode(
            QtWidgets.QAbstractItemView.MultiSelection)
        px_lay.addWidget(self.exit_proxy_list)
        ## Buttons row below the list
        px_btn_row = QHBoxLayout()
        px_rm_btn = QPushButton('Remove')
        px_rm_btn.clicked.connect(self._exit_proxy_remove_selected)
        px_clear_btn = QPushButton('Clear All')
        px_clear_btn.clicked.connect(self._exit_proxy_clear_all)
        self.exit_proxy_check_btn = QPushButton('\u2714 Check All')
        self.exit_proxy_check_btn.clicked.connect(
            self._exit_proxy_check_all)
        self.exit_proxy_rm_dead_btn = QPushButton('\u2716 Remove Dead')
        self.exit_proxy_rm_dead_btn.clicked.connect(
            self._exit_proxy_remove_dead)
        self.exit_proxy_verify_btn = QPushButton('\u26a1 Verify IP')
        self.exit_proxy_verify_btn.setToolTip(
            'Test exit IP through Tor and the first alive proxy')
        self.exit_proxy_verify_btn.clicked.connect(
            self._exit_proxy_verify_ip)
        self.exit_proxy_autobind_btn = QPushButton('\u2699 Auto-bind')
        self.exit_proxy_autobind_btn.setToolTip(
            'Auto-bind domains to alive proxies (hash-based)')
        self.exit_proxy_autobind_btn.clicked.connect(
            self._exit_proxy_auto_bind)
        px_btn_row.addWidget(px_rm_btn)
        px_btn_row.addWidget(px_clear_btn)
        px_btn_row.addWidget(self.exit_proxy_check_btn)
        px_btn_row.addWidget(self.exit_proxy_rm_dead_btn)
        px_btn_row.addWidget(self.exit_proxy_verify_btn)
        px_btn_row.addWidget(self.exit_proxy_autobind_btn)
        px_lay.addLayout(px_btn_row)
        ## Check status label
        self.exit_proxy_check_label = QLabel('')
        self.exit_proxy_check_label.setWordWrap(True)
        px_lay.addWidget(self.exit_proxy_check_label)
        ## Safety warning
        _px_warn = QLabel(
            '<small style="color:#E65100;">'
            '\u26a0 <b>Warning:</b> Public free proxies are not safe '
            'for sensitive use. They may intercept or log your traffic. '
            'For a clean and secure exit IP, use your own trusted proxy '
            'servers.</small>')
        _px_warn.setWordWrap(True)
        px_lay.addWidget(_px_warn)
        ## Proxy mode selector
        px_mode_row = QHBoxLayout()
        px_mode_row.addWidget(QLabel('<b>Proxy mode:</b>'))
        self.exit_proxy_mode_all = QtWidgets.QRadioButton(
            'All traffic through proxy')
        self.exit_proxy_mode_all.setChecked(True)
        self.exit_proxy_mode_all.setToolTip(
            'All connections go through external proxies')
        self.exit_proxy_mode_selective = QtWidgets.QRadioButton(
            'Selected domains only')
        self.exit_proxy_mode_selective.setToolTip(
            'Only domains in the binding list go through proxy.\n'
            'All other traffic goes directly through Tor.')
        px_mode_row.addWidget(self.exit_proxy_mode_all)
        px_mode_row.addWidget(self.exit_proxy_mode_selective)
        px_mode_row.addStretch()
        self.exit_proxy_mode_all.toggled.connect(
            self._exit_proxy_mode_changed)
        px_lay.addLayout(px_mode_row)
        ## Domain binding section
        px_dom_lbl = QLabel(
            '<small><b>Domain \u2192 Proxy binding:</b> bind specific '
            'domains to specific proxies. In "Selected domains only" '
            'mode, only listed domains go through proxy — rest via '
            'Tor directly.</small>')
        px_dom_lbl.setWordWrap(True)
        px_lay.addWidget(px_dom_lbl)
        px_dom_row = QHBoxLayout()
        self.exit_proxy_bind_domain = QLineEdit()
        self.exit_proxy_bind_domain.setPlaceholderText(
            'Domain (e.g. example.com)')
        self.exit_proxy_bind_proxy = QLineEdit()
        self.exit_proxy_bind_proxy.setPlaceholderText(
            'socks5://host:port')
        self.exit_proxy_bind_btn = QPushButton('Bind')
        self.exit_proxy_bind_btn.setMaximumWidth(50)
        self.exit_proxy_bind_btn.clicked.connect(
            self._exit_proxy_add_binding)
        px_dom_row.addWidget(self.exit_proxy_bind_domain, 1)
        px_dom_row.addWidget(self.exit_proxy_bind_proxy, 1)
        px_dom_row.addWidget(self.exit_proxy_bind_btn)
        px_lay.addLayout(px_dom_row)
        self.exit_proxy_bindings_list = QtWidgets.QListWidget()
        self.exit_proxy_bindings_list.setMaximumHeight(60)
        self.exit_proxy_bindings_list.setSelectionMode(
            QtWidgets.QAbstractItemView.MultiSelection)
        px_bind_rm_row = QHBoxLayout()
        px_bind_rm_row.addWidget(self.exit_proxy_bindings_list, 1)
        px_bind_rm_btn = QPushButton('Remove')
        px_bind_rm_btn.setMaximumWidth(70)
        px_bind_rm_btn.clicked.connect(
            lambda: self._remove_selected(
                self.exit_proxy_bindings_list))
        px_bind_clear_btn = QPushButton('Clear All')
        px_bind_clear_btn.setMaximumWidth(70)
        px_bind_clear_btn.setStyleSheet('color: #C62828;')
        px_bind_clear_btn.clicked.connect(
            self._reset_all_proxy_bindings)
        px_bind_btns = QVBoxLayout()
        px_bind_btns.addWidget(px_bind_rm_btn)
        px_bind_btns.addWidget(px_bind_clear_btn)
        px_bind_rm_row.addLayout(px_bind_btns)
        px_lay.addLayout(px_bind_rm_row)
        px_grp_lay = QVBoxLayout(self.exit_proxy_grp)
        px_grp_lay.setContentsMargins(0, 0, 0, 0)
        px_grp_lay.addWidget(px_content)
        px_content.setVisible(False)
        self.exit_proxy_grp.toggled.connect(px_content.setVisible)
        self.exit_proxy_grp.toggled.connect(self._exit_proxy_toggled)
        
        ## Hide Exit Proxy settings on Whonix (security/philosophy)
        if not self.is_whonix:
            self.t5_layout.addWidget(self.exit_proxy_grp)
        else:
            self.exit_proxy_grp.hide()

        self._exit_proxy_server = None
        self._proxy_checker_thread = None
        self._exit_proxy_intercept_state = {}

        ## Apply button
        self.apply_circuit_button = QPushButton(
            '\u2714  Apply Configuration')
        self.apply_circuit_button.setMinimumHeight(36)
        self.apply_circuit_button.setStyleSheet(
            'font-weight: bold; font-size: 13px;')
        self.apply_circuit_button.clicked.connect(self.apply_circuit_config)
        self.t5_layout.addWidget(self.apply_circuit_button)
        self.t5_layout.addStretch()

        ## ---- Tab 6: Circuits ----
        self.tab6 = QWidget()
        t6_lay = QVBoxLayout(self.tab6)

        ## Circuits controls
        circ_btns = QHBoxLayout()
        self.refresh_circuits_btn = QPushButton('\u27f3 Refresh')
        self.refresh_circuits_btn.clicked.connect(self.show_current_circuits)
        self.new_circuit_button = QPushButton('New Circuit')
        self.new_circuit_button.clicked.connect(self.request_new_circuit)
        self.circ_auto_check = QtWidgets.QCheckBox('Auto-refresh (2s)')
        self.circ_auto_check.setChecked(True)
        self.circ_auto_check.stateChanged.connect(
            self._toggle_circuit_autorefresh)
        circ_btns.addWidget(self.refresh_circuits_btn)
        circ_btns.addWidget(self.new_circuit_button)
        circ_btns.addWidget(self.circ_auto_check)
        circ_btns.addStretch()
        t6_lay.addLayout(circ_btns)

        ## Circuits display — interactive graphics view
        self.circ_status_label = QLabel(
            '<b>Circuits:</b> waiting for data...')
        self.circ_status_label.setStyleSheet('font-size: 11px; padding: 2px;')
        t6_lay.addWidget(self.circ_status_label)

        ## Horizontal splitter: circuit view (left) + detail panel (right)
        _circ_splitter = QtWidgets.QSplitter(Qt.Horizontal)
        self.circuit_view = CircuitGraphicsView(self)
        self.circuit_view.link_clicked.connect(
            self._on_circuit_link_clicked_str)
        _circ_splitter.addWidget(self.circuit_view)

        ## Detail / WHOIS panel — right of circuit chains
        self.circ_detail_browser = QTextBrowser()
        self.circ_detail_browser.setMinimumWidth(200)
        self.circ_detail_browser.setStyleSheet(
            'QTextBrowser { font-size: 11px; }')
        self.circ_detail_browser.setPlaceholderText(
            'Click a circuit node or stream target to see details '
            'and WHOIS/OSINT info.')
        _circ_splitter.addWidget(self.circ_detail_browser)
        _circ_splitter.setStretchFactor(0, 2)
        _circ_splitter.setStretchFactor(1, 1)
        _circ_splitter.setSizes([600, 300])
        t6_lay.addWidget(_circ_splitter, 3)

        ## Store last fetched circuits data for click lookups
        self._last_circuits_data = []
        ## Persistent stream history (target -> info) survives refreshes
        self._stream_history = {}
        ## Track recently-closed circuits so they stay visible ~15s
        self._recent_closed_circuits = {}  ## cid -> {data, closed_at}
        self._prev_circuit_ids = set()

        ## Circuit auto-refresh timer
        self._circ_timer = QtCore.QTimer(self)
        self._circ_timer.timeout.connect(self._auto_refresh_circuits)
        self._circ_timer.setInterval(2000)

        ## ---- Tab 7: Advanced (torrc parameter editor) ----
        self.tab7 = QWidget()
        t7_lay = QVBoxLayout(self.tab7)

        ## Top controls
        t7_top = QHBoxLayout()
        self.adv_apply_btn = QPushButton('Apply Changes (SIGHUP)')
        self.adv_apply_btn.clicked.connect(self._adv_apply_config)
        self.adv_save_check = QtWidgets.QCheckBox('Save to torrc')
        self.adv_save_check.setChecked(True)
        self.adv_save_check.setToolTip(
            'Also write changes to torrc file for persistence.')
        self.adv_filter_edit = QLineEdit()
        self.adv_filter_edit.setPlaceholderText('Filter options...')
        self.adv_filter_edit.setMaximumWidth(200)
        self.adv_filter_edit.textChanged.connect(self._adv_filter_options)
        self.adv_cat_combo = QComboBox()
        self.adv_cat_combo.addItem('All Categories')
        self.adv_cat_combo.currentIndexChanged.connect(
            self._adv_filter_options)
        self.adv_status_label = QLabel('')
        t7_top.addWidget(self.adv_apply_btn)
        t7_top.addWidget(self.adv_save_check)
        t7_top.addWidget(self.adv_filter_edit)
        t7_top.addWidget(self.adv_cat_combo)
        t7_lay.addLayout(t7_top)
        t7_lay.addWidget(self.adv_status_label)
        self._adv_values_loaded = False
        self._circuit_config_loaded = False

        ## Parameter table
        self.adv_table = QtWidgets.QTableWidget(0, 4)
        self.adv_table.setHorizontalHeaderLabels(
            ['Option', 'Value', 'Category', 'Summary'])
        adv_hdr = self.adv_table.horizontalHeader()
        adv_hdr.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        adv_hdr.setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
        adv_hdr.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        adv_hdr.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
        self.adv_table.setSelectionBehavior(
            QtWidgets.QAbstractItemView.SelectRows)
        self.adv_table.setAlternatingRowColors(True)
        self.adv_table.clicked.connect(self._adv_show_description)
        t7_lay.addWidget(self.adv_table, 1)

        ## Description panel at bottom
        self.adv_desc_browser = QTextBrowser()
        self.adv_desc_browser.setMaximumHeight(120)
        self.adv_desc_browser.setPlaceholderText(
            'Click an option to see its full description...')
        t7_lay.addWidget(self.adv_desc_browser)

        ## Raw torrc editor toggle
        t7_raw_row = QHBoxLayout()
        self.adv_raw_toggle = QPushButton('Edit Raw torrc')
        self.adv_raw_toggle.setCheckable(True)
        self.adv_raw_toggle.clicked.connect(self._adv_toggle_raw)
        t7_raw_row.addWidget(self.adv_raw_toggle)
        t7_raw_row.addStretch()
        t7_lay.addLayout(t7_raw_row)
        self.adv_editor = QtWidgets.QPlainTextEdit()
        self.adv_editor.setFont(QtGui.QFont('monospace', 9))
        self.adv_editor.setPlaceholderText(
            'Raw torrc content (toggle above to show)')
        self.adv_editor.hide()
        t7_lay.addWidget(self.adv_editor)

        ## ---- Tab 8: Onion Services ----
        self.tab8 = QWidget()
        t8_lay = QVBoxLayout(self.tab8)

        ## Onion service configuration
        onion_cfg = QGroupBox('Create Onion Service (via control port)')
        oc_lay = QVBoxLayout(onion_cfg)

        ## Info label
        oc_lay.addWidget(QLabel(
            '<small>Creates an ephemeral .onion address via ADD_ONION. '
            'Check "Persistent" to save the key so it survives '
            'Tor restarts.</small>'))

        ## Port mapping
        port_row = QHBoxLayout()
        port_row.addWidget(QLabel('Virtual port:'))
        self.onion_vport_spin = QtWidgets.QSpinBox()
        self.onion_vport_spin.setRange(1, 65535)
        self.onion_vport_spin.setValue(80)
        port_row.addWidget(self.onion_vport_spin)
        port_row.addWidget(QLabel('Target:'))
        self.onion_target_edit = QLineEdit()
        self.onion_target_edit.setPlaceholderText('127.0.0.1:80')
        self.onion_target_edit.setText('127.0.0.1:80')
        port_row.addWidget(self.onion_target_edit)
        self.onion_add_port_btn = QPushButton('Add Port')
        self.onion_add_port_btn.setMaximumWidth(80)
        self.onion_add_port_btn.clicked.connect(self._onion_add_port)
        port_row.addWidget(self.onion_add_port_btn)
        oc_lay.addLayout(port_row)

        ## Port mappings list
        self.onion_ports_list = QtWidgets.QListWidget()
        self.onion_ports_list.setMaximumHeight(60)
        self.onion_ports_list.setSelectionMode(
            QtWidgets.QAbstractItemView.MultiSelection)
        ports_row = QHBoxLayout()
        ports_row.addWidget(self.onion_ports_list, 1)
        ports_btns = QVBoxLayout()
        self.onion_rm_port_btn = QPushButton('Remove')
        self.onion_rm_port_btn.setMaximumWidth(70)
        self.onion_rm_port_btn.clicked.connect(
            lambda: self._remove_selected(self.onion_ports_list))
        ports_btns.addWidget(self.onion_rm_port_btn)
        ports_row.addLayout(ports_btns)
        oc_lay.addLayout(ports_row)

        ## Persistent checkbox + Create button
        bottom_row = QHBoxLayout()
        self.onion_persistent_check = QtWidgets.QCheckBox(
            'Persistent (save key to disk)')
        self.onion_persistent_check.setChecked(True)
        bottom_row.addWidget(self.onion_persistent_check)
        bottom_row.addStretch()
        self.onion_create_btn = QPushButton('Create Service')
        self.onion_create_btn.setStyleSheet(
            'font-weight:bold; background:#1976D2; color:white; '
            'padding:5px 12px; border-radius:3px;')
        self.onion_create_btn.clicked.connect(self._onion_create_service)
        bottom_row.addWidget(self.onion_create_btn)
        oc_lay.addLayout(bottom_row)
        t8_lay.addWidget(onion_cfg)

        ## Existing onion services
        svc_grp = QGroupBox('Active Onion Services')
        svc_lay = QVBoxLayout(svc_grp)
        svc_top = QHBoxLayout()
        self.onion_refresh_btn = QPushButton('\u27f3 Refresh')
        self.onion_refresh_btn.clicked.connect(self._onion_refresh)
        svc_top.addWidget(self.onion_refresh_btn)
        self.onion_restore_btn = QPushButton('Restore Saved')
        self.onion_restore_btn.setToolTip(
            'Re-create persistent onion services from saved keys')
        self.onion_restore_btn.clicked.connect(self._onion_restore_saved)
        svc_top.addWidget(self.onion_restore_btn)
        svc_top.addStretch()
        svc_lay.addLayout(svc_top)
        self.onion_services_browser = QTextBrowser()
        self.onion_services_browser.setMinimumHeight(200)
        self.onion_services_browser.setStyleSheet(
            'QTextBrowser { font-size: 11px; }')
        self.onion_services_browser.setOpenLinks(False)
        self.onion_services_browser.anchorClicked.connect(
            self._onion_link_clicked)
        self.onion_services_browser.setPlaceholderText(
            'Click "Refresh" to see active onion services...')
        svc_lay.addWidget(self.onion_services_browser)
        t8_lay.addWidget(svc_grp)
        t8_lay.addStretch()

        ## Category colors for nyx-like display
        self._adv_cat_colors = {
            'General': '#4CAF50',
            'Client': '#2196F3',
            'Relay': '#FF9800',
            'Directory': '#9C27B0',
            'Authority': '#795548',
            'Hidden Service': '#E91E63',
            'Testing': '#607D8B',
            'Denial Of Service': '#f44336',
        }
        ## Populate from stem.manual
        self._adv_options = {}
        self._adv_populate_options()

        ## Bottom bar layout: [Theme: combo] [stretch] [Apply Config] [Exit]
        self.theme_combo = QComboBox()
        self.theme_combo.addItem('Light')
        self.theme_combo.addItem('Dark')
        self.theme_combo.addItem('System')
        self.theme_combo.currentIndexChanged.connect(self._apply_theme)
        self.button_layout.insertWidget(0, QLabel('Theme:'))
        self.button_layout.insertWidget(1, self.theme_combo)
        ## Heart button — opens Utilities tab (donations)
        self._donate_heart_btn = QPushButton('\u2764')
        self._donate_heart_btn.setMaximumWidth(30)
        self._donate_heart_btn.setToolTip('Support Development')
        self._donate_heart_btn.setStyleSheet(
            'QPushButton { color: #E53935; font-size: 14px; border: none; }'
            'QPushButton:hover { color: #B71C1C; }')
        self._donate_heart_btn.clicked.connect(self._open_donate_tab)
        self.button_layout.insertWidget(2, self._donate_heart_btn)
        self.button_layout.insertStretch(3)
        self.button_layout.addWidget(self.bottom_apply_btn)
        self.button_layout.addWidget(self.quit_button)
        self._apply_theme(0)

        self.setup_ui()

    def setup_ui(self):
        self.tabs.addTab(self.tab1, 'Control')
        self.tabs.addTab(self.tab4, 'Network')
        self.tabs.addTab(self.tab5, 'Circuit Config')
        self.tabs.addTab(self.tab6, 'Circuits')
        if not self.is_whonix:
            self.tabs.addTab(self.tab8, 'Onion')
        self.tabs.addTab(self.tab7, 'Advanced')
        self.tabs.addTab(self.tab3, 'Utilities')
        self.tabs.addTab(self.tab2, 'Logs')
        self.tabs.currentChanged.connect(self._on_tab_changed)

        self.quit_button.setIconSize(QtCore.QSize(20, 20))

        self.status.setText('Tor status')

        self.tor_message_browser.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.tor_message_browser.setMinimumHeight(24)
        self.tor_message_browser.setStyleSheet('background-color:rgba(0, 0, 0, 0)')

        self.bootstrap_progress.setMaximumHeight(15)
        self.bootstrap_progress.setMinimum(0)
        self.bootstrap_progress.setMaximum(100)
        self.bootstrap_progress.hide()

        self.user_frame.setLineWidth(2)
        self.user_frame.setMaximumHeight(175)
        self.user_frame.setMinimumHeight(175)
        self.user_frame.setFrameShape(QFrame.Panel | QFrame.Raised)

        self.config_frame.setTitle('User configuration')

        self.bridges_label.setMaximumWidth(90)
        self.bridges_label.setText('Bridges type :')
        self.bridges_type.setStyleSheet('font:bold')
        self.bridges_type.setMinimumHeight(24)
        self.bridges_combo.hide()
        self.bridge_info_button.setMaximumWidth(20)
        self.bridge_info_button.setFlat(True)
        self.bridge_info_button.hide()
        self.bridge_info_button.setToolTip('Show bridges help')

        self.proxy_label.setText('Proxy type :')
        self.proxy_label.setMaximumWidth(90)
        self.proxy_type.setStyleSheet('font:bold')
        self.proxy_type.setMinimumHeight(24)
        self.proxy_combo.hide()
        self.proxy_info_button.setMaximumWidth(20)
        self.proxy_info_button.setFlat(True)
        self.proxy_info_button.hide()
        self.proxy_info_button.setToolTip('Show proxies help')

        self.proxy_ip_label.setText('Address:')
        self.proxy_ip_label.hide()
        self.proxy_ip_edit.setPlaceholderText('ex : 127.0.0.1')
        self.proxy_ip_edit.hide()
        self.proxy_ip_edit.setEnabled(False)

        self.proxy_port_label.setText('Port:')
        self.proxy_port_label.hide()
        self.proxy_port_edit.setPlaceholderText('1-65535')
        self.proxy_port_edit.hide()
        self.proxy_port_edit.setEnabled(False)

        self.proxy_user_label.setText('User: ')
        self.proxy_user_label.hide()
        self.proxy_user_edit.setPlaceholderText('Optional')
        self.proxy_user_edit.hide()
        self.proxy_user_edit.setEnabled(False)

        self.proxy_pwd_label.setText('Password: ')
        self.proxy_pwd_label.hide()
        self.proxy_pwd_edit.setPlaceholderText('Optional')
        self.proxy_pwd_edit.hide()
        self.proxy_pwd_edit.setEnabled(False)

        self.prev_button.setMaximumWidth(20)
        self.prev_button.setFlat(True)
        self.prev_button.hide()
        self.prev_button.setToolTip('Quit configuration')

        self.control_box.setMinimumWidth(140)
        self.control_box.setMaximumWidth(140)
        self.control_box.setTitle('Control')
        self.restart_button.setIconSize(QtCore.QSize(28, 28))
        self.restart_button.setFlat(True)
        self.restart_button.setGeometry(QtCore.QRect(10, 28, 113, 32))
        self.stop_button.setIconSize(QtCore.QSize(28, 28))
        self.stop_button.setFlat(True)
        self.stop_button.setGeometry(QtCore.QRect(10, 70, 96, 32))
        self.configure_button.setIconSize(QtCore.QSize(28, 28))
        self.configure_button.setFlat(True)
        self.configure_button.setGeometry(QtCore.QRect(10, 110, 102, 32))
        self.configure_button.setDefault(True)

        self.custom_bridges_frame.hide()
        self.custom_cancel_button.setFlat(True)
        self.custom_accept_button.setFlat(True)
        self.custom_bridges_help.setWordWrap(True)
        self.custom_bridges_help.setTextInteractionFlags(
            Qt.TextSelectableByMouse)
        self.custom_bridges_help.setText(info.custom_bridges_help())

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

        self.files_box_layout.setVerticalSpacing(0)
        self.files_box_layout.setHorizontalSpacing(20)
        self.files_box_layout.setContentsMargins(6, 0, 6, 0)
        self.files_box.setTitle('  Files            Logs')
        self.torrc_button.setText('&torrc')
        self.log_button.setText('Tor &log')
        self.journal_button.setText('systemd &journal')
        self.log_button.setChecked(True)

        self.refresh_button.setMaximumWidth(70)
        self.refresh_button.setFlat(True)

    def newnym(self):
        from stem import Signal
        try:
            controller = tor_network_status.get_controller(
                self.control_method, self.control_address_setting,
                self.control_port_setting, self.control_socket_path_setting,
                self.control_password)
            controller.signal(Signal.NEWNYM)
            controller.close()
        except Exception as e:
            print('[ERROR] newnym failed: %s' % e)
            try:
                from stem.control import Controller
                with Controller.from_socket_file('/run/tor/control') as c:
                    c.authenticate()
                    c.signal(Signal.NEWNYM)
            except Exception as e2:
                print('[ERROR] newnym fallback also failed: %s' % e2)

    def onioncircuits(self):
        try:
            Popen(['onioncircuits'], start_new_session=True)
        except FileNotFoundError:
            pass

    def _open_donate_tab(self):
        """Switch to Utilities tab (donations section)."""
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == 'Utilities':
                self.tabs.setCurrentIndex(i)
                break

    def _on_donate_link_clicked(self, url):
        """Handle clicks in the donations browser."""
        href = url.toString()
        if href.startswith('copy:'):
            text = href[5:]
            if text == 'xmr':
                text = self._donate_xmr_addr
            QtWidgets.QApplication.clipboard().setText(text)
            ## Show visible feedback
            _short = text if len(text) < 50 else text[:47] + '...'
            QtWidgets.QToolTip.showText(
                QtGui.QCursor.pos(),
                '\u2714 Copied: %s' % _short,
                self.donate_browser, QtCore.QRect(), 2500)
        elif href.startswith('qr:'):
            ## Show bundled QR image in a dialog
            import os as _os
            pix = QtGui.QPixmap(self._donate_qr_path)
            if pix.isNull():
                QtWidgets.QMessageBox.information(
                    self, 'QR Code',
                    'QR image not found at:\n%s' % self._donate_qr_path)
                return
            dlg = QtWidgets.QDialog(self)
            dlg.setWindowTitle('Monero QR')
            dlg.setMinimumSize(340, 420)
            lay = QVBoxLayout(dlg)
            lbl = QLabel()
            lbl.setPixmap(pix.scaled(
                300, 300, Qt.KeepAspectRatio, Qt.SmoothTransformation))
            lbl.setAlignment(Qt.AlignCenter)
            lay.addWidget(lbl)
            addr_lbl = QLabel(
                '<code style="font-size:8px;word-break:break-all;">'
                '%s</code>' % self._donate_xmr_addr)
            addr_lbl.setWordWrap(True)
            addr_lbl.setTextInteractionFlags(
                Qt.TextSelectableByMouse)
            lay.addWidget(addr_lbl)
            copy_btn = QPushButton('\U0001f4cb Copy Address')
            copy_btn.clicked.connect(lambda: (
                QtWidgets.QApplication.clipboard().setText(
                    self._donate_xmr_addr),
                copy_btn.setText('\u2714 Copied!')))
            lay.addWidget(copy_btn)
            dlg.exec_()
        elif href.startswith('open:'):
            link = href[5:]
            ## Copy to clipboard instead of opening browser
            ## (browsers may not work on Gateway)
            QtWidgets.QApplication.clipboard().setText(link)
            self._panel_log('Copied link: %s' % link)

    def update_bootstrap(self, bootstrap_phase, bootstrap_percent):
        print(f"[DEBUG] bootstrap_phase = {bootstrap_phase}")
        print(f"[DEBUG] bootstrap_percent = {bootstrap_percent}")

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
            self._start_dashboard()
            ## Auto-fetch network data so country lists are populated
            QtCore.QTimer.singleShot(500, self.fetch_network_status)
            ## Crash recovery: restore Tor's SocksPort if needed
            QtCore.QTimer.singleShot(800,
                                     self._exit_proxy_crash_recovery)
            ## Load saved exit proxy config
            QtCore.QTimer.singleShot(1500, self._exit_proxy_load_config)
        else:
            self.message = bootstrap_phase
            self.tor_status = 'acquiring'
            self.refresh_status()

        if bootstrap_phase == 'no_controller':
            if hasattr(self, 'bootstrap_thread'):
                self.bootstrap_thread.terminate()
            self.tor_status = 'no_controller'
            self.message = info.no_controller()
            self.bootstrap_progress.hide()
            self.restart_button.setEnabled(True)
            self.stop_button.setEnabled(True)
            self.refresh_status()

        elif bootstrap_phase == 'socket_error':
            self.bootstrap_thread.terminate()
            self.message = info.socket_error()
            self.bootstrap_progress.hide()
            self.control_box.setEnabled(True)
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
            if self.bridges_combo.currentText() == 'Custom bridges':
                self.status.hide()
                self.tor_message_browser.hide()
                self.user_frame.hide()
                self.custom_bridges_frame.show()

            elif self.bridges_combo.currentText() == 'Disable network':
                tor_status.set_disabled()
                self.restart_tor()
                self.exit_configuration()

            elif self.bridges_combo.currentText() == 'Enable network':
                tor_status.set_enabled()
                self.restart_tor()
                self.exit_configuration()

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
        print(f"[DEBUG] tor_status = {self.tor_status}")
        print(f"[DEBUG] message = {self.message}")
        self.tor_message_browser.setText(self.message)
        color = self.tor_status_color[self.tor_status_list.index(
            self.tor_status)]
        self.status.setStyleSheet('background-color:%s; color:white; \
                                  font:bold' % color)

    def refresh_logs(self):
        for button in self.files_box.findChildren(QRadioButton):
            if button.isChecked():
                if button.text() == self.button_name[0]:
                    try:
                        p = Popen(self.journal_command, stdout=PIPE, stderr=PIPE)
                        stdout, stderr = p.communicate()
                        text = stdout.decode()
                    except FileNotFoundError:
                        try:
                            p = Popen(['journalctl', '-u', 'tor@default', '-u', 'tor',
                                       '-n', '200', '--no-pager'],
                                      stdout=PIPE, stderr=PIPE)
                            stdout, stderr = p.communicate()
                            text = stdout.decode(errors='replace')
                        except FileNotFoundError:
                            text = 'Cannot read systemd journal: journalctl not found.'

                # Get n last lines from Tor log, HTML format for highlighting
                # warnings and errors, write to file for text browser.
                elif button.text() == self.button_name[1]:
                    raw_lines = None
                    if os.path.exists(self.tor_log):
                        p = Popen(['tail', '-n', '3000', self.tor_log],
                                  stdout=PIPE, stderr=PIPE)
                        stdout, _ = p.communicate()
                        raw_lines = stdout.decode(errors='replace').split('\n')
                    else:
                        try:
                            p = Popen(['journalctl', '-u', 'tor@default',
                                       '-u', 'tor', '-n', '200',
                                       '--no-pager'],
                                      stdout=PIPE, stderr=PIPE)
                            stdout, _ = p.communicate()
                            raw_lines = stdout.decode(
                                errors='replace').split('\n')
                        except FileNotFoundError:
                            pass

                    if raw_lines:
                        with open(self.tor_log_html, 'w') as fw:
                            for line in raw_lines:
                                line = line + '\n'
                                if len(line) > 19:
                                    line = line[:12] + '...' + line[19:]
                                line = line.replace('[warn]', self.warn_style)
                                line = line.replace('[error]', self.error_style)
                                if '[warn]' in line or '[error]' in line:
                                    line = line.replace('\n', '</span><br>')
                                else:
                                    line = line.replace('\n', '<br>')
                                fw.write(line)
                        with open(self.tor_log_html, 'r') as f:
                            text = f.read()
                    else:
                        text = ('Tor log not found at %s. '
                                'Try systemd journal tab or restart Tor.'
                                % self.tor_log)

                elif button.text() == self.button_name[2]:
                    ## Try to read the REAL torrc from the running Tor
                    _torrc_read = torrc_gen.torrc_path()
                    try:
                        ctrl = self._get_controller()
                        _torrc_read = ctrl.get_info('config-file')
                        ctrl.close()
                    except Exception:
                        pass
                    try:
                        with open(_torrc_read) as f:
                            text = f.read()
                        text = '## File: %s\n\n%s' % (_torrc_read, text)
                    except FileNotFoundError:
                        text = 'torrc file not found at: %s' % _torrc_read

                elif button.text() == 'Panel log':
                    text = '\n'.join(self._panel_log_lines) if \
                        self._panel_log_lines else '(no panel log entries yet)'

                self.file_browser.setText(text)
                self.file_browser.moveCursor(QtGui.QTextCursor.End)

    def closeEvent(self, event):
        """Clean up all threads and timers before closing."""
        ## Stop all timers first to prevent new work being scheduled
        for tname in ('_circ_timer', '_exit_proxy_recheck_timer',
                      '_exit_proxy_dead_timer'):
            t = getattr(self, tname, None)
            if t is not None:
                try:
                    t.stop()
                except Exception:
                    pass
        if hasattr(self, 'circuit_view'):
            try:
                self.circuit_view._anim_timer.stop()
            except Exception:
                pass
        ## Save exit proxy config
        try:
            self._exit_proxy_save_config()
        except Exception:
            pass
        ## Stop exit proxy server (handles asyncio task cleanup)
        try:
            if self._exit_proxy_server is not None:
                self._exit_proxy_server.stop()
                self._exit_proxy_server = None
        except Exception:
            pass
        ## Terminate proxy checker thread (uses asyncio, quit() won't work)
        if self._proxy_checker_thread is not None:
            try:
                if self._proxy_checker_thread.isRunning():
                    self._proxy_checker_thread.terminate()
                    self._proxy_checker_thread.wait(2000)
            except (RuntimeError, Exception):
                pass
            self._proxy_checker_thread = None
        ## Stop dashboard poller (runs a 1s sleep loop)
        if getattr(self, '_dashboard_poller', None) is not None:
            try:
                self._dashboard_poller.stop()
                if not self._dashboard_poller.wait(2000):
                    self._dashboard_poller.terminate()
                    self._dashboard_poller.wait(500)
            except (RuntimeError, Exception):
                pass
        ## Terminate bootstrap thread if still running
        if hasattr(self, 'bootstrap_thread'):
            try:
                if self.bootstrap_thread.isRunning():
                    self.bootstrap_thread.terminate()
                    self.bootstrap_thread.wait(1000)
            except (RuntimeError, Exception):
                pass
        ## Wait for all other QThread instances — keep references alive
        ## until each thread is fully stopped
        _threads_to_stop = []
        for attr in ('circuit_fetcher', '_auto_circ_fetcher',
                     '_circ_node_fetcher', '_speed_tester',
                     '_net_fetcher', '_node_detail_fetcher',
                     '_config_applier', 'circuit_tester'):
            t = getattr(self, attr, None)
            if t is not None and isinstance(t, QtCore.QThread):
                _threads_to_stop.append(t)
        for t in _threads_to_stop:
            try:
                if t.isRunning():
                    t.quit()
                    if not t.wait(1000):
                        t.terminate()
                        t.wait(500)
            except (RuntimeError, Exception):
                pass
        ## Now safe to close
        self.accept()
        super().closeEvent(event)

    def _panel_log(self, msg):
        import datetime
        ts = datetime.datetime.now().strftime('%H:%M:%S')
        self._panel_log_lines.append('[%s] %s' % (ts, msg))
        ## Keep max 500 lines
        if len(self._panel_log_lines) > 500:
            self._panel_log_lines = self._panel_log_lines[-500:]

    def refresh_user_configuration(self):
        try:
            args = torrc_gen.parse_torrc()
        except Exception:
            self.bridges_type.setText('None')
            self.proxy_type.setText('None')
            return

        if args is None:
            self.bridges_type.setText('None')
            self.proxy_type.setText('None')
            return

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
        tor_is_running = (os.path.exists(self.tor_running_path)
                          or tor_network_status.detect_tor_running())

        if tor_is_enabled and tor_is_running:
            self.tor_status = 'running'
            tor_state = True
            ## when refresh is called from update_bootstrap, the thread
            ## would be destroyed while running, crashing the program.
            if bootstrap:
                self.start_bootstrap()
        else:
            if not tor_is_running:
                self.tor_status = 'stopped'
                tor_state = False
                self.bridges_combo.removeItem(8)
                self.bridges_combo.addItem('Disable network')

            if not tor_is_enabled:
                if tor_is_running:
                    self.tor_status = 'disabled-running'
                    tor_state = True

                elif not tor_is_running:
                    self.tor_status = 'disabled'
                    tor_state = False
                self.bridges_combo.removeItem(8)
                self.bridges_combo.addItem('Enable network')

            self.message = self.tor_message[self.tor_status_list.index
                                            (self.tor_status)]

        self.newnym_button.setEnabled(tor_state)

        self.refresh_status()
        self.refresh_user_configuration()
        self.refresh_logs()

    def restart_tor(self):
        if not self.bootstrap_done:
            self.bootstrap_thread.terminate()
        ## if running restart tor directly stem returns
        ## bootstrap_percent 100 or a socket error, randomly.
        self.stop_tor()
        self.restart_button.setEnabled(False)

        try:
            p = Popen(['leaprun', 'acw-tor-control-restart'])
        except FileNotFoundError:
            try:
                p = Popen(['sudo', '-n', 'systemctl', 'restart', 'tor@default'])
            except Exception as e:
                self._panel_log('restart_tor fallback failed: %s' % e)
        self.start_bootstrap()

    def stop_tor(self):
        self.restart_button.setEnabled(True)
        if not self.bootstrap_done:
            self.bootstrap_progress.hide()
            self.bootstrap_thread.terminate()
        try:
            p = Popen(['leaprun', 'acw-tor-control-stop'])
            p.wait()
        except FileNotFoundError:
            try:
                p = Popen(['sudo', '-n', 'systemctl', 'stop', 'tor@default'])
                p.wait()
            except Exception as e:
                self._panel_log('stop_tor fallback failed: %s' % e)
        self.refresh(True)

    ## ---- Network / Circuit Methods ----

    def _apply_theme(self, idx):
        if idx == 0:  # Light
            self.setStyleSheet(
                'QWidget { background-color: #f5f5f5; color: #1a1a1a; }'
                'QGroupBox { font-weight: bold; }'
                'QTableView, QTableWidget { background-color: #ffffff; '
                '  gridline-color: #e0e0e0;'
                '  alternate-background-color: #f0f0f0; }'
                'QTableView::item, QTableWidget::item { padding: 2px; }'
                'QHeaderView::section { background-color: #e8e8e8;'
                '  color: #1a1a1a; padding: 4px; border: 1px solid #ccc; }'
                'QTextBrowser { background-color: #ffffff;'
                '  border: 1px solid #ccc; }'
                'QLineEdit { background-color: #ffffff; border: 1px solid #bbb;'
                '  border-radius: 3px; padding: 3px; }'
                'QPlainTextEdit { background-color: #ffffff; '
                '  border: 1px solid #bbb; }'
                'QComboBox { background-color: #ffffff;'
                '  border: 1px solid #bbb; border-radius: 3px; padding: 2px; }'
                'QListWidget { background-color: #ffffff;'
                '  border: 1px solid #bbb; }')
            if hasattr(self, 'circuit_view'):
                self.circuit_view.set_background_color('#FAFAFA')
        elif idx == 1:  # Dark
            self.setStyleSheet(
                'QWidget { background-color: #2b2b2b; color: #e0e0e0; }'
                'QGroupBox { font-weight: bold; color: #e0e0e0; }'
                'QTableView, QTableWidget { background-color: #333333;'
                '  color: #e0e0e0; gridline-color: #444;'
                '  alternate-background-color: #333333; }'
                'QTableView::item, QTableWidget::item {'
                '  padding: 2px; }'
                'QHeaderView::section { background-color: #3a3a3a;'
                '  color: #e0e0e0; padding: 4px; border: 1px solid #555; }'
                'QTextBrowser { background-color: #333333; color: #e0e0e0; }'
                'QLineEdit { background-color: #3a3a3a; color: #e0e0e0;'
                '  border: 1px solid #555; border-radius: 3px; padding: 3px; }'
                'QPlainTextEdit { background-color: #3a3a3a; color: #e0e0e0;'
                '  border: 1px solid #555; }'
                'QComboBox { background-color: #3a3a3a; color: #e0e0e0; }'
                'QPushButton { background-color: #444; color: #e0e0e0;'
                '  border: 1px solid #666; border-radius: 3px; padding: 4px; }'
                'QPushButton:hover { background-color: #555; }'
                'QTabBar::tab { background: #3a3a3a; color: #ccc;'
                '  padding: 6px 12px; }'
                'QTabBar::tab:selected { background: #2b2b2b; color: #fff; }'
                'QCheckBox { color: #e0e0e0; }'
                'QLabel { color: #e0e0e0; }'
                'QListWidget { background-color: #333; color: #e0e0e0;'
                '  border: 1px solid #555; }'
                'QGraphicsView { border: 1px solid #555; }')
            if hasattr(self, 'circuit_view'):
                self.circuit_view.set_background_color('#2b2b2b')
        else:  # System
            self.setStyleSheet('')
            if hasattr(self, 'circuit_view'):
                self.circuit_view.set_background_color('#FAFAFA')

    def _on_tab_changed(self, index):
        current = self.tabs.widget(index)
        ## Auto-load Circuit Config from Tor when first switching to tab
        if current is self.tab5 and not self._circuit_config_loaded:
            self._circuit_config_loaded = True
            QtCore.QTimer.singleShot(100, self._load_circuit_config)
        ## Auto-load Advanced values when switching to Advanced tab
        if current is self.tab7 and not self._adv_values_loaded:
            self._adv_values_loaded = True
            QtCore.QTimer.singleShot(100, self._adv_load_config)
        ## Start/stop circuit auto-refresh
        if current is self.tab6 and self.circ_auto_check.isChecked():
            self._circ_timer.start()
            self._auto_refresh_circuits()
        else:
            self._circ_timer.stop()

    def _goto_exit_proxy_settings(self):
        self.tabs.setCurrentWidget(self.tab5)
        QtCore.QTimer.singleShot(200, lambda:
            self.exit_proxy_grp.ensurePolished())

    def _add_exit_proxy(self):
        addr = self.exit_proxy_addr.text().strip()
        if not addr:
            return
        proto = self.exit_proxy_type.currentText()
        user = self.exit_proxy_user.text().strip()
        pw = self.exit_proxy_pass.text().strip()
        if user and pw:
            url = '%s://%s:%s@%s' % (proto, user, pw, addr)
        elif user:
            url = '%s://%s@%s' % (proto, user, addr)
        else:
            url = '%s://%s' % (proto, addr)
        item = QtWidgets.QListWidgetItem(url)
        item.setData(QtCore.Qt.UserRole, url)
        self.exit_proxy_list.addItem(item)
        self.exit_proxy_addr.clear()
        self.exit_proxy_user.clear()
        self.exit_proxy_pass.clear()
        self._exit_proxy_save_config()

    def _import_exit_proxies(self):
        text = self.exit_proxy_url_edit.text().strip()
        if not text:
            return
        urls = re.split(r'[,\n\s]+', text)
        added = 0
        for url in urls:
            url = url.strip()
            if not url:
                continue
            item = QtWidgets.QListWidgetItem(url)
            item.setData(QtCore.Qt.UserRole, url)
            self.exit_proxy_list.addItem(item)
            added += 1
        self.exit_proxy_url_edit.clear()
        if added:
            self.exit_proxy_check_label.setText(
                'Imported %d proxies' % added)
            self._exit_proxy_save_config()

    def _toggle_circuit_autorefresh(self, state):
        if state and self.tabs.currentWidget() is self.tab6:
            self._circ_timer.start()
            self._auto_refresh_circuits()
        else:
            self._circ_timer.stop()

    def _auto_refresh_circuits(self):
        if self.tabs.currentWidget() is not self.tab6:
            self._circ_timer.stop()
            return
        self._sync_control_settings()
        params = self._get_control_params()
        self._auto_circ_fetcher = tor_network_status.TorCircuitFetcher(
            **params, parent=self)
        self._auto_circ_fetcher.circuits_done.connect(self._on_circuits_fetched)
        self._auto_circ_fetcher.error.connect(
            lambda e: self.circ_status_label.setText(
                '<b style="color:red">Error:</b> %s' % e))
        self._auto_circ_fetcher.start()

    def _auto_detect_ports(self):
        self.cp_port_combo.clear()
        found = tor_network_status.detect_control_ports()
        if not found:
            self.cp_port_combo.addItem('No ports detected')
            self.cp_status_label.setText('No Tor control port found.')
        else:
            for method, addr, port in found:
                if method == 'socket':
                    self.cp_port_combo.addItem(
                        'Socket: %s' % addr, ('socket', addr, 0))
                else:
                    self.cp_port_combo.addItem(
                        'TCP %s:%d' % (addr, port), ('tcp', addr, port))
            self.cp_status_label.setText('%d port(s) found.' % len(found))
            m, a, p = found[0]
            self.control_method = m
            if m == 'socket':
                self.control_socket_path_setting = a
            else:
                self.control_address_setting = a
                self.control_port_setting = p

    def _get_control_params(self):
        return {
            'control_method': self.control_method,
            'control_address': self.control_address_setting,
            'control_port': self.control_port_setting,
            'control_socket_path': self.control_socket_path_setting,
            'password': self.control_password,
        }

    def _sync_control_settings(self):
        data = self.cp_port_combo.currentData()
        if data:
            method, addr, port = data
            self.control_method = method
            if method == 'socket':
                self.control_socket_path_setting = addr
            else:
                self.control_address_setting = addr
                self.control_port_setting = port
        self.control_password = self.cp_pass_edit.text()

    ## -- Network fetch --

    def fetch_network_status(self):
        self._sync_control_settings()
        self.cp_connect_button.setEnabled(False)
        self.cp_status_label.setText('Connecting...')
        params = self._get_control_params()
        self.net_fetcher = tor_network_status.TorNetworkFetcher(
            **params, parent=self)
        self.net_fetcher.progress.connect(
            lambda m: self.cp_status_label.setText(m))
        self.net_fetcher.fetch_done.connect(self._on_fetch_finished)
        self.net_fetcher.error.connect(self._on_fetch_error)
        self.net_fetcher.start()

    def _on_fetch_finished(self, data):
        self.network_data = data
        self.cp_connect_button.setEnabled(True)
        self.cp_status_label.setText('%d relays loaded.' % data['total'])
        for key in ['total', 'guards', 'exits', 'fast', 'stable']:
            self.net_labels[key].setText('<b>%d</b>' % data[key])
        self.net_labels['countries'].setText(
            '<b>%d</b>' % len(data['countries']))
        self._populate_charts(data)
        self._populate_node_table(data)
        self._populate_country_combos(data)

    def _on_fetch_error(self, err):
        self.cp_connect_button.setEnabled(True)
        self.cp_status_label.setText('Error: %s' % err)

    ## -- Charts --

    def _populate_charts(self, data):
        colors = tor_network_status.CHART_COLORS
        top = sorted(data['countries'].items(), key=lambda x: -x[1])[:10]
        other = sum(v for _, v in sorted(
            data['countries'].items(), key=lambda x: -x[1])[10:])
        pie_data = [(tor_network_status.country_label(cc), cnt,
                     colors[i % len(colors)])
                    for i, (cc, cnt) in enumerate(top)]
        if other > 0:
            pie_data.append(('Other', other, '#999999'))
        self.country_pie.set_data(pie_data, 'Countries')

        bw_by_cc = {}
        for r in data['relays']:
            bw_by_cc[r['country']] = \
                bw_by_cc.get(r['country'], 0) + r['bandwidth']
        top_bw = sorted(bw_by_cc.items(), key=lambda x: -x[1])[:12]
        bar_data = [(tor_network_status.country_label(cc),
                     int(bw / 1024), colors[i % len(colors)])
                    for i, (cc, bw) in enumerate(top_bw)]
        self.bw_bar.set_data(bar_data, 'Bandwidth (MB/s)')

    ## -- Node table (with fingerprint + numeric BW sort) --

    def _populate_node_table(self, data):
        relays = data['relays']
        self._relay_model.set_relays(relays)
        self.nodes_table.resizeColumnsToContents()

        ## Populate country filter menu (checkboxes) — re-add search
        ## field and utility actions after clearing
        self.country_filter_menu.clear()
        self._country_actions = {}
        self.country_filter_menu.addAction(self._cc_filter_widget)
        self.country_filter_menu.addSeparator()
        self.country_filter_menu.addAction(self._cc_select_all_act)
        self.country_filter_menu.addAction(self._cc_clear_all_act)
        self.country_filter_menu.addSeparator()
        for cc in sorted(data['countries'].keys()):
            label = '%s (%d)' % (
                tor_network_status.country_label(cc), data['countries'][cc])
            act = QtWidgets.QAction(label, self.country_filter_menu)
            act.setCheckable(True)
            act.setData(cc)
            act.triggered.connect(self._filter_node_table_flags)
            self.country_filter_menu.addAction(act)
            self._country_actions[cc] = act

    def _filter_node_table(self, text=None):
        if text is None:
            text = self.nodes_filter_edit.text()
        req_flags = [f for f, a in self._flag_actions.items() if a.isChecked()]
        req_countries = [cc for cc, a in self._country_actions.items()
                         if a.isChecked()]
        spd_thresholds = {
            0: 0, 1: 100, 2: 500,
            3: 1024, 4: 5*1024, 5: 10*1024,
        }
        min_bw = spd_thresholds.get(
            self.speed_filter_combo.currentIndex(), 0)
        self._relay_proxy.set_filter(
            text=text, req_flags=req_flags,
            req_countries=req_countries, min_bw=min_bw)

    def _filter_node_table_flags(self, *_args):
        self._filter_node_table()
        ## Sort by bandwidth descending if "Prefer Fastest" is checked
        if hasattr(self, 'net_prefer_fastest_cb') and \
                self.net_prefer_fastest_cb.isChecked():
            self._relay_proxy.sort(
                RelayTableModel.COL_BW, QtCore.Qt.DescendingOrder)
        else:
            self._relay_proxy.sort(
                RelayTableModel.COL_NICK, QtCore.Qt.AscendingOrder)

    def _filter_country_menu(self, text):
        """Hide country checkboxes that don't match the search text."""
        text = text.lower()
        for cc, act in self._country_actions.items():
            act.setVisible(text in act.text().lower())

    def _set_all_country_checks(self, checked):
        """Select All / Clear All country checkboxes."""
        for act in self._country_actions.values():
            act.setChecked(checked)
        self._filter_node_table()

    ## -- Node detail on click --

    def _on_node_clicked(self, index):
        ## Map proxy index to source model to get fingerprint
        source_idx = self._relay_proxy.mapToSource(
            self._relay_proxy.index(index.row(), RelayTableModel.COL_FP))
        fp = self._relay_model.data(source_idx, Qt.UserRole)
        if not fp:
            return
        self.node_detail_group.show()
        self.node_detail_browser.setText('Loading %s...' % fp[:8])
        self._sync_control_settings()
        params = self._get_control_params()
        self._detail_fetcher = tor_network_status.TorNodeDetailFetcher(
            fp, **params, parent=self)
        self._detail_fetcher.detail_done.connect(self._on_node_detail)
        self._detail_fetcher.log.connect(self._panel_log)
        self._detail_fetcher.error.connect(
            lambda e: self.node_detail_browser.setText(
                '<span style="color:red">%s</span>' % e))
        self._detail_fetcher.start()

    def _on_node_detail(self, info):
        self._current_node_fp = info['fingerprint']
        self._current_node_flags = info['flags']

        ## Enable add-to-layer buttons based on flags
        flags = info['flags']
        has_guard = 'Guard' in flags
        has_exit = 'Exit' in flags and 'BadExit' not in flags
        has_bad = 'BadExit' in flags
        self._nd_add_entry_btn.setEnabled(has_guard and not has_bad)
        self._nd_add_middle_btn.setEnabled(not has_bad)
        self._nd_add_exit_btn.setEnabled(has_exit)

        html = '<table cellpadding="2">'
        rows = [
            ('Nickname', info['nickname']),
            ('Fingerprint', '<code style="user-select:all">%s</code>' %
             info['fingerprint']),
            ('Country', tor_network_status.country_label(info['country'])),
            ('Address', '%s:%s' % (info['address'], info['or_port'])),
            ('Flags', ', '.join(info['flags'])),
            ('Consensus BW', tor_network_status.format_bandwidth(
                info['bandwidth'])),
            ('Observed BW', tor_network_status.format_bandwidth(
                info['observed_bandwidth'])),
            ('Average BW', tor_network_status.format_bandwidth(
                info['average_bandwidth'])),
            ('Burst BW', tor_network_status.format_bandwidth(
                info['burst_bandwidth'])),
            ('Uptime', tor_network_status.format_uptime(info['uptime'])),
            ('Running Since', info.get('running_since', '') or 'N/A'),
            ('Platform', info['platform'] or 'N/A'),
            ('Last Published', info['published'] or 'N/A'),
            ('Contact', info['contact'] or 'N/A'),
            ('Exit Policy', '<small>%s</small>' % (
                info['exit_policy'][:300] if info['exit_policy'] else 'N/A')),
        ]
        for k, v in rows:
            html += '<tr><td><b>%s:</b></td><td>%s</td></tr>' % (k, v)
        html += '</table>'
        self.node_detail_browser.setText(html)

    def _add_node_to_layer(self, layer):
        ## Collect fingerprints: selected rows in table + current detail node
        fps_to_add = []
        selected_rows = self.nodes_table.selectionModel().selectedRows()
        if selected_rows:
            for idx in selected_rows:
                source_idx = self._relay_proxy.mapToSource(
                    self._relay_proxy.index(
                        idx.row(), RelayTableModel.COL_FP))
                fp = self._relay_model.data(source_idx, Qt.UserRole)
                if fp:
                    fps_to_add.append(fp)
        elif self._current_node_fp:
            fps_to_add.append(self._current_node_fp)

        if not fps_to_add:
            return
        if not self.strict_nodes_check.isChecked():
            self._nd_notify_label.setStyleSheet(
                'font-weight: bold; color: #d32f2f;')
            self._nd_notify_label.setText(
                '\u26a0 Enable "Strict Nodes" in Circuit Config tab first '
                'to use custom node selection.')
            return
        w = self._layer_widgets.get(layer)
        if not w:
            return
        fp_list = w['fp_list']
        added = 0
        skipped = 0
        for fp in fps_to_add:
            ## Check duplicate
            dup = False
            for i in range(fp_list.count()):
                if fp_list.item(i).data(QtCore.Qt.UserRole) == fp:
                    dup = True
                    break
            if dup:
                skipped += 1
                continue
            nick = ''
            if self.network_data:
                for r in self.network_data['relays']:
                    if r['fingerprint'] == fp:
                        nick = r['nickname']
                        break
            item = QtWidgets.QListWidgetItem(
                '%s (%s...)' % (nick, fp[:8]) if nick else fp[:16] + '...')
            item.setToolTip(fp)
            item.setData(QtCore.Qt.UserRole, fp)
            fp_list.addItem(item)
            added += 1

        ## Auto-expand the layer block
        grp = w.get('group')
        if grp and not grp.isChecked():
            grp.setChecked(True)

        ## Show bottom Apply button
        self.bottom_apply_btn.setVisible(True)

        layer_names = {'entry': 'Entry', 'middle': 'Middle', 'exit': 'Exit'}
        if added > 0:
            self._nd_notify_label.setStyleSheet(
                'font-weight: bold; color: #2E7D32;')
            msg = '\u2714 Added %d node(s) to %s list.' % (
                added, layer_names.get(layer, layer))
            if skipped:
                msg += ' (%d already in list)' % skipped
            self._nd_notify_label.setText(msg)
        else:
            self._nd_notify_label.setStyleSheet(
                'font-weight: bold; color: #FF8F00;')
            self._nd_notify_label.setText(
                'All selected nodes already in %s list.' % layer)

    ## -- Country combos for circuit config --

    def _populate_country_combos(self, data):
        all_cc = sorted(data['countries'].keys())
        guard_cc = sorted(data.get('guard_countries', {}).keys())
        exit_cc = sorted(data.get('exit_countries', {}).keys())

        combos_to_fill = {
            'entry': (guard_cc, data.get('guard_countries', {})),
            'middle': (all_cc, data['countries']),
            'exit': (exit_cc, data.get('exit_countries', {})),
        }
        for layer, (cc_list, counts) in combos_to_fill.items():
            combo = self._layer_widgets[layer]['country']
            combo.clear()
            combo.addItem('Any country')
            for cc in cc_list:
                label = '%s (%d)' % (
                    tor_network_status.country_label(cc), counts.get(cc, 0))
                combo.addItem(label, cc)

        self.exclude_add_combo.clear()
        self.exclude_add_combo.addItem('Select country...')
        for cc in all_cc:
            label = '%s (%d)' % (
                tor_network_status.country_label(cc), data['countries'][cc])
            self.exclude_add_combo.addItem(label, cc)

    ## -- Per-layer helpers --

    def _add_country_to_list(self, combo, listw):
        idx = combo.currentIndex()
        if idx <= 0:
            return
        cc = combo.currentData()
        if not cc:
            return
        for i in range(listw.count()):
            if listw.item(i).data(QtCore.Qt.UserRole) == cc:
                return
        item = QtWidgets.QListWidgetItem(combo.currentText())
        item.setData(QtCore.Qt.UserRole, cc)
        listw.addItem(item)

    def _add_fp_to_list(self, edit, listw):
        ## Be forgiving: strip $, spaces, 0x prefix
        raw = edit.text().strip().upper()
        raw = raw.lstrip('$').replace(' ', '').replace('0X', '')
        ## Also handle "nickname ($fp)" format
        if '(' in raw and ')' in raw:
            raw = raw.split('(')[-1].rstrip(')')
        fp = raw[:40]
        if len(fp) != 40 or not all(c in '0123456789ABCDEF' for c in fp):
            edit.setStyleSheet('border: 1px solid red;')
            edit.setPlaceholderText('Invalid — need 40 hex chars, got %d' % len(fp))
            QtCore.QTimer.singleShot(2000, lambda: (
                edit.setStyleSheet(''),
                edit.setPlaceholderText('Paste relay fingerprint (40 hex chars)')))
            return
        for i in range(listw.count()):
            if listw.item(i).data(QtCore.Qt.UserRole) == fp:
                edit.clear()
                return
        nick = ''
        if self.network_data:
            for r in self.network_data['relays']:
                if r['fingerprint'] == fp:
                    nick = r['nickname']
                    break
        item = QtWidgets.QListWidgetItem(
            '%s (%s...)' % (nick, fp[:8]) if nick else fp[:16] + '...')
        item.setToolTip(fp)
        item.setData(QtCore.Qt.UserRole, fp)
        listw.addItem(item)
        edit.clear()

    def _remove_selected(self, listw):
        for item in listw.selectedItems():
            listw.takeItem(listw.row(item))

    ## -- Exclude countries --

    def add_exclude_country(self):
        idx = self.exclude_add_combo.currentIndex()
        if idx <= 0:
            return
        cc = self.exclude_add_combo.currentData()
        if cc:
            for i in range(self.exclude_list.count()):
                if self.exclude_list.item(i).data(QtCore.Qt.UserRole) == cc:
                    return
            item = QtWidgets.QListWidgetItem(
                tor_network_status.country_label(cc))
            item.setData(QtCore.Qt.UserRole, cc)
            self.exclude_list.addItem(item)

    def remove_exclude_country(self):
        for item in self.exclude_list.selectedItems():
            self.exclude_list.takeItem(self.exclude_list.row(item))

    ## -- Exit Proxy auto-management --

    def _exit_proxy_apply_mode(self):
        """Apply the current proxy mode to the running server."""
        if not self._exit_proxy_server:
            return
        mode = 'selective' if self.exit_proxy_mode_selective.isChecked() \
            else 'all'
        self._exit_proxy_server._proxy_mode = mode
        if mode == 'selective':
            domains = set()
            for i in range(self.exit_proxy_bindings_list.count()):
                d = self.exit_proxy_bindings_list.item(i).data(
                    QtCore.Qt.UserRole)
                if d:
                    domains.add(d[0].lower())
            self._exit_proxy_server._selective_domains = domains
        else:
            self._exit_proxy_server._selective_domains = set()

    def _exit_proxy_mode_changed(self, _checked=None):
        """Update the proxy server's mode when radio buttons change."""
        if self._exit_proxy_server and self._exit_proxy_server.running:
            self._exit_proxy_apply_mode()
            mode = self._exit_proxy_server._proxy_mode
            self._panel_log('Proxy mode: %s' % mode)
        self._exit_proxy_save_config()

    def _exit_proxy_toggled(self, checked):
        """Auto-start/stop the exit proxy server when groupbox toggled."""
        if self.is_whonix:
            return
        if checked:
            self._exit_proxy_ensure_running()
        else:
            self._exit_proxy_stop()

    def _get_controller(self):
        """Return an authenticated stem Controller."""
        self._sync_control_settings()
        params = self._get_control_params()
        return tor_network_status.get_controller(**params)

    def _detect_tor_socks(self):
        """Detect the Tor SOCKS address and port."""
        tor_socks_addr = '127.0.0.1'
        tor_socks_port = 9050
        try:
            import stem.control
            ctrl = self._get_controller()
            listeners = ctrl.get_listeners(stem.control.Listener.SOCKS)
            if listeners:
                tor_socks_addr, tor_socks_port = listeners[0]
                tor_socks_port = int(tor_socks_port)
            ctrl.close()
        except Exception:
            pass
        return tor_socks_addr, tor_socks_port

    def _exit_proxy_ensure_running(self):
        """Intercept Tor's SocksPort and start exit proxy on it.

        Flow:
        1. Swap Tor's SocksPort to an internal port via SETCONF
        2. Start our proxy on ALL of Tor's original bindings
        3. Our proxy chains: client → Tor (internal) → exit proxy → dest
        4. All apps automatically go through exit proxies

        For Whonix Workstation (Tor on Gateway):
        1. Start our proxy on a local port
        2. iptables redirects Gateway-bound SOCKS traffic to our proxy
        3. Our proxy connects directly to exit proxies (Whonix routes
           through Tor transparently)
        """
        from tor_control_panel import exit_proxy as ep
        proxies = []
        for i in range(self.exit_proxy_list.count()):
            url = self.exit_proxy_list.item(i).data(QtCore.Qt.UserRole)
            if url:
                proxies.append(url)
        if not proxies:
            self.exit_proxy_status_label.setText(
                '<small style="color:gray">Add proxies and use '
                'Check All to validate</small>')
            return

        ## Security: Strict disable on Whonix
        if self.is_whonix:
            self.exit_proxy_status_label.setText(
                '<span style="color:orange"><b>Disabled:</b> '
                'Exit Proxy feature is disabled on Whonix for security.</span>')
            return

        try:
            if self._exit_proxy_server and self._exit_proxy_server.running:
                self._exit_proxy_server.update_proxies(proxies)
                return

            if ep._WHONIX_WS:
                self._exit_proxy_start_whonix_ws(proxies)
            elif ep._WHONIX_GW:
                self._exit_proxy_start_whonix_gw(proxies)
            else:
                self._exit_proxy_start_intercept(proxies)
        except Exception as e:
            self.exit_proxy_status_label.setText(
                '<span style="color:red"><b>Error:</b> %s</span>' % e)
            self._panel_log('Exit proxy error: %s' % e)

    def _exit_proxy_start_intercept(self, proxies):
        """Non-Whonix-WS: swap Tor's SocksPort and start proxy."""
        from tor_control_panel import exit_proxy as ep

        ## Step 1: Intercept Tor's SocksPort
        intercept = ep.intercept_tor_socks(self._get_controller)
        self._exit_proxy_intercept_state = intercept

        internal_port = intercept['internal_port']
        listen_bindings = [tuple(b) for b in intercept['listen_bindings']]

        ## Step 2: Start proxy on original bindings, using Tor's
        ## new internal port as upstream
        self._exit_proxy_server = ep.ExitProxyServer(
            exit_proxies=proxies,
            listen_bindings=listen_bindings,
            tor_socks_addr='127.0.0.1',
            tor_socks_port=internal_port,
            is_whonix=False)
        self._exit_proxy_server._domain_rotation = \
            self.exit_proxy_domain_rotation_cb.isChecked()

        ## Apply domain bindings
        bindings = {}
        for i in range(self.exit_proxy_bindings_list.count()):
            d = self.exit_proxy_bindings_list.item(i).data(
                QtCore.Qt.UserRole)
            if d:
                bindings[d[0]] = d[1]
        if bindings:
            self._exit_proxy_server.set_domain_bindings(bindings)

        ## Apply proxy mode (all / selective)
        self._exit_proxy_apply_mode()

        ## Start with retry (server retries bind up to 8 × 0.5s)
        try:
            self._exit_proxy_server.start(wait_ready=True, timeout=10)
        except Exception as e:
            ## CRITICAL: restore Tor's SocksPort if proxy failed
            self._exit_proxy_server = None
            try:
                ep.restore_tor_socks(
                    self._get_controller,
                    intercept['original_conf'])
            except Exception:
                pass
            self._exit_proxy_intercept_state = {}
            raise RuntimeError(
                'Failed to bind proxy on Tor\'s port: %s' % e)

        _mode_str = ('selective' if self.exit_proxy_mode_selective.isChecked()
                     else 'ALL')
        binds_str = ', '.join('%s:%d' % (a, p) for a, p in listen_bindings)
        self.exit_proxy_status_label.setText(
            '<span style="color:green"><b>\u2714 Active — '
            '%s traffic via exit proxies</b></span><br>'
            '<small>Intercepting Tor SocksPort: <b>%s</b><br>'
            'Tor moved to internal port %d. '
            '%d proxies active.</small>'
            % (_mode_str, binds_str, internal_port, len(proxies)))
        self._panel_log(
            'Exit proxy ACTIVE: intercepting %s, '
            'Tor on :%d, %d proxies'
            % (binds_str, internal_port, len(proxies)))

    def _exit_proxy_start_whonix_ws(self, proxies):
        """Whonix Workstation: local proxy + nft redirect."""
        from tor_control_panel import exit_proxy as ep

        ## Detect Gateway's Tor SOCKS for proxy checking
        gw_addr, gw_port = self._detect_tor_socks()

        ## Start proxy on local port (Whonix mode: direct to proxy,
        ## Tor routing handled by Gateway transparently)
        self._exit_proxy_server = ep.ExitProxyServer(
            exit_proxies=proxies,
            tor_socks_addr=gw_addr,
            tor_socks_port=gw_port,
            is_whonix=True)
        self._exit_proxy_server._domain_rotation = \
            self.exit_proxy_domain_rotation_cb.isChecked()

        ## Apply domain bindings
        bindings = {}
        for i in range(self.exit_proxy_bindings_list.count()):
            d = self.exit_proxy_bindings_list.item(i).data(
                QtCore.Qt.UserRole)
            if d:
                bindings[d[0]] = d[1]
        if bindings:
            self._exit_proxy_server.set_domain_bindings(bindings)

        ## Apply proxy mode (all / selective)
        self._exit_proxy_apply_mode()

        try:
            self._exit_proxy_server.start()
        except Exception as e:
            self.exit_proxy_status_label.setText(
                '<span style="color:red"><b>Error:</b> '
                'Proxy failed to start: %s</span>' % e)
            return

        local_port = self._exit_proxy_server.local_port

        ## nft redirect: Gateway SOCKS → local proxy
        try:
            rules = ep.intercept_whonix_ws(
                local_port, self._get_controller)
            if rules:
                rstr = ', '.join('%s:%d' % (a, p) for a, p in rules)
                self.exit_proxy_status_label.setText(
                    '<span style="color:green"><b>\u2714 Active — '
                    'ALL traffic via exit proxies</b></span><br>'
                    '<small>nft redirect: %s → local:%d<br>'
                    '%d proxies active (Whonix WS mode).</small>'
                    % (rstr, local_port, len(proxies)))
                self._panel_log(
                    'Exit proxy ACTIVE (Whonix WS): redirect %s → :%d, '
                    '%d proxies' % (rstr, local_port, len(proxies)))
            else:
                self.exit_proxy_status_label.setText(
                    '<span style="color:orange"><b>\u26a0 Partial</b>'
                    '</span><br>'
                    '<small>Proxy on 127.0.0.1:%d but nft '
                    'redirect failed. Set browser SOCKS5 proxy to '
                    '<b>127.0.0.1:%d</b> manually.</small>'
                    % (local_port, local_port))
        except Exception as e:
            self.exit_proxy_status_label.setText(
                '<span style="color:orange"><b>\u26a0 Partial</b>'
                '</span><br>'
                '<small>Proxy on 127.0.0.1:%d but nft failed: %s'
                '<br>Set browser SOCKS5 proxy to '
                '<b>127.0.0.1:%d</b> manually.</small>'
                % (local_port, e, local_port))

    def _exit_proxy_start_whonix_gw(self, proxies):
        """Whonix Gateway: proxy + nft redirect.

        Uses nftables to redirect Workstation SOCKS traffic from Tor's
        ports to our proxy.  Tor's config is NOT modified — stream
        isolation and all system services are preserved.

        Order: first add nft redirect rules, THEN start the proxy.
        This avoids binding on ports that are still in use.
        """
        from tor_control_panel import exit_proxy as ep

        ## Step 1: Add nft redirect rules and find a free proxy port.
        ## intercept_whonix_gw() detects Tor's external SOCKS listeners,
        ## finds a port free on all addresses, and inserts nft rules.
        try:
            state = ep.intercept_whonix_gw(self._get_controller)
        except Exception as e:
            self.exit_proxy_status_label.setText(
                '<span style="color:red"><b>Error:</b> %s</span><br>'
                '<small>Firewall rules could not be added.<br>'
                'Ensure <b>tor-control-panel</b> package is installed correctly.</small>' % e)
            self._panel_log(
                'Exit proxy (Whonix GW) firewall failed: %s' % e)
            return

        self._exit_proxy_intercept_state = state
        proxy_port = state['proxy_port']
        listen_bindings = [tuple(b) for b in state['listen_bindings']]

        ## Step 2: Start proxy on the listen bindings.
        ## Use localhost Tor SOCKS as upstream — the GW firewall allows
        ## local connections to Tor but blocks direct outbound for the
        ## user account.
        _tor_addr, _tor_port = self._detect_tor_socks()
        self._exit_proxy_server = ep.ExitProxyServer(
            exit_proxies=proxies,
            listen_bindings=listen_bindings,
            tor_socks_addr='127.0.0.1',
            tor_socks_port=_tor_port,
            is_whonix=False)
        self._exit_proxy_server._domain_rotation = \
            self.exit_proxy_domain_rotation_cb.isChecked()

        ## Apply domain bindings
        bindings = {}
        for i in range(self.exit_proxy_bindings_list.count()):
            d = self.exit_proxy_bindings_list.item(i).data(
                QtCore.Qt.UserRole)
            if d:
                bindings[d[0]] = d[1]
        if bindings:
            self._exit_proxy_server.set_domain_bindings(bindings)
        self._exit_proxy_apply_mode()

        try:
            self._exit_proxy_server.start()
        except Exception as e:
            ## Proxy failed to start — remove nft rules
            ep.restore_whonix_gw()
            self._exit_proxy_intercept_state = {}
            self.exit_proxy_status_label.setText(
                '<span style="color:red"><b>Error:</b> '
                'Proxy failed to start: %s</span>' % e)
            self._panel_log(
                'Exit proxy (Whonix GW) start failed: %s' % e)
            return

        ports_str = ', '.join(str(p) for p in state['ext_ports'])
        self.exit_proxy_status_label.setText(
            '<span style="color:green"><b>\u2714 Active — '
            'ALL Workstation traffic via exit proxies</b></span><br>'
            '<small>nft redirect: ports %s → :%d<br>'
            '%d proxies active (Whonix GW mode, '
            'interface: %s).</small>'
            % (ports_str, proxy_port, len(proxies),
               state['int_if']))
        self._panel_log(
            'Exit proxy ACTIVE (Whonix GW): nft redirect '
            'ports [%s] → :%d, %d proxies, if=%s'
            % (ports_str, proxy_port, len(proxies),
               state['int_if']))

    def _exit_proxy_stop(self):
        """Stop the exit proxy server and restore Tor's SocksPort."""
        ## Exit Proxy is disabled on Whonix
        if self.is_whonix:
            return

        from tor_control_panel import exit_proxy as ep

        if self._exit_proxy_server:
            self._exit_proxy_server.stop()
            self._exit_proxy_server = None

        ## Restore original config / remove redirect rules
        try:
            original = getattr(self, '_exit_proxy_intercept_state', {})
            if original.get('whonix_gw'):
                ep.restore_whonix_gw()
                self._panel_log('Whonix GW iptables rules removed')
            elif original.get('original_conf'):
                ep.restore_tor_socks(
                    self._get_controller,
                    original['original_conf'])
                self._panel_log(
                    'Tor SocksPort restored: %s'
                    % original['original_conf'])
            elif ep._WHONIX_WS:
                ep.restore_whonix_ws()
                self._panel_log('Whonix WS iptables rules removed')
            elif ep._WHONIX_GW:
                ep.restore_whonix_gw()
            else:
                ## Try crash recovery restore
                ep.restore_tor_socks(self._get_controller)
        except Exception as e:
            self._panel_log('Restore error: %s' % e)

        self._exit_proxy_intercept_state = {}
        self.exit_proxy_status_label.setText('')
        self._panel_log('Exit proxy stopped')

    def _exit_proxy_check_all(self):
        """Check all proxies in the list — validate through Tor."""
        if self.is_whonix:
            return
        from tor_control_panel import exit_proxy as ep
        proxies = []
        for i in range(self.exit_proxy_list.count()):
            url = self.exit_proxy_list.item(i).data(QtCore.Qt.UserRole)
            if url:
                proxies.append(url)
        if not proxies:
            self.exit_proxy_check_label.setText(
                '<span style="color:red">No proxies to check</span>')
            return
        ## Use internal port if intercepted, otherwise detect normally
        intercept = getattr(self, '_exit_proxy_intercept_state', {})
        if intercept.get('internal_port'):
            tor_socks_addr = '127.0.0.1'
            tor_socks_port = intercept['internal_port']
        else:
            tor_socks_addr, tor_socks_port = self._detect_tor_socks()

        ## Reset all items to "checking" state
        for i in range(self.exit_proxy_list.count()):
            item = self.exit_proxy_list.item(i)
            url = item.data(QtCore.Qt.UserRole)
            item.setText('\u23f3 %s' % url)
            item.setBackground(QtGui.QColor(255, 255, 230))
            item.setData(QtCore.Qt.UserRole + 1, None)

        self._check_alive_count = 0
        self._check_dead_count = 0
        self.exit_proxy_check_btn.setEnabled(False)
        self.exit_proxy_check_btn.setText(
            '\u23f3 0/%d' % len(proxies))
        self.exit_proxy_check_label.setText(
            'Checking %d proxies through Tor...' % len(proxies))

        class _CheckThread(QtCore.QThread):
            result_ready = QtCore.pyqtSignal(list)
            progress = QtCore.pyqtSignal(int, int, dict)

            def __init__(self, urls, addr, port, timeout, conc,
                         is_whonix=False):
                super().__init__()
                self.urls = urls
                self.addr = addr
                self.port = port
                self.timeout = timeout
                self.conc = conc
                self.is_whonix = is_whonix

            def run(self):
                def _cb(done, total, res):
                    self.progress.emit(done, total, res)
                results = ep.check_proxies_sync(
                    self.urls, self.addr, self.port,
                    is_whonix=self.is_whonix,
                    timeout=self.timeout, concurrency=self.conc,
                    progress_cb=_cb)
                self.result_ready.emit(results)

        timeout = self.exit_proxy_timeout_spin.value()
        conc = self.exit_proxy_threads_spin.value()
        self._proxy_checker_thread = _CheckThread(
            proxies, tor_socks_addr, tor_socks_port, timeout, conc,
            is_whonix=ep._WHONIX_WS)
        self._proxy_checker_thread.progress.connect(
            self._exit_proxy_check_progress)
        self._proxy_checker_thread.result_ready.connect(
            self._exit_proxy_check_done)
        ## Temporarily enable fast circuit refresh during proxy checks
        ## so check connections are visible in the circuit view
        self._pre_check_circ_timer_active = self._circ_timer.isActive()
        if not self._circ_timer.isActive():
            self._circ_timer.start(1500)
        self._proxy_checker_thread.start()

    def _exit_proxy_check_progress(self, done, total, res):
        """Update each proxy item in real-time as results arrive."""
        url = res.get('url', '')
        show_ip = self.exit_proxy_autocheck_ip.isChecked()
        ## Find the matching list item and update it immediately
        for i in range(self.exit_proxy_list.count()):
            item = self.exit_proxy_list.item(i)
            if item.data(QtCore.Qt.UserRole) == url:
                if res.get('alive'):
                    self._check_alive_count += 1
                    if show_ip and res.get('exit_ip'):
                        item.setText(
                            '\u2714 %s  \u2192  IP: %s  (%dms)' % (
                                url, res['exit_ip'],
                                res['latency_ms']))
                    else:
                        item.setText('\u2714 %s  (%dms)' % (
                            url, res['latency_ms']))
                    item.setBackground(QtGui.QColor(200, 255, 200))
                    item.setData(QtCore.Qt.UserRole + 1, True)
                else:
                    self._check_dead_count += 1
                    err = res.get('error', '?')
                    item.setText('\u2716 %s  [%s]' % (url, err))
                    item.setBackground(QtGui.QColor(255, 200, 200))
                    item.setData(QtCore.Qt.UserRole + 1, False)
                break
        alive = self._check_alive_count
        dead = self._check_dead_count
        self.exit_proxy_check_btn.setText(
            '\u23f3 %d/%d' % (done, total))
        self.exit_proxy_check_label.setText(
            '<b style="color:green">%d alive</b>, '
            '<span style="color:red">%d dead</span>, '
            '%d remaining' % (alive, dead, total - done))

    def _exit_proxy_check_done(self, results):
        self.exit_proxy_check_btn.setEnabled(True)
        self.exit_proxy_check_btn.setText('\u2714 Check All')
        self._proxy_checker_thread = None
        ## Restore circuit refresh timer state from before check
        if not getattr(self, '_pre_check_circ_timer_active', False):
            self._circ_timer.stop()
        alive = sum(1 for r in results if r['alive'])
        dead = len(results) - alive
        self.exit_proxy_check_label.setText(
            '<b>Done:</b> <b style="color:green">%d alive</b>, '
            '<span style="color:red">%d dead</span> out of %d' %
            (alive, dead, len(results)))
        self._panel_log('Proxy check: %d alive, %d dead' % (alive, dead))
        ## Feed results into running server's health tracker
        if self._exit_proxy_server and self._exit_proxy_server.running:
            for r in results:
                url = r.get('url', '')
                if r.get('alive'):
                    self._exit_proxy_server.report_proxy_success(url)
                else:
                    ## Mark as dead immediately (check is authoritative)
                    for _ in range(self._exit_proxy_server._dead_threshold):
                        self._exit_proxy_server.report_proxy_failure(url)
        ## Auto-remove dead proxies if enabled
        if getattr(self, '_exit_proxy_auto_remove_dead', False) and dead > 0:
            self._exit_proxy_remove_dead()
            self._panel_log('Auto-removed %d dead proxies' % dead)
        ## Auto-restart server with updated proxy list if active
        if self.exit_proxy_grp.isChecked():
            self._exit_proxy_ensure_running()
        ## Auto-save
        self._exit_proxy_save_config()

    def _exit_proxy_sync_server(self):
        """Sync the running server's proxy list and mode from the UI."""
        if not self._exit_proxy_server or \
           not self._exit_proxy_server.running:
            return
        proxies = []
        for i in range(self.exit_proxy_list.count()):
            url = self.exit_proxy_list.item(i).data(QtCore.Qt.UserRole)
            if url:
                proxies.append(url)
        if proxies:
            self._exit_proxy_server.update_proxies(proxies)
        else:
            ## No proxies left — stop the server
            self._exit_proxy_stop()
            return
        ## Sync proxy mode
        mode = 'selective' if self.exit_proxy_mode_selective.isChecked() \
            else 'all'
        self._exit_proxy_server._proxy_mode = mode
        if mode == 'selective':
            domains = set()
            for i in range(self.exit_proxy_bindings_list.count()):
                d = self.exit_proxy_bindings_list.item(i).data(
                    QtCore.Qt.UserRole)
                if d:
                    domains.add(d[0].lower())
            self._exit_proxy_server._selective_domains = domains
        else:
            self._exit_proxy_server._selective_domains = set()

    def _exit_proxy_remove_selected(self):
        """Remove selected proxies from the list and save."""
        self._remove_selected(self.exit_proxy_list)
        self._exit_proxy_sync_server()
        self._exit_proxy_save_config()

    def _exit_proxy_clear_all(self):
        """Clear all proxies and save."""
        self.exit_proxy_list.clear()
        self._exit_proxy_stop()
        self._exit_proxy_save_config()

    def _exit_proxy_toggle_domain_rotation(self, enabled):
        """Enable/disable domain rotation on the running server."""
        if self._exit_proxy_server and self._exit_proxy_server.running:
            self._exit_proxy_server._domain_rotation = enabled
        self._exit_proxy_save_config()

    def _exit_proxy_toggle_auto_recheck(self, enabled):
        """Start/stop the periodic auto-recheck timer."""
        if enabled:
            mins = self.exit_proxy_recheck_interval.value()
            self._exit_proxy_recheck_timer.start(mins * 60 * 1000)
            self._panel_log('Auto-recheck enabled: every %d min' % mins)
        else:
            self._exit_proxy_recheck_timer.stop()
            self._panel_log('Auto-recheck disabled')

    def _exit_proxy_update_recheck_interval(self, mins):
        """Update the recheck timer interval if running."""
        if self._exit_proxy_recheck_timer.isActive():
            self._exit_proxy_recheck_timer.start(mins * 60 * 1000)

    def _exit_proxy_auto_recheck_tick(self):
        """Called by the timer — trigger a proxy check if not already
        running and the exit proxy is active."""
        if self._proxy_checker_thread is not None:
            return  # already checking
        if not self.exit_proxy_grp.isChecked():
            return  # proxy not active
        if self.exit_proxy_list.count() == 0:
            return
        self._panel_log('Auto-recheck: starting periodic proxy check')
        self._exit_proxy_check_all()

    def _exit_proxy_remove_dead(self):
        """Remove proxies marked as dead after a check."""
        to_remove = []
        for i in range(self.exit_proxy_list.count()):
            item = self.exit_proxy_list.item(i)
            alive = item.data(QtCore.Qt.UserRole + 1)
            if alive is False:  # explicitly marked dead
                to_remove.append(i)
        if not to_remove:
            self.exit_proxy_check_label.setText(
                '<span style="color:gray">No dead proxies to remove '
                '(run Check All first)</span>')
            return
        for i in reversed(to_remove):
            self.exit_proxy_list.takeItem(i)
        self.exit_proxy_check_label.setText(
            'Removed %d dead proxies' % len(to_remove))
        self._exit_proxy_sync_server()
        self._exit_proxy_save_config()

    def _exit_proxy_health_check(self):
        """Periodic health check: remove proxies that died during live
        traffic (detected by the server's health tracker)."""
        if not self._exit_proxy_auto_remove_dead:
            return
        if not self._exit_proxy_server or \
                not self._exit_proxy_server.running:
            return
        dead_proxies = self._exit_proxy_server.get_dead_proxies()
        if not dead_proxies:
            return
        dead_urls = set(
            px.get('display', '') for px in dead_proxies)
        removed = 0
        for i in reversed(range(self.exit_proxy_list.count())):
            item = self.exit_proxy_list.item(i)
            url = item.data(QtCore.Qt.UserRole)
            if url in dead_urls:
                self.exit_proxy_list.takeItem(i)
                removed += 1
        if removed:
            self._panel_log(
                'Auto-removed %d dead proxies (live traffic)' % removed)
            self._exit_proxy_sync_server()
            self._exit_proxy_save_config()

    def _exit_proxy_add_binding(self):
        """Add a domain→proxy binding."""
        domain = self.exit_proxy_bind_domain.text().strip().lower()
        proxy = self.exit_proxy_bind_proxy.text().strip()
        if not domain or not proxy:
            return
        ## Check for duplicates
        for i in range(self.exit_proxy_bindings_list.count()):
            d = self.exit_proxy_bindings_list.item(i).data(
                QtCore.Qt.UserRole)
            if d and d[0] == domain:
                self.exit_proxy_bindings_list.item(i).setText(
                    '%s → %s' % (domain, proxy))
                self.exit_proxy_bindings_list.item(i).setData(
                    QtCore.Qt.UserRole, (domain, proxy))
                self.exit_proxy_bind_domain.clear()
                self.exit_proxy_bind_proxy.clear()
                return
        item = QtWidgets.QListWidgetItem('%s → %s' % (domain, proxy))
        item.setData(QtCore.Qt.UserRole, (domain, proxy))
        self.exit_proxy_bindings_list.addItem(item)
        self.exit_proxy_bind_domain.clear()
        self.exit_proxy_bind_proxy.clear()
        ## If server is running, update bindings live
        if self._exit_proxy_server and self._exit_proxy_server.running:
            bindings = {}
            for i in range(self.exit_proxy_bindings_list.count()):
                d = self.exit_proxy_bindings_list.item(i).data(
                    QtCore.Qt.UserRole)
                if d:
                    bindings[d[0]] = d[1]
            self._exit_proxy_server.set_domain_bindings(bindings)

    def _exit_proxy_verify_ip(self):
        """Verify exit IP through the running exit proxy server."""
        from tor_control_panel import exit_proxy as ep
        if not self._exit_proxy_server or not self._exit_proxy_server.running:
            ## Auto-start if groupbox is checked
            if self.exit_proxy_grp.isChecked():
                self._exit_proxy_ensure_running()
            if not self._exit_proxy_server or \
               not self._exit_proxy_server.running:
                self.exit_proxy_check_label.setText(
                    '<span style="color:red">No proxies active — '
                    'add proxies first</span>')
                return
        port = self._exit_proxy_server.local_port
        self.exit_proxy_verify_btn.setEnabled(False)
        self.exit_proxy_verify_btn.setText('\u23f3 ...')
        self.exit_proxy_check_label.setText(
            'Verifying exit IP through 127.0.0.1:%d ...' % port)

        class _VerifyThread(QtCore.QThread):
            result_ready = QtCore.pyqtSignal(str, str)
            def __init__(self, p):
                super().__init__()
                self._port = p
            def run(self):
                try:
                    ip, lat = ep.verify_exit_ip_sync(self._port, timeout=30)
                    self.result_ready.emit(ip, '%dms' % lat)
                except Exception as e:
                    self.result_ready.emit('', str(e))

        self._verify_thread = _VerifyThread(port)
        self._verify_thread.result_ready.connect(
            self._exit_proxy_verify_done)
        self._verify_thread.start()

    def _exit_proxy_verify_done(self, ip, info):
        self.exit_proxy_verify_btn.setEnabled(True)
        self.exit_proxy_verify_btn.setText('\u26a1 Verify IP')
        if ip:
            self.exit_proxy_check_label.setText(
                '<b style="color:green">Exit IP: %s</b> (%s) — '
                'this is the IP the destination sees' % (ip, info))
            self._panel_log('Exit proxy verified: exit IP = %s (%s)' %
                            (ip, info))
        else:
            self.exit_proxy_check_label.setText(
                '<span style="color:red">Verify failed: %s</span>' % info)
            self._panel_log('Exit proxy verify failed: %s' % info)

    def _exit_proxy_auto_bind(self):
        """Auto-bind domains from the binding list to alive proxies."""
        from tor_control_panel import exit_proxy as ep
        ## Collect alive proxy URLs
        alive_urls = []
        for i in range(self.exit_proxy_list.count()):
            item = self.exit_proxy_list.item(i)
            alive = item.data(QtCore.Qt.UserRole + 1)
            if alive is True:
                alive_urls.append(item.data(QtCore.Qt.UserRole))
        if not alive_urls:
            ## Fall back to all proxies
            for i in range(self.exit_proxy_list.count()):
                url = self.exit_proxy_list.item(i).data(QtCore.Qt.UserRole)
                if url:
                    alive_urls.append(url)
        if not alive_urls:
            self.exit_proxy_check_label.setText(
                '<span style="color:red">No proxies available</span>')
            return
        ## Collect domains from binding list
        domains = []
        for i in range(self.exit_proxy_bindings_list.count()):
            d = self.exit_proxy_bindings_list.item(i).data(
                QtCore.Qt.UserRole)
            if d:
                domains.append(d[0])
        if not domains:
            ## Use some common defaults if no domains listed
            domains = ['google.com', 'youtube.com', 'github.com',
                       'reddit.com', 'twitter.com', 'facebook.com']
        bindings = ep.auto_bind_domains(alive_urls, domains)
        ## Update bindings list
        self.exit_proxy_bindings_list.clear()
        for domain, proxy_url in sorted(bindings.items()):
            item = QtWidgets.QListWidgetItem(
                '%s \u2192 %s' % (domain, proxy_url))
            item.setData(QtCore.Qt.UserRole, (domain, proxy_url))
            self.exit_proxy_bindings_list.addItem(item)
        self.exit_proxy_check_label.setText(
            'Auto-bound %d domains to %d proxies' %
            (len(bindings), len(alive_urls)))
        ## Update running server
        if self._exit_proxy_server and self._exit_proxy_server.running:
            self._exit_proxy_server.set_domain_bindings(bindings)

    def _toggle_fast_spins(self, checked):
        """Mark config dirty when Prefer Fastest toggled."""
        self._mark_config_dirty()

    ## -- Load existing circuit config from Tor --

    def _load_circuit_config(self):
        """Read current EntryNodes/MiddleNodes/ExitNodes/ExcludeNodes/
        StrictNodes from Tor and populate the Circuit Config UI."""
        import re
        self._panel_log('Loading existing circuit config from Tor...')
        try:
            self._sync_control_settings()
            params = self._get_control_params()
            controller = tor_network_status.get_controller(**params)

            layer_map = {
                'entry': 'EntryNodes',
                'middle': 'MiddleNodes',
                'exit': 'ExitNodes',
            }
            for layer, tor_key in layer_map.items():
                try:
                    val = controller.get_conf(tor_key, default='')
                except Exception:
                    val = ''
                if not val:
                    continue
                w = self._layer_widgets[layer]
                parts = [p.strip() for p in val.split(',') if p.strip()]
                cc_re = re.compile(r'^\{([A-Z]{2})\}$')
                fp_re = re.compile(r'^\$?([A-F0-9]{40})', re.IGNORECASE)
                has_items = False
                for part in parts:
                    m_cc = cc_re.match(part)
                    m_fp = fp_re.match(part)
                    if m_cc:
                        cc = m_cc.group(1)
                        ## Check duplicate
                        dup = False
                        for i in range(w['cc_list'].count()):
                            if w['cc_list'].item(i).data(
                                    QtCore.Qt.UserRole) == cc:
                                dup = True
                                break
                        if not dup:
                            label = tor_network_status.country_label(cc)
                            item = QtWidgets.QListWidgetItem(
                                '%s (%s)' % (label, cc) if label != cc
                                else cc)
                            item.setData(QtCore.Qt.UserRole, cc)
                            w['cc_list'].addItem(item)
                            has_items = True
                    elif m_fp:
                        fp = m_fp.group(1).upper()
                        dup = False
                        for i in range(w['fp_list'].count()):
                            if w['fp_list'].item(i).data(
                                    QtCore.Qt.UserRole) == fp:
                                dup = True
                                break
                        if not dup:
                            nick = ''
                            if self.network_data:
                                for r in self.network_data.get(
                                        'relays', []):
                                    if r.get('fingerprint') == fp:
                                        nick = r.get('nickname', '')
                                        break
                            label = ('%s (%s...)' % (nick, fp[:8])
                                     if nick else fp[:16] + '...')
                            item = QtWidgets.QListWidgetItem(label)
                            item.setToolTip(fp)
                            item.setData(QtCore.Qt.UserRole, fp)
                            w['fp_list'].addItem(item)
                            has_items = True
                if has_items:
                    w['group'].setChecked(True)

            ## ExcludeNodes
            try:
                exc_val = controller.get_conf('ExcludeNodes', default='')
            except Exception:
                exc_val = ''
            if exc_val:
                for part in exc_val.split(','):
                    part = part.strip()
                    m = re.match(r'^\{([A-Z]{2})\}$', part)
                    if m:
                        cc = m.group(1)
                        dup = False
                        for i in range(self.exclude_list.count()):
                            if self.exclude_list.item(i).data(
                                    QtCore.Qt.UserRole) == cc:
                                dup = True
                                break
                        if not dup:
                            label = tor_network_status.country_label(cc)
                            item = QtWidgets.QListWidgetItem(
                                '%s (%s)' % (label, cc) if label != cc
                                else cc)
                            item.setData(QtCore.Qt.UserRole, cc)
                            self.exclude_list.addItem(item)

            ## StrictNodes
            try:
                strict = controller.get_conf('StrictNodes', default='0')
            except Exception:
                strict = '0'
            self.strict_nodes_check.setChecked(strict == '1')

            ## NumEntryGuards
            try:
                ng = controller.get_conf('NumEntryGuards', default='3')
                ng_int = int(ng)
            except Exception:
                ng_int = 3
            for idx in range(self.circuit_len_combo.count()):
                if self.circuit_len_combo.itemText(idx).startswith(
                        str(ng_int)):
                    self.circuit_len_combo.setCurrentIndex(idx)
                    break

            controller.close()
            self._panel_log('Circuit config loaded from Tor')
        except Exception as e:
            self._panel_log('Failed to load circuit config: %s' % e)

        ## Reset dirty flag — these are existing settings, not changes
        self._config_dirty = False
        self.bottom_apply_btn.setVisible(False)

    ## -- Config dirty tracking --

    def _mark_config_dirty(self, *args):
        """Show the bottom Apply button whenever Circuit Config has unsaved changes."""
        self._config_dirty = True
        self.bottom_apply_btn.setVisible(True)
        self.bottom_apply_btn.setEnabled(True)
        self.bottom_apply_btn.setStyleSheet(
            'font-weight: bold; background-color: #1976D2; color: white;'
            ' padding: 5px 14px; border-radius: 3px;')

    ## -- Reset helpers --

    def _reset_all_circuit_config(self):
        """Clear ALL nodes, countries, and exclude lists across all layers."""
        for layer in self._layer_widgets:
            w = self._layer_widgets[layer]
            w['cc_list'].clear()
            w['fp_list'].clear()
            w['group'].setChecked(False)
        self.exclude_list.clear()
        self.strict_nodes_check.setChecked(False)
        self.circuit_len_combo.setCurrentIndex(0)
        self.prefer_fastest_check.setChecked(False)
        self._mark_config_dirty()
        self._panel_log('Reset all circuit config (nodes, countries, exclude)')

    def _reset_all_proxy_bindings(self):
        """Clear ALL proxy-domain bindings."""
        self.exit_proxy_bindings_list.clear()
        if self._exit_proxy_server and self._exit_proxy_server.running:
            self._exit_proxy_server.set_domain_bindings({})
        self.exit_proxy_check_label.setText(
            'All proxy-domain bindings cleared')
        self._exit_proxy_save_config()

    ## -- Apply circuit config --

    def _resolve_fastest_nodes(self, countries, layer,
                              nodes_per_country=None):
        """When 'Prefer Fastest' is checked, resolve country codes to
        individual fastest node fingerprints from network_data.
        Returns list of fingerprints (top N fastest per country)."""
        if not self.network_data or not countries:
            return []
        ## Determine required flags per layer
        layer_flags = {
            'entry': {'Guard', 'Running', 'Valid'},
            'middle': {'Running', 'Valid'},
            'exit': {'Exit', 'Running', 'Valid'},
        }
        required = layer_flags.get(layer, {'Running', 'Valid'})
        relays = self.network_data.get('relays', [])
        fps = []
        if nodes_per_country is None:
            ## Default counts per layer (conservative)
            nodes_per_country = {'entry': 2, 'middle': 3, 'exit': 3}.get(
                layer, 3)
        for cc in countries:
            ## Filter relays by country and required flags, sort by bandwidth
            matching = [r for r in relays
                        if r.get('country', '').upper() == cc.upper()
                        and required.issubset(set(r.get('flags', [])))]
            matching.sort(key=lambda r: r.get('bandwidth', 0), reverse=True)
            for r in matching[:nodes_per_country]:
                fp = r.get('fingerprint', '')
                if fp and fp not in fps:
                    fps.append(fp)
        return fps

    def _resolve_fastest_global(self, layer, count):
        """Pick the N fastest nodes globally (no country filter) for a
        given layer.  Returns list of fingerprints."""
        if not self.network_data:
            return []
        layer_flags = {
            'entry': {'Guard', 'Running', 'Valid'},
            'middle': {'Running', 'Valid'},
            'exit': {'Exit', 'Running', 'Valid'},
        }
        required = layer_flags.get(layer, {'Running', 'Valid'})
        relays = self.network_data.get('relays', [])
        matching = [r for r in relays
                    if required.issubset(set(r.get('flags', [])))]
        matching.sort(key=lambda r: r.get('bandwidth', 0), reverse=True)
        fps = []
        for r in matching[:count]:
            fp = r.get('fingerprint', '')
            if fp:
                fps.append(fp)
        return fps

    def apply_circuit_config(self):
        self._panel_log('apply_circuit_config: collecting config...')
        self._sync_control_settings()
        config = {}
        prefer_fast = self.prefer_fastest_check.isChecked()

        ## If Prefer Fastest is checked but network_data not loaded,
        ## auto-load it first (synchronous — small delay)
        if prefer_fast and not self.network_data:
            self._panel_log('Prefer Fast: network_data not loaded, '
                            'fetching now...')
            try:
                params = self._get_control_params()
                fetcher = tor_network_status.TorNetworkFetcher(
                    **params, parent=self)
                fetcher.fetch_done.connect(self._on_fetch_finished)
                fetcher.start()
                fetcher.wait(15000)
                if self.network_data:
                    self._panel_log('Prefer Fast: network_data loaded '
                                    '(%d relays)' % len(
                                        self.network_data.get('relays', [])))
                else:
                    self._panel_log('Prefer Fast: network_data still empty, '
                                    'please load Network tab first')
            except Exception as e:
                self._panel_log('Prefer Fast: fetch error: %s' % e)

        ## Get per-layer spinbox values
        fast_counts = {
            'entry': self.fast_entry_spin.value(),
            'middle': self.fast_middle_spin.value(),
            'exit': self.fast_exit_spin.value(),
        }

        for layer, tor_key_prefix in [
            ('entry', 'entry'), ('middle', 'middle'), ('exit', 'exit')
        ]:
            w = self._layer_widgets[layer]
            ## Collect countries from the list widget
            countries = []
            cc_list = w['cc_list']
            for i in range(cc_list.count()):
                cc = cc_list.item(i).data(QtCore.Qt.UserRole)
                if cc:
                    countries.append(cc)

            fps = []
            for i in range(w['fp_list'].count()):
                fp = w['fp_list'].item(i).data(QtCore.Qt.UserRole)
                if fp:
                    fps.append(fp)

            total_nodes = fast_counts.get(layer, 4)
            if countries:
                ## Distribute total node budget across countries.
                ## E.g. 6 total with 3 countries = 2 per country.
                npc = max(1, total_nodes // len(countries))
                resolved = self._resolve_fastest_nodes(
                    countries, layer, nodes_per_country=npc)
                if resolved:
                    ## Cap to the total requested
                    resolved = resolved[:total_nodes]
                    for f in resolved:
                        if f not in fps:
                            fps.append(f)
                    self._panel_log(
                        '%s layer — resolved %d countries '
                        'to %d nodes (total limit %d, fast=%s)' % (
                            layer, len(countries), len(resolved),
                            total_nodes, prefer_fast))
                else:
                    self._panel_log(
                        '%s layer — no matching nodes, '
                        'using country codes' % layer)
                    config['%s_countries' % tor_key_prefix] = countries
            elif prefer_fast and not countries and not fps:
                ## No countries or nodes selected — pick fastest globally
                fast_fps = self._resolve_fastest_global(
                    layer, total_nodes)
                if fast_fps:
                    fps = fast_fps
                    self._panel_log(
                        'Prefer Fast: %s layer — selected top %d '
                        'fastest nodes globally' % (layer, len(fast_fps)))

            if fps:
                config['%s_fps' % tor_key_prefix] = fps

        exclude = []
        for i in range(self.exclude_list.count()):
            cc = self.exclude_list.item(i).data(QtCore.Qt.UserRole)
            if cc:
                exclude.append(cc)
        if exclude:
            config['exclude_countries'] = exclude

        config['strict_nodes'] = self.strict_nodes_check.isChecked()
        txt = self.circuit_len_combo.currentText()
        for n in [3, 4, 5]:
            if txt.startswith(str(n)):
                config['num_entry_guards'] = n
                break

        ## If fewer entry nodes are specified than NumEntryGuards,
        ## reduce NumEntryGuards so Tor doesn't wait for guards
        ## it can never find (causes circuits to not build).
        entry_fps = config.get('entry_fps', [])
        entry_ccs = config.get('entry_countries', [])
        if entry_fps and not entry_ccs:
            ng = config.get('num_entry_guards', 3)
            if len(entry_fps) < ng:
                config['num_entry_guards'] = len(entry_fps)
                self._panel_log(
                    'Auto-reduced NumEntryGuards to %d (only %d entry '
                    'nodes specified)' % (len(entry_fps), len(entry_fps)))

        self._panel_log('apply_circuit_config: config=%s' % config)
        self.apply_circuit_button.setEnabled(False)
        self.apply_circuit_button.setText('\u23f3 Applying...')
        self.bottom_apply_btn.setEnabled(False)
        self.bottom_apply_btn.setText('\u23f3 Applying...')
        self.bottom_apply_btn.setStyleSheet(
            'font-weight: bold; background-color: #888; color: white;'
            ' padding: 5px 14px; border-radius: 3px;')
        params = self._get_control_params()

        ## Detect the REAL torrc write path from the running Tor instance
        ## (not static dir checks which can point to wrong Tor).
        detected_write_path = torrc_gen.user_path()  # default
        try:
            ctrl = self._get_controller()
            _read, _write = torrc_gen.detect_torrc_write_path(ctrl)
            ctrl.close()
            detected_write_path = _write
            self._panel_log('Detected torrc write path: %s' % _write)
        except Exception as e:
            self._panel_log('torrc detection failed (%s), using default: %s'
                            % (e, detected_write_path))

        self.config_applier = tor_network_status.TorConfigApplier(
            config=config, torrc_path=detected_write_path,
            **params, parent=self)
        self.config_applier.apply_done.connect(self._on_config_applied)
        self.config_applier.log.connect(self._panel_log)
        self.config_applier.start()
        ## Safety timeout: reset button if thread hangs
        self._apply_safety_timer = QtCore.QTimer(self)
        self._apply_safety_timer.setSingleShot(True)
        self._apply_safety_timer.timeout.connect(self._on_apply_timeout)
        self._apply_safety_timer.start(30000)

    def _on_config_applied(self, success, msg):
        self._panel_log('config applied: success=%s msg=%s' % (success, msg))
        if hasattr(self, '_apply_safety_timer'):
            self._apply_safety_timer.stop()
        color = 'green' if success else 'red'
        self.circ_status_label.setText(
            '<span style="color:%s"><b>%s</b></span>' % (color, msg))
        if success:
            self._config_dirty = False
            self.apply_circuit_button.setText('\u2714 Applied!')
            self.apply_circuit_button.setStyleSheet(
                'font-weight: bold; font-size: 13px; color: green;')
            self.bottom_apply_btn.setVisible(False)
            ## Reset button text after 3 seconds
            QtCore.QTimer.singleShot(3000, lambda: (
                self.apply_circuit_button.setText(
                    '\u2714  Apply Configuration'),
                self.apply_circuit_button.setStyleSheet(
                    'font-weight: bold; font-size: 13px;'),
                self.apply_circuit_button.setEnabled(True),
            ))
            ## Auto-refresh circuits after apply so user sees new
            ## circuits being built with the new config
            QtCore.QTimer.singleShot(1500, self.show_current_circuits)
            ## Switch to Circuits tab to show progress
            self.tabs.setCurrentWidget(self.tab6)
            self.circ_auto_check.setChecked(True)
            ## Force-reload Advanced tab values so they reflect new config
            self._adv_values_loaded = False
        else:
            self.apply_circuit_button.setEnabled(True)
            self.apply_circuit_button.setText('\u2714  Apply Configuration')
            self.bottom_apply_btn.setEnabled(True)
            self.bottom_apply_btn.setText('\u2714 Apply Circuit Config')
            self.bottom_apply_btn.setStyleSheet(
                'font-weight: bold; background-color: #1976D2; color: white;'
                ' padding: 5px 14px; border-radius: 3px;')
            QtWidgets.QMessageBox.warning(
                self, 'Circuit Config Error', msg)

    def _on_apply_timeout(self):
        self._panel_log('apply_circuit_config: TIMEOUT (30s) — resetting button')
        ## Disconnect signal so a late reply doesn't corrupt button state
        if hasattr(self, 'config_applier'):
            try:
                self.config_applier.apply_done.disconnect(
                    self._on_config_applied)
            except (TypeError, RuntimeError):
                pass
        self.apply_circuit_button.setEnabled(True)
        self.apply_circuit_button.setText('\u2714  Apply Configuration')
        self.apply_circuit_button.setStyleSheet(
            'font-weight: bold; font-size: 13px;')
        self.bottom_apply_btn.setEnabled(True)
        self.bottom_apply_btn.setText('\u2714 Apply Circuit Config')
        self.bottom_apply_btn.setStyleSheet(
            'font-weight: bold; background-color: #1976D2; color: white;'
            ' padding: 5px 14px; border-radius: 3px;')
        self.circ_status_label.setText(
            '<span style="color:red"><b>Apply timed out — '
            'could not reach Tor controller within 30 seconds.</b></span>')

    ## -- Circuits tab --

    def request_new_circuit(self):
        self._sync_control_settings()
        try:
            from stem import Signal
            c = tor_network_status.get_controller(
                **self._get_control_params())
            c.signal(Signal.NEWNYM)
            c.close()
            self.circ_status_label.setText(
                '<b style="color:green">New circuit requested.</b>')
        except Exception as e:
            self.circ_status_label.setText(
                '<b style="color:red">Error:</b> %s' % e)

    def run_speed_test(self):
        self._sync_control_settings()
        ## Build list of modes to run
        modes = []
        if self.st_mode_standard.isChecked():
            modes.append('standard')
        if self.st_mode_user.isChecked():
            modes.append('user')
        if self.st_mode_fast.isChecked():
            modes.append('fast')
        if not modes:
            self.speed_test_browser.setText(
                '<b style="color:red">Select at least one test mode.</b>')
            return
        self.speed_test_button.setEnabled(False)
        num_per_mode = self.st_count_spin.value()
        self._st_modes_queue = list(modes)
        self._st_num_per_mode = num_per_mode
        self._st_results = {}  # mode -> [results]
        self._st_url = self.st_domain_edit.text().strip()
        total = num_per_mode * len(modes)
        mode_names = {'standard': 'Standard (default Tor)',
                      'user': 'User Config',
                      'fast': 'Prefer Fast'}
        self.speed_test_browser.setText(
            '<b>Speed Test: %d circuits '
            '(%d per mode \u00d7 %d mode%s)</b><br>'
            'Modes: %s' % (
                total, num_per_mode, len(modes),
                's' if len(modes) > 1 else '',
                ', '.join(mode_names.get(m, m) for m in modes)))
        self._run_next_speed_mode()

    def _run_next_speed_mode(self):
        """Run the next speed test mode from the queue."""
        if not self._st_modes_queue:
            ## All modes done — show comparison
            self._show_speed_comparison()
            return
        mode = self._st_modes_queue.pop(0)
        self._st_current_mode = mode
        mode_names = {'standard': 'Standard (default Tor)',
                      'user': 'User Config',
                      'fast': 'Prefer Fast'}
        self.speed_test_browser.append(
            '<br><hr><b>\u25b6 %s</b> — %d circuits...' % (
                mode_names.get(mode, mode), self._st_num_per_mode))
        params = self._get_control_params()
        self.circuit_tester = tor_network_status.TorCircuitTester(
            num_tests=self._st_num_per_mode,
            test_url=self._st_url if self._st_url else '',
            **params, parent=self)
        self.circuit_tester.progress.connect(
            lambda m: self.speed_test_browser.append(
                '<small style="color:#888;">%s</small>' % m))
        self.circuit_tester.result.connect(self._on_speed_mode_result)
        self.circuit_tester.error.connect(self._on_speed_error)
        self.circuit_tester.start()

    def _on_speed_mode_result(self, results):
        """Handle results from one speed test mode, then continue."""
        mode = self._st_current_mode
        self._st_results[mode] = results
        ## Show all completed modes horizontally right away
        remaining = list(self._st_modes_queue)
        self._rebuild_speed_display(remaining)
        ## Continue with next mode
        self._run_next_speed_mode()

    def _rebuild_speed_display(self, pending_modes=None):
        """Rebuild the speed test display with completed modes
        shown as horizontal blocks (side-by-side).
        """
        mode_names = {'standard': 'Standard (default Tor)',
                      'user': 'User Config',
                      'fast': 'Prefer Fast'}
        mode_colors = {'standard': '#E8F5E9', 'user': '#E3F2FD',
                       'fast': '#FFF3E0'}
        mode_border = {'standard': '#66BB6A', 'user': '#42A5F5',
                       'fast': '#FFA726'}
        style = ('<style>.st{border-collapse:collapse;width:100%;} '
                 '.st th,.st td{border:1px solid #ddd;padding:3px;'
                 'font-size:10px;} .st th{background:#e8e8e8;}</style>')
        html = style

        n_cols = len(self._st_results) + len(pending_modes or [])
        col_w = max(30, 95 // max(n_cols, 1))
        html += ('<table cellspacing="4" cellpadding="0" '
                 'style="width:100%;table-layout:fixed;">'
                 '<tr valign="top">')
        for mode, results in self._st_results.items():
            bg = mode_colors.get(mode, '#F5F5F5')
            bdr = mode_border.get(mode, '#BDBDBD')
            html += ('<td style="vertical-align:top;width:%d%%;'
                     'padding:3px;">'
                     '<div style="background:%s;border:1px solid %s;'
                     'border-radius:6px;padding:6px;'
                     'overflow:hidden;">'
                     % (col_w, bg, bdr))
            if not results:
                html += ('<b>%s</b><br><i>no results</i>'
                         % mode_names.get(mode, mode))
                html += '</div></td>'
                continue
            results.sort(key=lambda r: r.get('real_speed_kbs', 0),
                         reverse=True)
            avg_spd = (sum(r.get('real_speed_kbs', 0) for r in results)
                       / len(results))
            avg_lat = (sum(r.get('latency_ms', 0) for r in results)
                       / len(results))
            html += ('<b style="font-size:10px;">%s</b><br>'
                     '<span style="font-size:9px;">avg: <b>%s</b>, '
                     '%d ms</span><br>' % (
                         mode_names.get(mode, mode),
                         self._fmt_speed(avg_spd), int(avg_lat)))
            html += '<table class="st">'
            html += ('<tr><th>#</th><th>Path</th><th>Speed</th>'
                     '<th>TTFB</th></tr>')
            for i, r in enumerate(results):
                path = ' \u2192 '.join(
                    '%s [%s]' % (n['nickname'], n['country'])
                    for n in r['path'])
                row_bg = '#c8e6c9' if i == 0 else ''
                html += ('<tr style="background:%s">'
                         '<td>%d</td><td style="font-size:9px;">%s</td>'
                         '<td><b>%s</b></td><td>%d ms</td>'
                         '</tr>' % (
                             row_bg, i + 1, path,
                             self._fmt_speed(r.get('real_speed_kbs', 0)),
                             r.get('latency_ms', 0)))
            html += '</table></div></td>'
        ## Show pending modes as gray placeholders
        for pm in (pending_modes or []):
            html += ('<td style="vertical-align:top;width:%d%%;'
                     'padding:3px;">'
                     '<div style="background:#f0f0f0;border:1px dashed '
                     '#bbb;border-radius:6px;padding:10px;'
                     'text-align:center;min-height:60px;">'
                     '<b style="font-size:10px;color:#999;">'
                     '\u23f3 %s</b><br>'
                     '<i style="color:#aaa;font-size:9px;">'
                     'pending...</i></div></td>'
                     % (col_w, mode_names.get(pm, pm)))
        html += '</tr></table>'
        self.speed_test_browser.setText(html)

    def _show_speed_comparison(self):
        """Show final comparison of all speed test modes."""
        self.speed_test_button.setEnabled(True)
        mode_names = {'standard': 'Standard (default Tor)',
                      'user': 'User Config',
                      'fast': 'Prefer Fast'}

        ## Reuse the horizontal block display (no pending modes)
        self._rebuild_speed_display(pending_modes=None)

        ## Append comparison summary below the blocks
        if len(self._st_results) > 1:
            summary = ('<br><hr><b>\u2605 Comparison Summary</b><br>'
                       '<table style="border-collapse:collapse;'
                       'width:100%;"><tr>'
                       '<th style="border:1px solid #ddd;padding:3px;'
                       'font-size:10px;background:#e8e8e8;">Mode</th>'
                       '<th style="border:1px solid #ddd;padding:3px;'
                       'font-size:10px;background:#e8e8e8;">Avg Speed</th>'
                       '<th style="border:1px solid #ddd;padding:3px;'
                       'font-size:10px;background:#e8e8e8;">Avg Latency</th>'
                       '<th style="border:1px solid #ddd;padding:3px;'
                       'font-size:10px;background:#e8e8e8;">Best</th></tr>')
            best_mode = None
            best_avg = 0
            for mode, results in self._st_results.items():
                if not results:
                    summary += ('<tr><td style="border:1px solid #ddd;'
                                'padding:3px;font-size:10px;">%s</td>'
                                '<td colspan="3" style="border:1px solid '
                                '#ddd;padding:3px;font-size:10px;">'
                                '<i>no data</i></td></tr>'
                                % mode_names.get(mode, mode))
                    continue
                avg_s = (sum(r.get('real_speed_kbs', 0) for r in results)
                         / len(results))
                avg_l = (sum(r.get('latency_ms', 0) for r in results)
                         / len(results))
                best_r = results[0]
                best_path = ' \u2192 '.join(
                    n['nickname'] for n in best_r['path'])
                if avg_s > best_avg:
                    best_avg = avg_s
                    best_mode = mode
                _td = ('style="border:1px solid #ddd;padding:3px;'
                       'font-size:10px;"')
                summary += ('<tr><td %s><b>%s</b></td>'
                            '<td %s>%s</td><td %s>%d ms</td>'
                            '<td %s>%s (%s)</td></tr>' % (
                                _td, mode_names.get(mode, mode),
                                _td, self._fmt_speed(avg_s),
                                _td, int(avg_l),
                                _td, self._fmt_speed(
                                    best_r.get('real_speed_kbs', 0)),
                                best_path))
            summary += '</table>'
            if best_mode:
                summary += ('<br><b style="color:#2E7D32;">'
                            '\u2605 Winner: %s (%s avg)</b>'
                            % (mode_names.get(best_mode, best_mode),
                               self._fmt_speed(best_avg)))
            self.speed_test_browser.append(summary)

    @staticmethod
    def _fmt_speed(kbs):
        if kbs >= 1024:
            return '%.2f MB/s' % (kbs / 1024)
        elif kbs >= 1:
            return '%.1f KB/s' % kbs
        return '%.2f KB/s' % kbs

    @staticmethod
    def _fmt_bytes(b):
        if b >= 1048576:
            return '%.1f MB' % (b / 1048576)
        if b >= 1024:
            return '%.1f KB' % (b / 1024)
        return '%d B' % b

    def _on_speed_error(self, err):
        self.speed_test_button.setEnabled(True)
        self.speed_test_browser.append(
            '<b style="color:red">Speed test error:</b> %s' % err)
        ## Try to continue with remaining modes
        if hasattr(self, '_st_modes_queue') and self._st_modes_queue:
            self._run_next_speed_mode()

    def show_current_circuits(self):
        self._sync_control_settings()
        ## Don't overwrite with "Fetching..." to avoid scroll jumps
        params = self._get_control_params()
        self.circuit_fetcher = tor_network_status.TorCircuitFetcher(
            **params, parent=self)
        self.circuit_fetcher.circuits_done.connect(self._on_circuits_fetched)
        self.circuit_fetcher.error.connect(self._on_circuits_error)
        self.circuit_fetcher.start()

    def _on_circuits_fetched(self, circuits):
        import time as _time
        prev_data = self._last_circuits_data  ## save BEFORE overwriting
        self._last_circuits_data = circuits

        ## Periodic auto-remove: during live traffic, check the server's
        ## health tracker and remove proxies that have died on the fly.
        self._exit_proxy_health_check()

        now = _time.time()

        ## ── Track recently-closed circuits ────────────────────────
        ## Detect circuits that had streams but disappeared
        current_ids = set()
        for c in circuits:
            current_ids.add(c['circuit_id'])
        ## Save circuits that just disappeared (had targets)
        for old_cid in self._prev_circuit_ids - current_ids:
            ## Check if this circuit had streams worth preserving
            for rc in prev_data:
                if rc.get('circuit_id') == old_cid:
                    if rc.get('targets') or rc.get('target_details'):
                        rc_copy = dict(rc)
                        rc_copy['status'] = 'CLOSED'
                        rc_copy['_closed'] = True
                        self._recent_closed_circuits[old_cid] = {
                            'data': rc_copy, 'closed_at': now}
                    break
        self._prev_circuit_ids = current_ids

        ## Also mark CLOSED/FAILED circuits from Tor itself
        for c in circuits:
            if c.get('status') in ('CLOSED', 'FAILED'):
                if c.get('targets') or c.get('target_details'):
                    cid = c['circuit_id']
                    if cid not in self._recent_closed_circuits:
                        c_copy = dict(c)
                        c_copy['_closed'] = True
                        self._recent_closed_circuits[cid] = {
                            'data': c_copy, 'closed_at': now}

        ## Prune closed circuits older than 15 seconds
        _closed_cutoff = now - 15
        self._recent_closed_circuits = {
            k: v for k, v in self._recent_closed_circuits.items()
            if v['closed_at'] > _closed_cutoff}

        ## Filter out CLOSED/FAILED from active list
        active_circuits = [c for c in circuits
                           if c.get('status') not in ('CLOSED', 'FAILED')]

        ## Inject recently-closed circuits back with marker
        for cid, entry in self._recent_closed_circuits.items():
            if cid not in current_ids:
                cd = entry['data']
                ## Mark targets as closed for display
                closed_tgts = []
                for t in cd.get('targets', []):
                    if not t.endswith(' \u2718'):
                        closed_tgts.append(t + ' \u2718')
                    else:
                        closed_tgts.append(t)
                cd['targets'] = closed_tgts
                active_circuits.append(cd)

        if not active_circuits:
            self.circ_status_label.setText(
                '<b>Circuits:</b> No active circuits.')
            self.circuit_view.update_circuits([])
            return

        ## Merge stream targets into persistent history
        for c in active_circuits:
            cid = c['circuit_id']
            for td in c.get('target_details', []):
                key = td['target']
                if key not in self._stream_history:
                    self._stream_history[key] = {
                        'circuit_id': cid, 'path': c['path'],
                        'first_seen': now,
                        'source_addr': td.get('source_addr', ''),
                        'stream_id': td.get('stream_id', ''),
                    }
                self._stream_history[key]['last_seen'] = now
                self._stream_history[key]['circuit_id'] = cid
                self._stream_history[key]['path'] = c['path']
        ## Prune entries older than 5 minutes
        cutoff = now - 300
        self._stream_history = {
            k: v for k, v in self._stream_history.items()
            if v.get('last_seen', 0) > cutoff}

        ## Sort: BUILT first, CLOSED last
        order = {'BUILT': 0, 'EXTENDED': 1, 'LAUNCHED': 2,
                 'CLOSED': 8, 'FAILED': 9}
        active_circuits.sort(
            key=lambda c: order.get(c.get('status', ''), 5))
        circuits = active_circuits

        ## Collect active exit proxy connections for circuit display
        _ep_active = {}
        _ep_running = (self._exit_proxy_server and
                       self._exit_proxy_server.running and
                       self.exit_proxy_grp.isChecked())
        if _ep_running:
            ## Build proxy address → display URL mapping
            _px_addr_to_url = {}
            for px in self._exit_proxy_server._proxies:
                key = '%s:%d' % (px['host'], int(px['port']))
                _px_addr_to_url[key] = px.get('display', key)

            ## Build proxy URL → set of real destinations.
            ## Use connection HISTORY (active + recently finished)
            ## because HTTP requests often complete before we query,
            ## but Tor still holds the stream/circuit open.
            _px_url_to_dests = {}
            _all_conns = self._exit_proxy_server.get_connection_history()
            for _cid2, info_item in _all_conns.items():
                pu = info_item.get('proxy', '')
                dst = info_item.get('dst', '')
                if pu and dst:
                    _px_url_to_dests.setdefault(pu, set()).add(dst)

            ## Pre-process circuits: replace proxy-address targets
            ## with real destinations so the view shows what's behind
            ## each proxy, not the proxy as the endpoint.
            for c in circuits:
                _proxy_map = {}
                new_targets = []
                for td in c.get('target_details', []):
                    raw = td.get('raw_target', '')
                    purl = _px_addr_to_url.get(raw)
                    if purl:
                        real_dests = sorted(
                            _px_url_to_dests.get(purl, set()))
                        if real_dests:
                            for rd in real_dests:
                                if rd not in new_targets:
                                    new_targets.append(rd)
                                    _proxy_map[rd] = purl
                        else:
                            t = td.get('target', raw)
                            if t not in new_targets:
                                new_targets.append(t)
                                _proxy_map[t] = purl
                    else:
                        t = td.get('target', raw)
                        if t not in new_targets:
                            new_targets.append(t)
                if new_targets:
                    c['targets'] = new_targets
                c['_proxy_map'] = _proxy_map

            ## Build ep_active keyed by real destination
            for _cid2, info_item in _all_conns.items():
                dst = info_item.get('dst', '')
                _ep_active.setdefault(dst, []).append(info_item)

        ## Update the interactive circuit graphics view
        self.circuit_view.update_circuits(
            circuits, ep_running=_ep_running, ep_active=_ep_active)

        ## Update status label
        status = self.circuit_view.get_status_text(circuits)
        status_html = '<b>Circuits:</b> %s' % status

        ## -- Exit Proxy status --
        if _ep_running:
            active = self._exit_proxy_server.get_active_connections()
            n_px = len(getattr(self._exit_proxy_server, '_proxies', []))
            n_alive = len(self._exit_proxy_server.get_alive_proxies())
            n_dead = n_px - n_alive
            status_html += (' &nbsp; <b style="color:#7B1FA2">'
                            '\U0001f310 Proxy:</b> '
                            '<b style="color:green">%d alive</b>' % n_alive)
            if n_dead:
                status_html += (', <span style="color:red">%d dead</span>'
                                % n_dead)
            if active:
                status_html += ', %d active conn' % len(active)

        ## -- Proxy check progress --
        if self._proxy_checker_thread is not None:
            alive = getattr(self, '_check_alive_count', 0)
            dead = getattr(self, '_check_dead_count', 0)
            total_px = 0
            for i in range(self.exit_proxy_list.count()):
                if self.exit_proxy_list.item(i).data(
                        QtCore.Qt.UserRole):
                    total_px += 1
            checked = alive + dead
            status_html += (' &nbsp; <b style="color:#F57F17">'
                            '\u23f3 Check:</b> %d/%d '
                            '(<span style="color:green">%d</span>/'
                            '<span style="color:red">%d</span>)'
                            % (checked, total_px, alive, dead))

        self.circ_status_label.setText(status_html)

    def _build_node_detail_html(self, node):
        """Build HTML for a single node's detailed info."""
        cc = tor_network_status.country_label(node.get('country', '??'))
        bw = tor_network_status.format_bandwidth(node.get('bandwidth', 0))
        flags = ', '.join(node.get('flags', [])) or 'N/A'
        addr = node.get('address', '?')
        or_port = node.get('or_port', 0)
        nick = node.get('nickname', '?')
        fp = node.get('fingerprint', '?')
        return (
            '<td style="vertical-align:top; padding:4px 8px; '
            'border:1px solid #ddd; border-radius:4px; min-width:160px;">'
            '<b style="font-size:12px;">%s</b><br>'
            '<small style="color:#666">%s</small><br>'
            '<code style="font-size:9px; user-select:all;">%s</code><br>'
            '<b>IP:</b> <span style="user-select:all">%s:%s</span><br>'
            '<b>BW:</b> %s<br>'
            '<b>Flags:</b> <small>%s</small>'
            '</td>' % (nick, cc, fp, addr, or_port, bw, flags))

    def _on_circuit_link_clicked_str(self, href):
        """Adapter: accepts href string from CircuitGraphicsView signal."""
        self._handle_circuit_link(href)

    def _on_circuit_link_clicked(self, url):
        """Handle clicks on circuit tree links (from QTextBrowser)."""
        href = url.toString()
        self._handle_circuit_link(href)

    def _handle_circuit_link(self, href):

        if href.startswith('circ:'):
            ## Show ALL nodes in this circuit side by side
            cid = href[5:]
            circ = None
            for c in self._last_circuits_data:
                if str(c['circuit_id']) == str(cid):
                    circ = c
                    break
            if not circ:
                self.circ_detail_browser.setText(
                    '<i>Circuit %s not found.</i>' % cid)
                return
            roles = ['Guard', 'Middle', 'Exit', 'Hop 4', 'Hop 5']
            html = ('<b>Circuit #%s</b> — '
                    '<span style="color:%s">%s</span> %s<br>'
                    '<table cellspacing="4"><tr>' % (
                        cid,
                        {'BUILT': '#2E7D32', 'EXTENDED': '#F57F17',
                         'LAUNCHED': '#1565C0'}.get(
                            circ.get('status', ''), '#888'),
                        circ.get('status', '?'),
                        circ.get('purpose', '')))
            for i, node in enumerate(circ['path']):
                role = roles[i] if i < len(roles) else 'Hop %d' % (i + 1)
                html += ('<td style="vertical-align:top; padding:4px 8px; '
                         'border:1px solid #ddd; border-radius:4px; '
                         'min-width:140px; background:#fafafa;">'
                         '<b style="color:#1565C0;">%s</b><br>' % role)
                html += ('<b style="font-size:12px;">%s</b><br>'
                         '<small style="color:#666">%s</small><br>'
                         '<code style="font-size:9px; user-select:all;">'
                         '%s</code><br>'
                         '<b>IP:</b> <span style="user-select:all">'
                         '%s:%s</span><br>'
                         '<b>BW:</b> %s<br>'
                         '<b>Flags:</b> <small>%s</small>'
                         '</td>' % (
                             node.get('nickname', '?'),
                             tor_network_status.country_label(
                                 node.get('country', '??')),
                             node.get('fingerprint', '?'),
                             node.get('address', '?'),
                             node.get('or_port', 0),
                             tor_network_status.format_bandwidth(
                                 node.get('bandwidth', 0)),
                             ', '.join(node.get('flags', [])) or 'N/A'))
            html += '</tr></table>'
            ## Show streams on this circuit
            targets = circ.get('targets', [])
            if targets:
                seen = []
                for t in targets:
                    if t not in seen:
                        seen.append(t)
                html += '<br><b>Streams:</b> '
                html += ', '.join(seen[:10])
            self.circ_detail_browser.setText(html)

        elif href.startswith('stream:'):
            ## Show stream/connection details + circuit used
            rest = href[7:]
            ## Format: circ_id:target
            colon_idx = rest.find(':')
            if colon_idx < 0:
                return
            cid = rest[:colon_idx]
            target = rest[colon_idx + 1:]
            ## Find stream details from history
            sh = self._stream_history.get(target, {})
            ## Find circuit
            circ = None
            for c in self._last_circuits_data:
                if str(c['circuit_id']) == str(cid):
                    circ = c
                    break
            ## Compact header: connection info in one line
            _host = target.split(':')[0] if ':' in target else target
            info_parts = ['\U0001f310 <b>%s</b>' % target]
            if sh.get('stream_id'):
                info_parts.append('SID:%s' % sh['stream_id'])
            if sh.get('first_seen'):
                import time as _time
                age = _time.time() - sh['first_seen']
                if age < 60:
                    info_parts.append('%ds' % age)
                else:
                    info_parts.append('%dm%ds' % (age // 60, age % 60))
            html = ('<div style="font-size:10px;margin-bottom:4px;">'
                    '%s</div>' % ' &nbsp;\u2502&nbsp; '.join(info_parts))
            ## Circuit path nodes in a row below
            if circ:
                html += ('<div style="font-size:9px;color:#666;'
                         'margin-bottom:2px;">'
                         'Circuit #%s — %s</div>'
                         % (cid, circ.get('status', '?')))
                html += '<table cellspacing="3"><tr>'
                roles = ['Guard', 'Middle', 'Exit', 'Hop 4', 'Hop 5']
                for i, node in enumerate(circ['path']):
                    role = roles[i] if i < len(roles) else 'Hop %d' % (i+1)
                    html += self._build_node_detail_html(node)
                html += '</tr></table>'
            elif sh.get('path'):
                html += ('<div style="font-size:9px;color:#666;'
                         'margin-bottom:2px;">Last known path</div>')
                html += '<table cellspacing="3"><tr>'
                for node in sh['path']:
                    html += self._build_node_detail_html(node)
                html += '</tr></table>'
            ## INFO section below the nodes — store base for callback
            html += ('<div style="margin-top:4px;padding-top:4px;'
                     'border-top:1px solid #eee;">'
                     '<b style="font-size:10px;">INFO: '
                     '<code>%s</code></b> '
                     '<i style="color:#888;font-size:9px;">'
                     'Loading via Tor...</i></div>' % _host)
            self._info_base_html = html
            self.circ_detail_browser.setText(html)
            self._whois_target = target
            self._run_whois_lookup(_host, cid)

        elif href.startswith('node:'):
            ## Format: node:CIRCUIT_ID:FINGERPRINT
            rest = href[5:]
            colon = rest.find(':')
            if colon < 0:
                return
            cid = rest[:colon]
            fp = rest[colon + 1:]
            ## Find the exact circuit by ID
            circ = None
            for c in self._last_circuits_data:
                if str(c['circuit_id']) == str(cid):
                    circ = c
                    break
            if not circ:
                ## Fallback: search all circuits for the fp
                for c in self._last_circuits_data:
                    for n in c.get('path', []):
                        if n['fingerprint'] == fp:
                            circ = c
                            break
                    if circ:
                        break
            if not circ:
                self.circ_detail_browser.setText(
                    '<i>Node %s... not found.</i>' % fp[:8])
                return
            ## Show all nodes from that circuit with clicked one highlighted
            ## Basic info first, then async-load full details
            roles = ['Guard', 'Middle', 'Exit', 'Hop 4', 'Hop 5']
            html = ('<b>Circuit #%s path:</b><br>'
                    '<table cellspacing="4"><tr>' % circ['circuit_id'])
            for i, n in enumerate(circ['path']):
                role = roles[i] if i < len(roles) else 'Hop %d' % (i+1)
                is_sel = n['fingerprint'] == fp
                bg = '#e3f2fd' if is_sel else '#fafafa'
                bdr = '#1565C0' if is_sel else '#ddd'
                html += (
                    '<td style="vertical-align:top; padding:4px 8px; '
                    'border:2px solid %s; border-radius:4px; '
                    'min-width:140px; background:%s;">'
                    '<b style="color:#1565C0;">%s</b><br>'
                    '<b style="font-size:12px;">%s</b><br>'
                    '<small style="color:#666">%s</small><br>'
                    '<code style="font-size:9px; user-select:all;">'
                    '%s</code><br>'
                    '<b>IP:</b> <span style="user-select:all">'
                    '%s:%s</span><br>'
                    '<b>BW:</b> %s<br>'
                    '<b>Flags:</b> <small>%s</small>'
                    '%s'
                    '</td>' % (
                        bdr, bg, role,
                        n.get('nickname', '?'),
                        tor_network_status.country_label(
                            n.get('country', '??')),
                        n.get('fingerprint', '?'),
                        n.get('address', '?'),
                        n.get('or_port', 0),
                        tor_network_status.format_bandwidth(
                            n.get('bandwidth', 0)),
                        ', '.join(n.get('flags', [])) or 'N/A',
                        '<br><i style="font-size:9px; color:#888">'
                        'Loading details...</i>' if is_sel else ''))
            html += '</tr></table>'
            self.circ_detail_browser.setText(html)
            ## Async-load full detail for the selected node
            self._circ_detail_context = {
                'circuit': circ, 'selected_fp': fp}
            self._sync_control_settings()
            params = self._get_control_params()
            self._circ_node_fetcher = (
                tor_network_status.TorNodeDetailFetcher(
                    fp, **params, parent=self))
            self._circ_node_fetcher.detail_done.connect(
                self._on_circ_node_detail_loaded)
            self._circ_node_fetcher.error.connect(
                lambda e: self._panel_log(
                    'circ node detail error: %s' % e))
            self._circ_node_fetcher.start()

    def _on_circ_node_detail_loaded(self, info):
        """Update circuit detail panel with full node info."""
        ctx = getattr(self, '_circ_detail_context', None)
        if not ctx:
            return
        circ = ctx['circuit']
        sel_fp = ctx['selected_fp']
        roles = ['Guard', 'Middle', 'Exit', 'Hop 4', 'Hop 5']
        html = ('<b>Circuit #%s path:</b><br>'
                '<table cellspacing="4"><tr>' % circ['circuit_id'])
        for i, n in enumerate(circ['path']):
            role = roles[i] if i < len(roles) else 'Hop %d' % (i + 1)
            is_sel = n['fingerprint'] == sel_fp
            bg = '#e3f2fd' if is_sel else '#fafafa'
            bdr = '#1565C0' if is_sel else '#ddd'
            ## Use full info for selected node, basic for others
            if is_sel:
                obs_bw = tor_network_status.format_bandwidth(
                    info.get('observed_bandwidth', 0))
                avg_bw = tor_network_status.format_bandwidth(
                    info.get('average_bandwidth', 0))
                uptime = tor_network_status.format_uptime(
                    info.get('uptime', 0))
                since = info.get('running_since', '') or 'N/A'
                contact = info.get('contact', '') or 'N/A'
                platform = info.get('platform', '') or 'N/A'
                policy = info.get('exit_policy', '') or 'N/A'
                html += (
                    '<td style="vertical-align:top; padding:4px 8px; '
                    'border:2px solid %s; border-radius:4px; '
                    'min-width:160px; background:%s;">'
                    '<b style="color:#1565C0;">%s</b><br>'
                    '<b style="font-size:12px;">%s</b><br>'
                    '<small style="color:#666">%s</small><br>'
                    '<code style="font-size:9px; user-select:all;">'
                    '%s</code><br>'
                    '<b>IP:</b> <span style="user-select:all">'
                    '%s:%s</span><br>'
                    '<b>Consensus BW:</b> %s<br>'
                    '<b>Observed BW:</b> %s<br>'
                    '<b>Average BW:</b> %s<br>'
                    '<b>Flags:</b> <small>%s</small><br>'
                    '<b>Uptime:</b> %s<br>'
                    '<b>Since:</b> %s<br>'
                    '<b>Platform:</b> <small>%s</small><br>'
                    '<b>Contact:</b> <small>%s</small><br>'
                    '<b>Exit Policy:</b> <small>%s</small>'
                    '</td>' % (
                        bdr, bg, role,
                        info.get('nickname', n.get('nickname', '?')),
                        tor_network_status.country_label(
                            info.get('country', n.get('country', '??'))),
                        n['fingerprint'],
                        info.get('address', n.get('address', '?')),
                        info.get('or_port', n.get('or_port', 0)),
                        tor_network_status.format_bandwidth(
                            info.get('bandwidth', n.get('bandwidth', 0))),
                        obs_bw, avg_bw,
                        ', '.join(info.get('flags', n.get('flags', []))
                                  ) or 'N/A',
                        uptime, since, platform,
                        contact[:80],
                        policy[:200]))
            else:
                html += (
                    '<td style="vertical-align:top; padding:4px 8px; '
                    'border:2px solid %s; border-radius:4px; '
                    'min-width:140px; background:%s;">'
                    '<b style="color:#1565C0;">%s</b><br>'
                    '<b style="font-size:12px;">%s</b><br>'
                    '<small style="color:#666">%s</small><br>'
                    '<code style="font-size:9px; user-select:all;">'
                    '%s</code><br>'
                    '<b>IP:</b> <span style="user-select:all">'
                    '%s:%s</span><br>'
                    '<b>BW:</b> %s<br>'
                    '<b>Flags:</b> <small>%s</small>'
                    '</td>' % (
                        bdr, bg, role,
                        n.get('nickname', '?'),
                        tor_network_status.country_label(
                            n.get('country', '??')),
                        n.get('fingerprint', '?'),
                        n.get('address', '?'),
                        n.get('or_port', 0),
                        tor_network_status.format_bandwidth(
                            n.get('bandwidth', 0)),
                        ', '.join(n.get('flags', [])) or 'N/A'))
        html += '</tr></table>'
        self.circ_detail_browser.setText(html)

    def _get_tor_socks_for_whois(self):
        """Return (addr, port) for SOCKS access for WHOIS lookups.

        When exit proxy is running, use the intercepted port (goes
        through proxy like all other traffic for consistency).
        Otherwise use direct Tor SOCKS.
        """
        intercept = getattr(self, '_exit_proxy_intercept_state', {})
        if intercept.get('internal_port'):
            return '127.0.0.1', intercept['internal_port']
        return self._detect_tor_socks()

    def _run_whois_lookup(self, host, cid):
        """Run IP info + HTTP header lookup for a host through Tor."""
        import threading
        _tor_addr, _tor_port = self._get_tor_socks_for_whois()

        def _socks_request(socks_mod, dest_host, dest_port, request_bytes,
                           timeout=10, max_recv=16000):
            """Helper: send raw request through Tor SOCKS, return bytes."""
            s = socks_mod.socksocket()
            s.set_proxy(socks_mod.SOCKS5, _tor_addr, _tor_port,
                        rdns=True)
            s.settimeout(timeout)
            s.connect((dest_host, dest_port))
            s.sendall(request_bytes)
            data = b''
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > max_recv:
                    break
            s.close()
            return data

        def _do_lookup():
            result = {'_socks': '%s:%d' % (_tor_addr, _tor_port)}
            try:
                try:
                    import socks as _socks
                except ImportError:
                    result['error'] = ('PySocks not installed — '
                                       'apt install python3-socks')
                    return
                import re as _re
                import json as _json

                is_ip = bool(_re.match(
                    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host))

                ## --- Step 1: HTTP HEAD to target (get server headers) ---
                _interesting = ['server', 'x-powered-by',
                                'content-type', 'x-frame-options',
                                'strict-transport-security',
                                'x-content-type-options',
                                'alt-svc', 'via', 'x-cache',
                                'cf-ray', 'x-served-by',
                                'x-cdn', 'x-request-id']
                ## Try port 80 (plain HTTP — works with raw sockets)
                for _port in (80, 443):
                    try:
                        _req_host = host
                        req = ('HEAD / HTTP/1.1\r\n'
                               'Host: %s\r\n'
                               'User-Agent: curl/8.0\r\n'
                               'Accept: */*\r\n'
                               'Connection: close\r\n\r\n'
                               % _req_host).encode()
                        if _port == 443:
                            ## TLS wrapper for HTTPS
                            import ssl
                            s = _socks.socksocket()
                            s.set_proxy(_socks.SOCKS5, _tor_addr,
                                        _tor_port, rdns=True)
                            s.settimeout(8)
                            s.connect((_req_host, 443))
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            ss = ctx.wrap_socket(s,
                                server_hostname=_req_host)
                            ss.sendall(req)
                            data = b''
                            while True:
                                chunk = ss.recv(4096)
                                if not chunk:
                                    break
                                data += chunk
                                if len(data) > 4000:
                                    break
                            ss.close()
                            raw = data
                        else:
                            raw = _socks_request(
                                _socks, _req_host, 80, req,
                                timeout=8, max_recv=4000)
                        hdr_text = raw.decode('utf-8', errors='replace')
                        if not hdr_text or len(hdr_text) < 8:
                            continue
                        _hdrs = {}
                        _status_line = ''
                        for _i, line in enumerate(
                                hdr_text.split('\r\n')):
                            if _i == 0:
                                _status_line = line
                                continue
                            if ':' in line:
                                k, _, v = line.partition(':')
                                _hdrs[k.strip().lower()] = v.strip()
                        if _status_line:
                            result['http_status'] = _status_line
                            _found = {k: _hdrs[k] for k in _interesting
                                      if k in _hdrs}
                            ## Show all headers if none of the
                            ## interesting ones matched
                            if not _found and _hdrs:
                                _found = dict(
                                    list(_hdrs.items())[:12])
                            result['http_headers'] = _found
                            break
                    except Exception as _he:
                        result.setdefault('_debug', []).append(
                            'port %d: %s' % (_port, _he))
                        continue

                ## --- Step 2: Resolve domain to IP ---
                if not is_ip:
                    try:
                        s = _socks.socksocket()
                        s.set_proxy(_socks.SOCKS5, _tor_addr, _tor_port,
                                    rdns=True)
                        s.settimeout(8)
                        s.connect((host, 80))
                        ip = s.getpeername()[0]
                        result['ip'] = ip
                        s.close()
                    except Exception:
                        result['ip'] = None
                else:
                    result['ip'] = host

                ## --- Step 3: IP info API lookup ---
                lookup_ip = result.get('ip') or host
                api_ok = False
                for api_url in [
                    'http://ip-api.com/json/%s' % lookup_ip,
                    'http://ipwho.is/%s' % lookup_ip,
                ]:
                    try:
                        _host_part = api_url.split('//')[1].split('/')[0]
                        _path = '/' + '/'.join(
                            api_url.split('//')[1].split('/')[1:])
                        req = ('GET %s HTTP/1.1\r\n'
                               'Host: %s\r\n'
                               'Accept: application/json\r\n'
                               'Connection: close\r\n\r\n'
                               % (_path, _host_part)).encode()
                        data = _socks_request(
                            _socks, _host_part, 80, req, timeout=10)
                        body = data.decode('utf-8', errors='replace')
                        if '\r\n\r\n' in body:
                            body = body.split('\r\n\r\n', 1)[1]
                        if body and body[0].isdigit() and '\r\n' in body:
                            body = body.split('\r\n', 1)[1]
                        _body = body.strip()
                        if _body.endswith('\r\n'):
                            _body = _body.rstrip()
                        if _body.endswith('0'):
                            _idx = _body.rfind('}')
                            if _idx >= 0:
                                _body = _body[:_idx + 1]
                        info = _json.loads(_body)
                        if info.get('status') == 'success' or info.get('ip'):
                            result['country'] = (info.get('country') or
                                                 info.get('country_code', ''))
                            result['city'] = info.get('city', '')
                            result['region'] = info.get('regionName') or \
                                info.get('region', '')
                            result['isp'] = info.get('isp') or \
                                info.get('connection', {}).get('isp', '')
                            result['org'] = info.get('org') or \
                                info.get('connection', {}).get('org', '')
                            result['as'] = info.get('as') or \
                                info.get('connection', {}).get('asn', '')
                            result['reverse'] = info.get('reverse', '')
                            api_ok = True
                            break
                    except Exception as _ae:
                        result.setdefault('_debug', []).append(
                            'api %s: %s' % (
                                api_url.split('/')[2], _ae))
                        continue

                ## --- Step 4: Raw WHOIS fallback ---
                if not api_ok:
                    try:
                        if is_ip:
                            whois_srv = 'whois.arin.net'
                            query = 'n + %s' % host
                        else:
                            parts = host.rsplit('.', 1)
                            tld = parts[-1] if len(parts) > 1 else 'com'
                            tld_servers = {
                                'com': 'whois.verisign-grs.com',
                                'net': 'whois.verisign-grs.com',
                                'org': 'whois.pir.org',
                                'io': 'whois.nic.io',
                                'ru': 'whois.tcinet.ru',
                            }
                            whois_srv = tld_servers.get(
                                tld, 'whois.iana.org')
                            query = host
                        data = _socks_request(
                            _socks, whois_srv, 43,
                            ('%s\r\n' % query).encode(),
                            timeout=10, max_recv=32000)
                        whois_text = data.decode('utf-8', errors='replace')
                        result['whois_server'] = whois_srv
                        result['whois'] = whois_text[:8000]
                    except Exception as e:
                        result['whois_error'] = str(e)

            except Exception as e:
                result['error'] = str(e)
            finally:
                self._whois_result_signal.emit(result)

        t = threading.Thread(target=_do_lookup, daemon=True)
        t.start()

    def _on_whois_result(self, result):
        """Display INFO results in the detail browser."""
        info_html = ''
        ## HTTP headers info (fast, always available)
        if result.get('http_status'):
            info_html += ('<b>HTTP:</b> <code>%s</code><br>'
                          % result['http_status'][:120])
        for k, v in result.get('http_headers', {}).items():
            info_html += ('<b>%s:</b> <small>%s</small><br>'
                          % (k, v[:120]))
        if result.get('ip'):
            info_html += '<b>IP:</b> <code>%s</code><br>' % result['ip']
        if result.get('country'):
            loc_parts = [result['country']]
            if result.get('city'):
                loc_parts.append(result['city'])
            if result.get('region'):
                loc_parts.append(result['region'])
            info_html += '<b>Location:</b> %s<br>' % ', '.join(loc_parts)
        if result.get('isp'):
            info_html += '<b>ISP:</b> %s<br>' % result['isp']
        if result.get('org'):
            info_html += '<b>Org:</b> %s<br>' % result['org']
        if result.get('as'):
            info_html += '<b>AS:</b> %s<br>' % result['as']
        if result.get('reverse'):
            info_html += '<b>Reverse DNS:</b> %s<br>' % result['reverse']
        if result.get('whois_server'):
            info_html += ('<b>WHOIS server:</b> %s<br>'
                          % result['whois_server'])
        if result.get('whois'):
            ## Parse key WHOIS fields
            whois = result['whois']
            _fields = {}
            for line in whois.split('\n'):
                line = line.strip()
                if ':' in line and not line.startswith('%'):
                    k, _, v = line.partition(':')
                    k = k.strip()
                    v = v.strip()
                    if v and k not in _fields:
                        _fields[k] = v
            important = [
                'OrgName', 'Organization', 'org-name',
                'NetRange', 'CIDR', 'inetnum',
                'Country', 'country',
                'Registrar', 'registrar',
                'Creation Date', 'created',
                'Registrant Organization',
                'descr', 'netname',
            ]
            for key in important:
                if key in _fields:
                    info_html += ('<b>%s:</b> %s<br>'
                                  % (key, _fields[key][:120]))
        if result.get('whois_error') and not info_html:
            info_html += ('<span style="color:red">Lookup error: %s</span>'
                          % result['whois_error'])
        if result.get('error'):
            info_html += ('<span style="color:red">%s</span>'
                          % result['error'])
        if result.get('_debug') or result.get('_socks'):
            _dbg = []
            if result.get('_socks'):
                _dbg.append('via %s' % result['_socks'])
            if result.get('_debug'):
                _dbg.extend(result['_debug'])
            if _dbg and not info_html:
                info_html += (
                    '<small style="color:#999">debug: %s</small><br>'
                    % '; '.join(_dbg))
        if not info_html:
            info_html = '<i style="color:#888">No data available</i>'
        ## Rebuild from stored base HTML instead of replacing in
        ## Qt-processed HTML (toHtml() transforms the markup and
        ## breaks string matching of markers).
        base = getattr(self, '_info_base_html', '')
        if base:
            ## Remove the "Loading via Tor..." part from the base
            _loading_marker = 'Loading via Tor...</i></div>'
            if _loading_marker in base:
                base = base.replace(
                    _loading_marker, '</i></div>')
            new_html = base + info_html
        else:
            new_html = info_html
        self.circ_detail_browser.setText(new_html)

    def _on_circuits_error(self, err):
        self.circ_status_label.setText(
            '<b style="color:red">Error:</b> %s' % err)

    ## -- Exit Proxy crash recovery --

    def _exit_proxy_crash_recovery(self):
        """On startup, restore Tor's SocksPort if a previous instance
        crashed while intercepting.

        Also detects orphaned intercepts where the state file was lost
        but Tor is still on an internal port (19050-19199 range).
        """
        ## Exit Proxy is disabled on Whonix — skip crash recovery entirely
        if self.is_whonix:
            return

        from tor_control_panel import exit_proxy as ep

        state = ep._load_intercept_state()

        ## --- Whonix GW: remove iptables redirect rules ---
        if state and state.get('whonix_gw'):
            self._panel_log('Crash recovery: removing GW iptables rules...')
            try:
                ep.restore_whonix_gw()
                self._panel_log('Crash recovery: GW iptables rules removed')
            except Exception as e:
                self._panel_log('Crash recovery (GW iptables): %s' % e)
            return

        ## --- Whonix WS: just remove iptables rules ---
        if state and state.get('whonix_ws'):
            self._panel_log('Crash recovery: removing iptables rules...')
            try:
                ep.restore_whonix_ws()
                self._panel_log('Crash recovery: iptables rules removed')
            except Exception as e:
                self._panel_log('Crash recovery (iptables): %s' % e)
            return

        ## --- Non-Whonix: check if Tor's SocksPort needs restoring ---
        try:
            import stem.control
            ctrl = self._get_controller()
            listeners = ctrl.get_listeners(stem.control.Listener.SOCKS)
            ctrl.close()
        except Exception:
            listeners = []
            if state:
                ep._clear_intercept_state()
            return

        current_ports = [int(p) for _, p in listeners]

        if state:
            ## Have state file — use it to restore
            internal_port = state.get('internal_port', 0)
            if internal_port and internal_port in current_ports:
                self._panel_log(
                    'Crash recovery: restoring Tor SocksPort...')
                try:
                    ep.restore_tor_socks(
                        self._get_controller,
                        state.get('original_conf'))
                    self._panel_log(
                        'Crash recovery: Tor SocksPort restored')
                except Exception as e:
                    self._panel_log('Crash recovery failed: %s' % e)
            else:
                ep._clear_intercept_state()
                self._panel_log(
                    'Crash recovery: stale state cleared '
                    '(Tor already restored)')
        else:
            ## No state file — check for orphaned intercept.
            ## If Tor is on an internal port (19050-19199) it was
            ## likely intercepted by a previous panel that crashed
            ## without saving or restoring state.
            orphan_ports = [p for p in current_ports
                           if 19050 <= p <= 19199]
            if orphan_ports:
                ## Find original SocksPort from torrc file
                orig_port = None
                torrc_file = None
                torrc_had_socks_port = True
                try:
                    ctrl2 = self._get_controller()
                    torrc_file = ctrl2.get_info('config-file')
                    ## Detect Tor Browser: check if Tor was launched
                    ## with +__SocksPort on the command line.  If so,
                    ## the torrc originally had NO SocksPort line and
                    ## we must DELETE it (not replace) to avoid a
                    ## duplicate bind with the command-line value.
                    try:
                        tor_pid = ctrl2.get_info('process/pid')
                        if not tor_pid.strip().isdigit():
                            raise ValueError('Invalid PID: %r' % tor_pid)
                        cmdline_path = '/proc/%s/cmdline' % tor_pid.strip()
                        import os
                        with open(cmdline_path, 'rb') as _cf:
                            cmdline = _cf.read().replace(b'\x00', b' ')
                        if b'__SocksPort' in cmdline:
                            torrc_had_socks_port = False
                            self._panel_log(
                                'Crash recovery: Tor Browser detected '
                                '(+__SocksPort in cmdline)')
                    except Exception:
                        pass
                    ctrl2.close()
                    import re
                    with open(torrc_file, 'r') as f:
                        for line in f:
                            m = re.match(
                                r'^\s*SocksPort\s+(\S+)', line)
                            if m:
                                val = m.group(1)
                                ## Extract port from addr:port or port
                                if ':' in val:
                                    orig_port = int(val.rsplit(':', 1)[1])
                                else:
                                    orig_port = int(val)
                except Exception:
                    pass
                ## If the torrc port is ALSO in the internal range,
                ## the file was corrupted too — don't trust it
                if orig_port and 19050 <= orig_port <= 19199:
                    orig_port = None
                ## Fallback: common ports based on control port
                if not orig_port:
                    cp = getattr(self, 'control_port_setting', 0)
                    orig_port = 9150 if int(cp) == 9151 else 9050
                orig_addr = '127.0.0.1'
                orig_conf = ['%s:%d' % (orig_addr, orig_port)]
                self._panel_log(
                    'Crash recovery: orphaned intercept detected! '
                    'Tor on :%d, restoring to %s:%d'
                    % (orphan_ports[0], orig_addr, orig_port))
                try:
                    ep.restore_tor_socks(
                        self._get_controller, orig_conf)
                    self._panel_log(
                        'Crash recovery: Tor SocksPort restored '
                        'from orphaned intercept')
                except Exception as e:
                    self._panel_log(
                        'Crash recovery (orphan): %s' % e)
                ## Also repair the torrc file directly
                if torrc_file:
                    ep._repair_torrc_file(
                        torrc_file, orig_conf, torrc_had_socks_port)

    ## -- Exit Proxy config persistence --

    def _exit_proxy_config_file(self):
        """Path to JSON file storing exit proxy configuration."""
        import os
        config_dir = os.path.join(
            os.path.expanduser('~'), '.config', 'tor-control-panel')
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, 'exit_proxies.json')

    def _exit_proxy_save_config(self):
        """Save exit proxy list and bindings to disk."""
        if self.is_whonix:
            return
        import json
        proxies = []
        for i in range(self.exit_proxy_list.count()):
            url = self.exit_proxy_list.item(i).data(QtCore.Qt.UserRole)
            alive = self.exit_proxy_list.item(i).data(
                QtCore.Qt.UserRole + 1)
            if url:
                proxies.append({'url': url, 'alive': alive})
        bindings = []
        for i in range(self.exit_proxy_bindings_list.count()):
            d = self.exit_proxy_bindings_list.item(i).data(
                QtCore.Qt.UserRole)
            if d:
                bindings.append({'domain': d[0], 'proxy': d[1]})
        data = {
            'enabled': self.exit_proxy_grp.isChecked(),
            'proxies': proxies,
            'bindings': bindings,
            'timeout': self.exit_proxy_timeout_spin.value(),
            'threads': self.exit_proxy_threads_spin.value(),
            'autocheck_ip': self.exit_proxy_autocheck_ip.isChecked(),
            'auto_remove_dead': self.exit_proxy_auto_remove_dead_cb.isChecked(),
            'auto_recheck': self.exit_proxy_auto_recheck_cb.isChecked(),
            'recheck_interval': self.exit_proxy_recheck_interval.value(),
            'domain_rotation': self.exit_proxy_domain_rotation_cb.isChecked(),
            'proxy_mode': 'selective' if self.exit_proxy_mode_selective.isChecked() else 'all',
        }
        try:
            with open(self._exit_proxy_config_file(), 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self._panel_log('Exit proxy config save error: %s' % e)

    def _exit_proxy_load_config(self):
        """Load exit proxy list and bindings from disk."""
        ## Exit Proxy is disabled on Whonix — do not load config
        if self.is_whonix:
            return
        import json
        try:
            with open(self._exit_proxy_config_file(), 'r') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return
        ## Clear existing lists to prevent duplicate accumulation
        self.exit_proxy_list.clear()
        self.exit_proxy_bindings_list.clear()
        ## Restore proxy list (deduplicate by URL)
        _seen_urls = set()
        for px in data.get('proxies', []):
            url = px.get('url', '')
            if not url or url in _seen_urls:
                continue
            _seen_urls.add(url)
            alive = px.get('alive')
            item = QtWidgets.QListWidgetItem(url)
            item.setData(QtCore.Qt.UserRole, url)
            if alive is True:
                item.setText('\u2714 %s' % url)
                item.setBackground(QtGui.QColor(200, 255, 200))
                item.setData(QtCore.Qt.UserRole + 1, True)
            elif alive is False:
                item.setText('\u2716 %s' % url)
                item.setBackground(QtGui.QColor(255, 200, 200))
                item.setData(QtCore.Qt.UserRole + 1, False)
            self.exit_proxy_list.addItem(item)
        ## Restore bindings (deduplicate — older saves had duplicates)
        seen_domains = set()
        for b in data.get('bindings', []):
            domain = b.get('domain', '')
            proxy = b.get('proxy', '')
            if domain and proxy and domain not in seen_domains:
                seen_domains.add(domain)
                item = QtWidgets.QListWidgetItem(
                    '%s \u2192 %s' % (domain, proxy))
                item.setData(QtCore.Qt.UserRole, (domain, proxy))
                self.exit_proxy_bindings_list.addItem(item)
        ## Restore settings
        if 'timeout' in data:
            self.exit_proxy_timeout_spin.setValue(
                data.get('timeout', 15))
        if 'threads' in data:
            self.exit_proxy_threads_spin.setValue(
                data.get('threads', 50))
        if 'autocheck_ip' in data:
            self.exit_proxy_autocheck_ip.setChecked(
                data.get('autocheck_ip', True))
        if 'auto_remove_dead' in data:
            self.exit_proxy_auto_remove_dead_cb.setChecked(
                data.get('auto_remove_dead', True))
            self._exit_proxy_auto_remove_dead = data.get(
                'auto_remove_dead', True)
        if 'recheck_interval' in data:
            self.exit_proxy_recheck_interval.setValue(
                data.get('recheck_interval', 5))
        if 'auto_recheck' in data and data['auto_recheck']:
            self.exit_proxy_auto_recheck_cb.setChecked(True)
        if 'domain_rotation' in data:
            self.exit_proxy_domain_rotation_cb.setChecked(
                data.get('domain_rotation', False))
        if data.get('proxy_mode') == 'selective':
            self.exit_proxy_mode_selective.setChecked(True)
        else:
            self.exit_proxy_mode_all.setChecked(True)
        ## Restore enabled state
        from tor_control_panel import exit_proxy as _ep
        if data.get('enabled', False) and self.exit_proxy_list.count():
            if _ep._WHONIX:
                ## Whonix (GW or WS): auto-start exit proxy on startup.
                ## GW: intercepts Tor SocksPort for all WS traffic.
                ## WS: iptables redirect + local proxy (safe, reversible).
                self.exit_proxy_grp.setChecked(True)
            else:
                ## Non-Whonix: block signals so we don't auto-trigger
                ## interception on startup. User must manually
                ## re-enable to avoid broken state from previous crash.
                self.exit_proxy_grp.blockSignals(True)
                self.exit_proxy_grp.setChecked(True)
                self.exit_proxy_grp.blockSignals(False)
                for child in self.exit_proxy_grp.children():
                    if isinstance(child, QtWidgets.QWidget):
                        child.setVisible(True)
                self.exit_proxy_status_label.setText(
                    '<small style="color:gray">Proxies loaded. '
                    'Uncheck and re-check the box to activate '
                    'interception.</small>')

    ## -- Onion Services (via ADD_ONION control port) --

    def _onion_keys_file(self):
        """Path to JSON file storing persistent onion service keys."""
        import os
        config_dir = os.path.join(
            os.path.expanduser('~'), '.config', 'tor-control-panel')
        os.makedirs(config_dir, exist_ok=True)
        return os.path.join(config_dir, 'onion_services.json')

    def _onion_load_saved(self):
        """Load saved onion service keys from disk."""
        import json
        try:
            with open(self._onion_keys_file(), 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _onion_save_keys(self, services):
        """Save onion service keys to disk."""
        import json
        with open(self._onion_keys_file(), 'w') as f:
            json.dump(services, f, indent=2)

    def _onion_add_port(self):
        vport = self.onion_vport_spin.value()
        target = self.onion_target_edit.text().strip()
        if not target:
            target = '127.0.0.1:%d' % vport
        label = '%d -> %s' % (vport, target)
        item = QtWidgets.QListWidgetItem(label)
        item.setData(QtCore.Qt.UserRole, (vport, target))
        self.onion_ports_list.addItem(item)

    def _onion_create_service(self):
        """Create an ephemeral onion service via ADD_ONION."""
        ## Onion Services disabled on Whonix (defense-in-depth)
        if self.is_whonix:
            return
        ports = []
        for i in range(self.onion_ports_list.count()):
            d = self.onion_ports_list.item(i).data(QtCore.Qt.UserRole)
            if d:
                ports.append(d)
        if not ports:
            QtWidgets.QMessageBox.warning(
                self, 'Onion Service', 'Add at least one port mapping.')
            return

        persistent = self.onion_persistent_check.isChecked()
        self._panel_log('Onion: creating service (persistent=%s) '
                        'ports=%s' % (persistent, ports))

        try:
            self._sync_control_settings()
            params = self._get_control_params()
            controller = tor_network_status.get_controller(**params)

            ## Build port spec: {vport: target, ...}
            port_map = {}
            for vport, target in ports:
                port_map[vport] = target

            ## Create ephemeral hidden service (detached so it survives
            ## this control connection closing)
            response = controller.create_ephemeral_hidden_service(
                port_map,
                detached=True,
                await_publication=False,
                key_type='NEW',
                key_content='ED25519-V3')
            service_id = response.service_id
            private_key = response.private_key
            key_type = response.private_key_type
            controller.close()

            onion_addr = '%s.onion' % service_id
            self._panel_log('Onion: created %s' % onion_addr)

            ## Save key for persistence across Tor restarts
            if persistent and private_key:
                saved = self._onion_load_saved()
                saved.append({
                    'service_id': service_id,
                    'key_type': key_type,
                    'private_key': private_key,
                    'ports': [[v, t] for v, t in ports],
                })
                self._onion_save_keys(saved)
                self._panel_log('Onion: key saved to %s'
                                % self._onion_keys_file())

            QtWidgets.QMessageBox.information(
                self, 'Onion Service Created',
                'Address: %s\n\n'
                'Ports: %s\n'
                '%s' % (
                    onion_addr,
                    ', '.join('%d->%s' % (v, t) for v, t in ports),
                    'Key saved to disk (persistent).'
                    if persistent else
                    'Ephemeral — will be lost when Tor restarts.'))
            self.onion_ports_list.clear()
            self._onion_refresh()
        except Exception as e:
            self._panel_log('Onion: create error: %s' % e)
            QtWidgets.QMessageBox.critical(
                self, 'Onion Service Error',
                'Failed to create onion service:\n%s' % e)

    def _onion_restore_saved(self):
        """Re-create persistent onion services from saved keys."""
        if self.is_whonix:
            return
        saved = self._onion_load_saved()
        if not saved:
            QtWidgets.QMessageBox.information(
                self, 'Onion Services',
                'No saved onion service keys found.\n'
                'File: %s' % self._onion_keys_file())
            return

        try:
            self._sync_control_settings()
            params = self._get_control_params()
            controller = tor_network_status.get_controller(**params)

            ## Get already active services to skip duplicates
            active = set()
            try:
                for sid in controller.list_ephemeral_hidden_services(
                        detached=True):
                    active.add(sid)
                for sid in controller.list_ephemeral_hidden_services(
                        detached=False):
                    active.add(sid)
            except Exception:
                pass

            restored = 0
            for svc in saved:
                sid = svc.get('service_id', '')
                if sid in active:
                    self._panel_log('Onion: %s.onion already active' % sid)
                    continue
                port_map = {}
                for v, t in svc.get('ports', []):
                    port_map[int(v)] = t
                key_type = svc.get('key_type', 'ED25519-V3')
                key = svc.get('private_key', '')
                if not key or not port_map:
                    continue
                try:
                    controller.create_ephemeral_hidden_service(
                        port_map,
                        detached=True,
                        await_publication=False,
                        key_type=key_type,
                        key_content=key)
                    restored += 1
                    self._panel_log('Onion: restored %s.onion' % sid)
                except Exception as e:
                    self._panel_log('Onion: restore %s error: %s'
                                    % (sid, e))

            controller.close()
            QtWidgets.QMessageBox.information(
                self, 'Onion Services',
                'Restored %d of %d saved services.' % (
                    restored, len(saved)))
            self._onion_refresh()
        except Exception as e:
            self._panel_log('Onion: restore error: %s' % e)
            QtWidgets.QMessageBox.critical(
                self, 'Onion Service Error',
                'Failed to restore services:\n%s' % e)

    def _onion_refresh(self):
        """List active ephemeral onion services from the control port."""
        if self.is_whonix:
            return
        self._sync_control_settings()
        services = []

        try:
            params = self._get_control_params()
            controller = tor_network_status.get_controller(**params)

            ## Get detached and non-detached services
            service_ids = set()
            try:
                for sid in controller.list_ephemeral_hidden_services(
                        detached=True):
                    service_ids.add(sid)
            except Exception:
                pass
            try:
                for sid in controller.list_ephemeral_hidden_services(
                        detached=False):
                    service_ids.add(sid)
            except Exception:
                pass

            controller.close()

            ## Match with saved keys for port info
            saved = self._onion_load_saved()
            saved_map = {s['service_id']: s for s in saved}

            for sid in sorted(service_ids):
                svc = {
                    'service_id': sid,
                    'address': '%s.onion' % sid,
                    'ports': [],
                    'persistent': sid in saved_map,
                }
                if sid in saved_map:
                    svc['ports'] = saved_map[sid].get('ports', [])
                services.append(svc)

            ## Also note saved services that are NOT currently active
            for s in saved:
                sid = s.get('service_id', '')
                if sid and sid not in service_ids:
                    services.append({
                        'service_id': sid,
                        'address': '%s.onion' % sid,
                        'ports': s.get('ports', []),
                        'persistent': True,
                        'inactive': True,
                    })
        except Exception as e:
            self._panel_log('Onion refresh error: %s' % e)

        if not services:
            self.onion_services_browser.setText(
                '<b>No onion services found.</b><br>'
                '<small>Create one above. Services are managed via '
                'the Tor control port (ADD_ONION).</small>')
            return

        html = '<b>%d onion service%s:</b><br><br>' % (
            len(services), 's' if len(services) != 1 else '')
        for s in services:
            addr = s['address']
            sid = s['service_id']
            inactive = s.get('inactive', False)
            persistent = s.get('persistent', False)

            border_color = '#d32f2f' if inactive else '#4CAF50'
            status = ('\u26a0\ufe0f Inactive (click Restore Saved)'
                      if inactive
                      else '\u2705 Active')
            html += ('<div style="margin-bottom:8px; padding:6px; '
                     'border:1px solid %s; border-radius:4px;">'
                     % border_color)
            html += ('<b style="user-select:all">'
                     '\U0001f9c5 %s</b><br>' % addr)
            html += '<small>%s</small>' % status
            if persistent:
                html += ' <small>\U0001f4be Persistent</small>'
            html += '<br>'
            if s.get('ports'):
                ports_str = ', '.join(
                    '%s->%s' % (v, t) for v, t in s['ports'])
                html += '<small><b>Ports:</b> %s</small><br>' % ports_str
            html += ('<a href="delete:%s" style="color:#d32f2f; '
                     'font-size:11px;">\u274c Remove</a>'
                     '</div>' % sid)
        self.onion_services_browser.setText(html)

    def _onion_link_clicked(self, url):
        href = url.toString()
        if href.startswith('delete:'):
            service_id = href[7:]
            reply = QtWidgets.QMessageBox.question(
                self, 'Remove Onion Service',
                'Remove onion service:\n%s.onion\n\n'
                'This will stop the service and delete its saved key '
                'if any.' % service_id,
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
            if reply != QtWidgets.QMessageBox.Yes:
                return
            self._onion_delete_service(service_id)

    def _onion_delete_service(self, service_id):
        """Remove an ephemeral onion service and its saved key."""
        ## Step 1: Remove from Tor via control port
        try:
            self._sync_control_settings()
            params = self._get_control_params()
            controller = tor_network_status.get_controller(**params)
            controller.remove_ephemeral_hidden_service(service_id)
            controller.close()
            self._panel_log('Onion: removed %s.onion' % service_id)
        except Exception as e:
            self._panel_log('Onion: remove error: %s' % e)

        ## Step 2: Remove from saved keys
        saved = self._onion_load_saved()
        new_saved = [s for s in saved
                     if s.get('service_id') != service_id]
        if len(new_saved) != len(saved):
            self._onion_save_keys(new_saved)
            self._panel_log('Onion: deleted saved key for %s' % service_id)

        QtWidgets.QMessageBox.information(
            self, 'Onion Service',
            'Service %s.onion removed.' % service_id)
        self._onion_refresh()

    ## -- Dashboard (nyx-like) --

    def _start_dashboard(self):
        if self._dashboard_poller is not None:
            self._dashboard_poller.stop()
            self._dashboard_poller.wait(2000)
        self._sync_control_settings()
        params = self._get_control_params()
        self._dashboard_poller = tor_network_status.TorDashboardPoller(
            **params, parent=self)
        self._dashboard_poller.update.connect(self._on_dashboard_update)
        self._dashboard_poller.error.connect(
            lambda e: self.dash_info_label.setText('Dashboard error: %s' % e))
        self._dashboard_poller.start()
        self.dash_frame.show()

    def _on_dashboard_update(self, data):
        ## System info line
        parts = []
        if data['version']:
            parts.append('Tor %s' % data['version'])
        if data['is_relay']:
            parts.append('Relay')
            if data['flags']:
                parts.append('Flags: %s' % ', '.join(data['flags']))
        else:
            parts.append('Relaying Disabled')
        if data['control_info']:
            parts.append('Control: %s' % data['control_info'])
        if data['pid']:
            parts.append('PID: %d' % data['pid'])
        if data['mem']:
            parts.append('Mem: %s' % tor_network_status.format_bytes(data['mem']))
        self.dash_info_label.setText(
            '<b>%s</b>' % '  |  '.join(parts))

        ## Bandwidth stats
        bw_parts = []
        bw_parts.append(
            '<font color="green">\u25bc %s</font> (avg: %s, total: %s)' % (
                tor_network_status.format_rate(data['bw_down']),
                tor_network_status.format_rate(data['avg_down']),
                tor_network_status.format_bytes(data['total_down'])))
        bw_parts.append(
            '<font color="blue">\u25b2 %s</font> (avg: %s, total: %s)' % (
                tor_network_status.format_rate(data['bw_up']),
                tor_network_status.format_rate(data['avg_up']),
                tor_network_status.format_bytes(data['total_up'])))
        if data['bw_rate']:
            bw_parts.append('Limit: %s, Burst: %s' % (
                tor_network_status.format_bytes(data['bw_rate']),
                tor_network_status.format_bytes(data['bw_burst'])))
        self.dash_bw_label.setText('  |  '.join(bw_parts))

        ## Bandwidth graph
        self.dash_bw_graph.set_data(
            data['bw_download_history'], data['bw_upload_history'])

        ## Events
        if data['events']:
            self.dash_events.setText('\n'.join(data['events']))
            self.dash_events.moveCursor(QtGui.QTextCursor.End)

    ## -- Advanced tab (stem.manual parameter editor) --

    def _adv_populate_options(self):
        try:
            import stem.manual
            manual = stem.manual.Manual.from_cache()
        except Exception:
            self.adv_status_label.setText(
                'stem.manual not available — using raw editor only.')
            self.adv_raw_toggle.setChecked(True)
            self.adv_editor.show()
            return

        cats = set()
        options = []
        for key, opt in sorted(manual.config_options.items()):
            cat = opt.category or 'General'
            cats.add(cat)
            options.append({
                'key': key,
                'usage': opt.usage or '',
                'summary': opt.summary or '',
                'description': opt.description or '',
                'category': cat,
            })
        self._adv_options = {o['key']: o for o in options}

        ## Populate category filter
        for cat in sorted(cats):
            self.adv_cat_combo.addItem(cat)

        ## Populate table
        self.adv_table.setSortingEnabled(False)
        self.adv_table.setRowCount(len(options))
        for row, o in enumerate(options):
            key_item = QtWidgets.QTableWidgetItem(o['key'])
            key_item.setFlags(key_item.flags() & ~Qt.ItemIsEditable)
            color = self._adv_cat_colors.get(o['category'], '#888888')
            key_item.setForeground(QtGui.QColor(color))
            key_item.setFont(QtGui.QFont('monospace', 9))
            self.adv_table.setItem(row, 0, key_item)

            val_item = QtWidgets.QTableWidgetItem('')
            val_item.setFont(QtGui.QFont('monospace', 9))
            self.adv_table.setItem(row, 1, val_item)

            cat_item = QtWidgets.QTableWidgetItem(o['category'])
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemIsEditable)
            cat_item.setForeground(QtGui.QColor(color))
            self.adv_table.setItem(row, 2, cat_item)

            sum_item = QtWidgets.QTableWidgetItem(o['summary'][:80])
            sum_item.setFlags(sum_item.flags() & ~Qt.ItemIsEditable)
            sum_item.setToolTip(o['summary'])
            self.adv_table.setItem(row, 3, sum_item)
        self.adv_table.setSortingEnabled(True)
        self.adv_status_label.setText(
            '%d options loaded. Click "Load Current Values" to see '
            'active settings.' % len(options))

    def _adv_filter_options(self, _=None):
        text = self.adv_filter_edit.text().lower()
        cat_filter = self.adv_cat_combo.currentText()
        for row in range(self.adv_table.rowCount()):
            key_item = self.adv_table.item(row, 0)
            cat_item = self.adv_table.item(row, 2)
            if not key_item:
                continue
            match = True
            if text:
                found = False
                for col in range(self.adv_table.columnCount()):
                    item = self.adv_table.item(row, col)
                    if item and text in item.text().lower():
                        found = True
                        break
                if not found:
                    match = False
            if match and cat_filter != 'All Categories':
                if cat_item and cat_item.text() != cat_filter:
                    match = False
            self.adv_table.setRowHidden(row, not match)

    def _adv_show_description(self, index):
        row = index.row()
        key_item = self.adv_table.item(row, 0)
        if not key_item:
            return
        key = key_item.text()
        opt = self._adv_options.get(key, {})
        if not opt:
            return
        color = self._adv_cat_colors.get(opt['category'], '#888888')
        html = ('<b style="color:%s">%s</b> '
                '<i>[%s]</i><br>' % (color, key, opt['category']))
        if opt['usage']:
            html += '<b>Usage:</b> <code>%s %s</code><br>' % (
                key, opt['usage'])
        html += '<br>%s' % opt['description'].replace('\n', '<br>')
        self.adv_desc_browser.setText(html)

    def _adv_load_config(self):
        self._sync_control_settings()
        try:
            c = tor_network_status.get_controller(
                **self._get_control_params())
            loaded = 0
            for row in range(self.adv_table.rowCount()):
                key_item = self.adv_table.item(row, 0)
                val_item = self.adv_table.item(row, 1)
                if not key_item or not val_item:
                    continue
                key = key_item.text()
                try:
                    val = c.get_conf(key, None)
                    if val is not None:
                        val_item.setText(str(val))
                        loaded += 1
                except Exception:
                    pass
            c.close()
            self.adv_status_label.setText(
                'Loaded %d active values. Edit Value column and '
                'click Apply.' % loaded)
            ## Also load raw torrc from the actual running Tor
            _real_torrc = torrc_gen.torrc_path()
            try:
                c2 = self._get_controller()
                _real_torrc = c2.get_info('config-file')
                c2.close()
            except Exception:
                pass
            try:
                with open(_real_torrc) as f:
                    self.adv_editor.setPlainText(f.read())
            except Exception:
                pass
        except Exception as e:
            self.adv_status_label.setText('Load failed: %s' % e)

    def _adv_apply_config(self):
        self._sync_control_settings()
        changes = {}
        for row in range(self.adv_table.rowCount()):
            key_item = self.adv_table.item(row, 0)
            val_item = self.adv_table.item(row, 1)
            if not key_item or not val_item:
                continue
            val = val_item.text().strip()
            if val:
                changes[key_item.text()] = val

        if not changes:
            self.adv_status_label.setText('No values to apply.')
            return

        try:
            c = tor_network_status.get_controller(
                **self._get_control_params())
            applied = 0
            errors = []
            for key, val in changes.items():
                try:
                    c.set_conf(key, val)
                    applied += 1
                except Exception as e:
                    errors.append('%s: %s' % (key, e))

            if self.adv_save_check.isChecked():
                try:
                    c.save_conf()
                except Exception:
                    ## Fallback: write to user torrc (never modify
                    ## the system torrc directly).
                    try:
                        lines = []
                        for k, v in changes.items():
                            lines.append('%s %s' % (k, v))
                        path = torrc_gen.user_path()
                        _dir = os.path.dirname(path)
                        if not os.path.isdir(_dir):
                            os.makedirs(_dir, exist_ok=True)
                        with open(path, 'a') as f:
                            f.write('\n## Applied by Tor Control Panel\n')
                            f.write('\n'.join(lines) + '\n')
                    except Exception as e2:
                        errors.append('save_conf: %s' % e2)

            c.close()
            msg = 'Applied %d options.' % applied
            if errors:
                msg += ' Errors: %s' % '; '.join(errors[:3])
            self.adv_status_label.setText(msg)
        except Exception as e:
            self.adv_status_label.setText('Apply failed: %s' % e)

    def _adv_toggle_raw(self, checked):
        self.adv_editor.setVisible(checked)

    def quit(self):
        self.close()

_main_window = None
_shutdown_requested = False

def signal_handler(sig, frame):
    """Handle SIGINT/SIGTERM — just set a flag, timer picks it up."""
    global _shutdown_requested
    _shutdown_requested = True

def main():
    global _main_window
    if os.geteuid() == 0:
        print('tor_control_panel.py: ERROR: Do not run with sudo / as root!')
        sys.exit(1)

    app = QApplication(sys.argv)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    tor_controller = TorControlPanel()
    _main_window = tor_controller

    def _check_signal():
        if _shutdown_requested:
            tor_controller.close()

    timer = QtCore.QTimer()
    timer.start(200)
    timer.timeout.connect(_check_signal)

    tor_controller.refresh(True)
    tor_controller.show()
    ret = app.exec_()
    _main_window = None
    sys.exit(ret)

if __name__ == "__main__":
    main()
