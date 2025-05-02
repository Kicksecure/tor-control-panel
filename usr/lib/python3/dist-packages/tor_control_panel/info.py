## Copyright (C) 2018 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

from PyQt5 import QtWidgets


def show_help_censorship():
    reply = QtWidgets.QMessageBox(QtWidgets.QMessageBox.NoIcon, 'Censorship Circumvention Help',
                                  '''<p><b>  Censorship Circumvention Help</b></p>

<p>If you are unable to connect to the Tor network, it could be that your Internet Service
Provider (ISP) or another agency is blocking Tor. Often, you can work around this problem
by using Tor Bridges, which are unlisted relays that are more difficult to block.</p>

<p>Tor bridges are the recommended way to circumvent Tor censorship. You should always take them as your first option to help bypass censorship. However, if you are living in a heavily censored area where all the Tor bridges are blocked, you may need to use third-party censorship circumvention tools instead. In such a case, you should choose not to use Tor bridges.</p>

<p>Using a third-party censorship circumvention tool may harm your security and/or anonymity. However, if you do need it, the following is an instruction on how to connect to the Tor network using different censorship circumvention tools:</p>

<blockquote><b>1. VPN</b><br>
1. Establish a connection to the VPN server; 2. Click the "Back" button on this page to return to the first page; 3. Click the "Connect" button on the first page.</blockquote>

<blockquote><b>2. HTTP/Socks Proxy</b><br>
1. Choose not to use Tor bridges on this page; 2. Click the "Next" button to proceed to the Proxy Configuration page; 3. Configure a proxy.</blockquote>

<blockquote><b>3. Specialized Tool</b><br>
1. Identify the tool's listening port, including protocol and port number; 2. Choose not to use Tor bridges on this page; 3. Click the "Next" button to proceed to the Proxy Configuration page; 4. Configure a proxy.</blockquote>
''', QtWidgets.QMessageBox.Ok)
    reply.exec_()

def show_proxy_help():
    reply = QtWidgets.QMessageBox(QtWidgets.QMessageBox.NoIcon, 'Proxy Configuration Help',
                                  '''<p><b>  Proxy Help</b></p>
                                  <p>In some situations, you may want to route your traffic through a proxy server before connecting to the Tor network. For example, if you are using a third-party censorship circumvention tool to bypass Tor censorship, you need to configure Tor to connect to the tool's listening port.</p>

<p>The following is a brief explanation of what each field means and how to find the correct value:</p>

<blockquote><b>1. Proxy Type</b><br>
The proxy type is the protocol you use to communicate with the proxy server. Since there are only three options, you can try each to see which one works.</blockquote>

<blockquote><b>2. Proxy IP/hostname</b><br>
You need to know the address you are trying to connect to. If connecting to a local proxy, use 127.0.0.1, which refers to localhost.</blockquote>

<blockquote><b>3. Proxy Port Number</b><br>
You need to know the port number you are trying to connect to. It should be a positive integer between 1 and 65535. For well-known tools, you can look up the port number online.</blockquote>

<blockquote><b>4. Username and Password</b><br>
If you do not know these, leave them blank and see if the connection succeeds. In most cases, they are not required.</blockquote>''', QtWidgets.QMessageBox.Ok)
    reply.exec_()

def custom_bridges_help():
    text = '''
<p>As an alternative to using the provided bridges, you can obtain a
custom set of addresses using one of the following methods:</p>

<p><b>1.</b> Use a web browser to visit:
<b>https://bridges.torproject.org/options</b></p>

<p><b>2.</b> Send an email to <b>bridges@torproject.org</b> with the line 'get bridges' in the body of the message. You must send this request from one of the following email providers
(listed in order of preference):<br>
https://www.riseup.net, https://mail.google.com, or https://mail.yahoo.com</p>
<p>For assistance, visit <b>torproject.org/about/contact.html#support</b></p>
<p>Paste the bridge list received from the Tor Project:</p>
'''
    return text.strip()


def tor_stopped():
    text = '''
<b>Tor is not running.</b> <p>
If Tor was stopped intentionally, you can restart it using the
[Restart Tor] button below.</p>
<p>Hints:<br>
In the <b>Logs</b> tab, check the content of torrc and
inspect the Tor log and systemd journal.<br><br>,

<b>The network is disabled.</b><br><br>

A line <i>DisableNetwork 1</i> exists in torrc. <p>The network can be enabled by: <p><b>Configure</b> -->
<b>Bridges type</b> --> <b>Enable network</b> -->
<b>Accept</b>,

<b>Tor is running but the network is disabled.</b><p>
A line <i>DisableNetwork 1</i> exists in torrc.
<br>Therefore, you most likely cannot connect to the internet.</br>\
<p>The network can be enabled by:</br><p><b>Configure</b> -->
<b>Bridges type</b> --> <b>Enable network</b> -->
<b>Accept</b>
'''
    return text.strip()


def cookie_error():
    text = '''
<b>ERROR: Tor Controller Authentication Failed</b> \
<p>Tor allows for authentication by reading a cookie file, \
but we cannot read that file (probably due to permissions)</p>
'''
    return text.strip()


def no_controller():
    text = '''
<b>ERROR: Tor Controller Not Constructed</b><p>The Tor \
controller cannot be constructed. This is most likely because \
you have a \"DisableNetwork 1\" line in a torrc file.\
Please manually remove or comment out those lines, then run \
anon-connection-wizard or restart Tor.
'''
    return text.strip()


def invalid_ip_port():
    text = '''
<p><b>ERROR: Please enter a valid address and port number.</b></p>
<p>The address should look like: 127.0.0.1 or localhost</p>
<p>The port number should be an integer between 1 and 65535</p>
'''
    return text.strip()


def newnym_text():
    text = '''
<p>Same functionality as the Tor Button's "New Identity", except:</p>

<p><span style="font:bold;color:red">Use with care</span>.\
 After this operation, Tor Browser will close tabs and clear the current \
history, cache, etc. <b>"All linkable identifiers and browser state \
MUST be cleared by this feature"</b> (from the Tor Browser design document).</p>
'''
    return text.strip()


def onions_text():
    text = '''
Displays Tor circuits and streams. It allows inspection of the circuits built by the locally running Tor daemon, along with some additional metadata for each node.

It is intended as a successor to the currently unmaintained Vidalia software.
'''
    return text.strip()


def torrc_text():
    text = '''
# This file is generated by and should ONLY be used by tor-control-panel.
# User configuration should go to /usr/local/etc/torrc.d/50_user.conf, not here, because:
#    1. This file can be easily overwritten by tor-control-panel.
#    2. Even a single character change in this file may cause errors.
# However, deleting this file is fine, since a new plain file will be generated the next time you run tor-control-panel.
'''
    return text.strip()


def user_torrc_text():
    text = '''
# Tor user-specific configuration file
#
# Add user modifications below this line:
############################################
'''
    return text.strip()

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)

    show_help_censorship()
    show_proxy_help()

    QtWidgets.QMessageBox.information(None, "custom_bridges_help()", custom_bridges_help(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "tor_stopped()", tor_stopped(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "cookie_error()", cookie_error(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "no_controller()", no_controller(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "invalid_ip_port()", invalid_ip_port(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "newnym_text()", newnym_text(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "onions_text()", onions_text(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "torrc_text()", torrc_text(), QtWidgets.QMessageBox.Ok)
    QtWidgets.QMessageBox.information(None, "user_torrc_text()", user_torrc_text(), QtWidgets.QMessageBox.Ok)

