from PyQt5 import QtWidgets

def show_help_censorship():
    reply = QtWidgets.QMessageBox(QtWidgets.QMessageBox.NoIcon, 'Censorship Circumvention Help',
                                  '''<p><b>  Censorship Circumvention Help</b></p>

<p>If you are unable to connect to the Tor network, it could be that your Internet Service
Provider (ISP) or another agency is blocking Tor.  Often, you can work around this problem
by using Tor Bridges, which are unlisted relays that are more difficult to block.</p>


<p>Tor bridges are the recommended way to circumvent the Tor censorship. You should always take it as the first option to help you bypass the Tor censorship. However, if you are living in a heavily censored area where all the Tor bridges are invalid, you may need to use some third-party censorship circumvention tools to help you instead. In such a case, you should choose not using Tor bridges to help you bypass the Tor censorship.</p>

<p> Using a third-party censorship circumvention tool may harm you security and/or anonymity. However, in case you do need it, the following is an instruction on how to connect to the Tor network using different censorship circumvention tools:</p>

<blockquote><b>1. VPN</b><br>
1. Establish your connection to the VPN server; 2. Hit the "back" buton on this page, going to the first page; 3. Hit the "Connect" button on the first page.</blockquote>

<blockquote><b>2. HTTP/Socks Proxy</b><br>
1. Choose not using Tor bridges in this page; 2. Hit the "next" buton on this page, going the Proxy Configuration page; 3. Configure a proxy.</blockquote>

<blockquote><b>3. Specialized Tool </b><br>
1. Figure out the listening port of the tool, including the port protocol and the port number; 2. Choose not using Tor bridges in this page; 3. Hit the "next" buton on this page, going the Proxy Configuration page; 4. Configure a proxy.</blockquote>
''', QtWidgets.QMessageBox.Ok)
    reply.exec_()

def show_proxy_help():
    reply = QtWidgets.QMessageBox(QtWidgets.QMessageBox.NoIcon, 'Proxy Configuration Help',
                                  '''<p><b>  Proxy Help</b></p>
                                  <p>In some situations, you may want to transfer your traffic through a proxy server before connecting to the Tor network. For example, if you are trying to use a third-party censorship circumvention tool to bypass the Tor censorship, you need to configure Tor to connect to the listening port of that circumvention tools. </p>

<p> The following is a brief introduction on what each blank means and how you may find the proper input value:</p>

<blockquote><b>1. Proxy Type</b><br>
                                  The proxy type is protocol you use to communicate with the proxy server. Since there are only three options, you can try all of them to see which one works.</blockquote>

<blockquote><b>2. Proxy IP/hostname</b><br>
You have to know the port number you are trying to connect to. If you are trying to connect to a local proxy, you should try 127.0.0.1 since it means localhost.</blockquote>

<blockquote><b>3. Proxy Port number</b><br>
You have to know the port number you are trying to connect to. It should be a positive integer from 1 to 65535. If you are trying to find the listening port number of a well-known censorship circumvention tool, you may simply search it online.</blockquote>

<blockquote><b>4. Username and Password</b><br>
If you do not know what they are, just leave them blank to see if the connection will success. Because in most cases, you do not need them.</blockquote>''', QtWidgets.QMessageBox.Ok)
    reply.exec_()

def custom_bridges_help():
    message = '''
<p>As an alternative to using the provided bridges, you may obtain a
custom set of addresses by using one of these two methods:</p>

<p><b>1.</b> Use a web browser to visit:
<b>https://bridges.torproject.org/options</b></p>

<p><b>2.</b> Send an email to <b>bridges@torproject.org</b> with the line 'get bridges' by itself in the body of the message. You must send this request from one of the following email providers
(listed in order of preference):<br>
https://www.riseup.net, https://mail.google.com, or https://mail.yahoo.com</p>
<p>For assistance, visit <b>torproject.org/about/contact.html#support</p>
<p>Paste the bridges list received from Tor Project:
'''
    return(message)

def tor_stopped():
    tor_message = ['',
            '<b>Tor is not running.</b> <p> \
            If Tor was stopped intentionally, you can restart it from the \
            button [Restart Tor] below</p> \
            <p> Hints:<br>  \
            In the <b>Logs</b> tab, check the content of torrc and \
            inspect Tor log and systemd journal <br><br>',

            '<b>Tor is disabled</b>. <br><br>A line <i>DisableNetwork 1</i> \
            exists in torrc <br> Therefore you most likely  can not connect to \
            the internet. <p> Run the <b>Connection Wizard</b> to connect to \
            or  configure the Tor network.',

            '<b>Tor is running but is disabled.</b><p> \
            A line <i>DisableNetwork 1</i> exists in torrc <p> \
            Run <b>Anon Connection Wizard</b> \
            to connect to or configure the Tor network.']

    return(tor_message)

def torrc_info(path):
    info = "\
# This file is generated by and should ONLY be used by anon-connection-wizard.\n\
# User configuration should go to " + path + ", not here. Because:\n\
#    1. This file can be easily overwritten by anon-connection-wizard.\n\
#    2. Even a single character change in this file may cause error.\n\
# However, deleting this file will be fine since a new plain file will be generated \
the next time you run anon-connection-wizard.\n\
"
    return(info)

def invalid_ip_port():
    return('''<p><b>  Please input valid Address and Port number.</b></p>
                <p> The Address should look like: 127.0.0.1 or localhost</p>
                <p> The Port number should be an integer between 1 and 65535</p>''')

