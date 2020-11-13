#!env python3

'''
    # BURL proxy

    Use the [BURL ESMTP extension](https://tools.ietf.org/html/rfc4468) with MUAs, which do not normally support it.

    That way you **don't have to upload a message two times** - once for submission and then into your "Sent" IMAP folder.
    BURL can be used to directly send a message, which was previously uploaded to an IMAP server.
    This is useful on metered connections when sending large attachments.

    This proxy is **stateless** and starts a local smtp server to accept connections from MUAs.
    It advertises AUTH PLAIN and decodes information about the **upstream submission and IMAP servers from the supplied password**.
    It then takes your message, uploads it to the specified mailbox via IMAP (e.g. "Sent") and retrieves an [URLAUTH](https://tools.ietf.org/html/rfc4467) token for it.
    With this token it connects to the upstream submission server and sends the message with the BURL extension.

    It is probably ok for private use, but please do not deploy it on a larger scale.
    It might be very unstable and is **only tested with one mail setup**. It was tested with **dovecot** as IMAP and submission server.

    ## How to use

    Start the proxy:

    ```sh
    $ python3 burlproxy.py
    ```

    Your MUA has to connect with the following credentials for this to work:
    ```
        Username: The username of the upstream submission server

        Password: It has to consist of 10 strings, separated by | (pipes), (pipes, which are no separators, have to be url-encoded (| = %7c))

        1.  smtp_host:      upstream submission server hostname
        2.  smtp_port:      upstream submission server port
        3.  smtp_tls:       upstream submission server encryption (can be 'tls', 'starttls' or anything else to disable it)
        4.  smtp_password:  upstream submission server password
        5.  imap_host:      IMAP server hostname
        6.  imap_port:      IMAP server port
        7.  imap_tls:       IMAP server encryption (see smtp_tls)
        8.  imap_mailbox:   mailbox to store messages in (probably "Sent")
        9.  imap_username:  IMAP server username
        10. imap_password:  IMAP server password
    ```

    Example MUA settings:
    ```
        IMAP Server:            imap.example.com:143 starttls
        IMAP Username:          tom@example.com
        IMAP Password:          pass|word
        Submission Server:      localhost:1587 unencrypted
        Submission Username:    tom@example.com
        Submission Password:    smtp.example.com|587|starttls|pass%7cword|imap.example.com|143|starttls|Sent|tom@example.com|pass%7cword
    ```

    You should also disable saving sent messages in the Sent mailbox by your MUA, because that is the point of this proxy.

'''

import smtpd
import asyncore
import base64
import urllib.parse
import imaplib
import datetime
import re
import smtplib
import ssl
import logging

# how long urlauths should be valid
validity = datetime.timedelta(minutes=1)

# where we listen
local_smtp = ('localhost', 1587)

def setuplogging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    consolehandler = logging.StreamHandler()
    consolehandler.setLevel(logging.DEBUG)
    consoleformatter = logging.Formatter('%(name)s\t%(levelname)s\t%(message)s')
    consolehandler.setFormatter(consoleformatter)
    logger.addHandler(consolehandler)

setuplogging()

append_msgid_re = re.compile('\[APPENDUID \d+ (\d+)\]')
fetch_uid_re = re.compile('\(UID (\d+)\)')
genurlauth_re = re.compile('GENURLAUTH "([^"]+)"')

def decode_base64(s):
    # fix padding
    s += '=' * (3-len(s)%3)
    return base64.standard_b64decode(s)

def decode_auth_plain(s):
    # see RFC 4616 The PLAIN Simple Authentication and Security Layer (SASL) Mechanism
    # https://tools.ietf.org/html/rfc4616#page-3
    b = decode_base64(s)
    null = b'\x00'
    authzid, username, password = b.split(null, 3)
    return username.decode(), password.decode()

def decode_proxy_settings(s):
    # extract proxy settings from plain auth password
    data = s.split('|', 11) # 11th is remainder
    data = list(map(urllib.parse.unquote, data))
    return {
        'smtp_host': data[0],
        'smtp_port': int(data[1]),
        'smtp_tls': data[2],
        'smtp_password': data[3],
        'imap_host': data[4],
        'imap_port': int(data[5]),
        'imap_tls': data[6],
        'imap_mailbox': data[7],
        'imap_username': data[8],
        'imap_password': data[9]
    }

class ProxyChannel(smtpd.SMTPChannel):
    def __init__(self, server, conn, addr, *args, **kw):
        self.logger = logging.getLogger(str(addr))
        self.logger.info('channel opened')
        super().__init__(server, conn, addr, *args, **kw)
        self.proxy_settings = None
        self.imap = None
        self.smtp = None

    def smtp_EHLO(self, arg):
        self.logger.info('EHLO from client: %s', arg)
        # from python source:
        # https://github.com/python/cpython/blob/master/Lib/smtpd.py
        if not arg:
            self.push('501 Syntax: EHLO hostname')
            return
        # See issue #21783 for a discussion of this behavior.
        if self.seen_greeting:
            self.push('503 Duplicate HELO/EHLO')
            return
        self._set_rset_state()
        self.seen_greeting = arg
        self.extended_smtp = True
        self.push('250-%s' % self.fqdn)
        if self.data_size_limit:
            self.push('250-SIZE %s' % self.data_size_limit)
            self.command_size_limits['MAIL'] += 26
        if not self._decode_data:
            self.push('250-8BITMIME')
        if self.enable_SMTPUTF8:
            self.push('250-SMTPUTF8')
            self.command_size_limits['MAIL'] += 10
        # end
        self.push('250-AUTH PLAIN')
        self.push('250 HELP')

    def smtp_AUTH(self, arg):
        self.logger.info('AUTH')
        arg = arg[len(b'PLAIN '):]
        username, password = decode_auth_plain(arg)
        proxy_settings = decode_proxy_settings(password)
        proxy_settings['smtp_username'] = username
        self.proxy_settings = proxy_settings
        self.push('250 OK')

    def connect_imap(self):
        self.logger.info('connecting to imap server')
        s = self.proxy_settings
        if s['imap_tls'] in ['tls', 'ssl']:
            context = ssl.create_default_context()
            self.imap = imaplib.IMAP4_SSL(
                s['imap_host'],
                port=s['imap_port'],
                ssl_context=context)
        else:
            self.imap = imaplib.IMAP4(s['imap_host'], port=s['imap_port'])
            if s['imap_tls'] == 'starttls':
                context = ssl.create_default_context()
                self.logger.info('starttls to imap: %s', self.imap.starttls(ssl_context=context))
        self.logger.info('logging in: %s', self.imap.login(s['imap_username'], s['imap_password']))

    def store_message(self, data):
        self.logger.info('storing message')
        s = self.proxy_settings
        now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        typ, data = self.imap.append(s['imap_mailbox'], '\Seen', now, data)
        self.logger.info('append: %s', (typ, data))
        msgid = append_msgid_re.search(data[0].decode()).group(1)
        self.logger.info('got msgid: %s', msgid)
        return msgid

    def gen_urlauth(self, msgid):
        self.logger.info('retrieving urlauth token')
        s = self.proxy_settings
        self.logger.info('selecting mailbox: %s %s', s['imap_mailbox'], self.imap.select(s['imap_mailbox']))
        # I thought, that we need a uid instead of a msgid, but I guess not
        #typ, data = self.imap.fetch(msgid, '(UID)')
        #print((typ, data))
        #uid = fetch_uid_re.search(data[0].decode()).group(1)
        uid = msgid
        self.logger.info('found uid: %s', uid)
        now = datetime.datetime.utcnow().replace(tzinfo=datetime.timezone.utc)
        expire = now + validity
        expire_str = expire.isoformat(timespec='seconds')
        self.logger.info('token will expire on: %s', expire_str)
        command = 'GENURLAUTH "imap://{username};AUTH=*@{host}/{mailbox}/;UID={uid};EXPIRE={expire};URLAUTH=submit+{username}" INTERNAL\r\n'.format(
            username=urllib.parse.quote(s['imap_username']),
            host=s['imap_host'],
            mailbox=s['imap_mailbox'],
            uid=uid,
            expire=expire_str
        )
        tag = b'bp00 '
        self.logger.info('sending GENURLAUTH: %s', command)
        self.imap.send(tag + command.encode())
        response = ''
        while True:
            line = self.imap.readline()
            response += line.decode()
            if line.startswith(tag):
                break
        urlauth = genurlauth_re.search(response).group(1)
        self.logger.info('got urlauth: %s', urlauth)
        self.logger.info('closing imap: %s', self.imap.close())
        return urlauth

    def connect_smtp(self):
        self.logger.info('connecting to submission server')
        s = self.proxy_settings
        if s['smtp_tls'] in ['tls', 'ssl']:
            context = ssl.create_default_context()
            self.smtp = smtplib.SMTP_SSL(
                s['smtp_host'],
                port=s['smtp_port'],
                context=context)
        else:
            self.smtp = smtplib.SMTP(s['smtp_host'], port=s['smtp_port'])
            if s['smtp_tls'] == 'starttls':
                context = ssl.create_default_context()
                self.logger.info('starttls to submission: %s', self.smtp.starttls(context=context))
        self.logger.info('logging in: %s', self.smtp.login(s['smtp_username'], s['smtp_password']))
        typ, data = self.smtp.ehlo()
        self.logger.info('EHLO to submission: %s', (typ, data))
        if b'BURL' not in data:
            self.logger.warn('smtp server does not advertise BURL capability')

    def send_message(self, mailfrom, rcpttos, urlauth):
        self.logger.info('mail from: %s %s', mailfrom, self.smtp.docmd('MAIL', 'FROM:<{fr}>'.format(fr=mailfrom)))
        for rcpt in rcpttos:
            self.logger.info('rcpt to: %s %s', rcpt, self.smtp.docmd('RCPT', 'TO:<{to}>'.format(to=rcpt)))
        code, data = self.smtp.docmd('BURL', '{urlauth} LAST'.format(
            urlauth=urlauth
        ))
        self.logger.info('burl: %s', (code, data))
        return '{code} {data}'.format(
            code=code,
            data=data
        )

    def process_message(self, peer, mailfrom, rcpttos, data, **kw):
        self.logger.info('processing message: %s %s %s %s', peer, mailfrom, rcpttos, kw)
        self.connect_imap()
        msgid = self.store_message(data)
        urlauth = self.gen_urlauth(msgid)
        self.logger.info('logging out of imap: %s', self.imap.logout())
        self.connect_smtp()
        result = self.send_message(mailfrom, rcpttos, urlauth)
        self.logger.info('quitting smtp: %s', self.smtp.quit())
        self.logger.info('DONE')
        return result

    # from python source:
    # https://github.com/python/cpython/blob/master/Lib/smtpd.py
    def found_terminator(self):
        line = self._emptystring.join(self.received_lines)
        self.received_lines = []
        if self.smtp_state == self.COMMAND:
            sz, self.num_bytes = self.num_bytes, 0
            if not line:
                self.push('500 Error: bad syntax')
                return
            if not self._decode_data:
                line = str(line, 'utf-8')
            i = line.find(' ')
            if i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i+1:].strip()
            max_sz = (self.command_size_limits[command]
                        if self.extended_smtp else self.command_size_limit)
            if sz > max_sz:
                self.push('500 Error: line too long')
                return
            method = getattr(self, 'smtp_' + command, None)
            if not method:
                self.push('500 Error: command "%s" not recognized' % command)
                return
            method(arg)
            return
        else:
            if self.smtp_state != self.DATA:
                self.push('451 Internal confusion')
                self.num_bytes = 0
                return
            if self.data_size_limit and self.num_bytes > self.data_size_limit:
                self.push('552 Error: Too much mail data')
                self.num_bytes = 0
                return
            # Remove extraneous carriage returns and de-transparency according
            # to RFC 5321, Section 4.5.2.
            data = []
            for text in line.split(self._linesep):
                if text and text[0] == self._dotsep:
                    data.append(text[1:])
                else:
                    data.append(text)
            self.received_data = self._newline.join(data)
            args = (self.peer, self.mailfrom, self.rcpttos, self.received_data)
            kwargs = {}
            if not self._decode_data:
                kwargs = {
                    'mail_options': self.mail_options,
                    'rcpt_options': self.rcpt_options,
                }
            # end
            status = self.process_message(*args, **kwargs)
            self._set_post_data_state()
            if not status:
                self.push('250 OK')
            else:
                self.push(status)

class BurlProxy(smtpd.SMTPServer):
    channel_class = ProxyChannel

    def __init__(self, *args, **kw):
        self.logger = logging.getLogger(self.__class__.__name__)
        kw['enable_SMTPUTF8'] = True
        super().__init__(*args, **kw)
        self.logger.info('ready')

def main(local_smtp):
    proxy = BurlProxy(local_smtp, ('', 0))
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        pass
    finally:
        proxy.close()

if __name__ == '__main__':
    main(local_smtp)
