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

## License

GPLv3
