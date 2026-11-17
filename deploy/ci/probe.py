"""Test client for deploy/ci/test.sh. Runs on the compose network, so postfix sees an
untrusted client exactly as it would see the internet. Each subcommand exits non-zero on
failure and prints one line on success."""

import imaplib
import os
import smtplib
import socket
import ssl
import sys
import time
from email.message import EmailMessage

SMTP = "postfix"
IMAP = "dovecot"
EXTERNAL = "bob@example.org"

# The test certificate is self-signed: trust exactly that file. The hostname is not checked
# because the stack is reached by service name (postfix, dovecot), not by the certificate's.
TLS = ssl.create_default_context(cafile="/ca.crt")
TLS.check_hostname = False


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def message(sender, rcpt, subject, body, extra=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, rcpt, subject
    for k, v in (extra or {}).items():
        m[k] = v
    m.set_content(body)
    return m


def wait(*targets):
    """Block until every host:port accepts a TCP connection."""
    for t in targets:
        host, port = t.rsplit(":", 1)
        for _ in range(90):
            try:
                socket.create_connection((host, int(port)), timeout=2).close()
                break
            except OSError:
                time.sleep(1)
        else:
            fail(f"{t} never came up")
    print("up")


def deliver(rcpt, subject, body, spam=False):
    """Deliver from outside on port 25. Postscreen holds first-time clients for its greet wait."""
    extra = {"X-CI-Spam-Probe": "1"} if spam else None
    with smtplib.SMTP(SMTP, 25, timeout=60) as s:
        s.send_message(message(EXTERNAL, rcpt, subject, body, extra))
    print(f"delivered to {rcpt}")


def fetch(user, password, subject, body, folder="INBOX"):
    """Poll IMAPS until the message is in the folder, then check its body."""
    deadline = time.time() + 60
    while time.time() < deadline:
        with imaplib.IMAP4_SSL(IMAP, 993, ssl_context=TLS) as imap:
            imap.login(user, password)
            if imap.select(folder, readonly=True)[0] == "OK":
                _, ids = imap.search(None, "SUBJECT", f'"{subject}"')
                if ids[0]:
                    _, data = imap.fetch(ids[0].split()[0], "(RFC822)")
                    if body.encode() not in data[0][1]:
                        fail(f"message in {folder} has the wrong body")
                    print(f"found '{subject}' in {folder}")
                    return
        time.sleep(1)
    fail(f"'{subject}' never arrived in {folder}")


def absent(user, password, subject, folder="INBOX"):
    with imaplib.IMAP4_SSL(IMAP, 993, ssl_context=TLS) as imap:
        imap.login(user, password)
        imap.select(folder, readonly=True)
        _, ids = imap.search(None, "SUBJECT", f'"{subject}"')
        if ids[0]:
            fail(f"'{subject}' is in {folder} but should not be")
    print(f"'{subject}' is not in {folder}")


def relay_denied():
    with smtplib.SMTP(SMTP, 25, timeout=60) as s:
        s.ehlo()
        if s.has_extn("auth"):
            fail("port 25 advertises AUTH")
        code, _ = s.mail(EXTERNAL)
        if code != 250:
            fail(f"MAIL FROM refused unexpectedly ({code})")
        code, resp = s.rcpt("someone@example.org")
        if not 500 <= code < 600:
            fail(f"relay to example.org answered {code}, want 5xx")
    print(f"relay refused ({code}), no AUTH offered on 25")


def unknown_recipient():
    with smtplib.SMTP(SMTP, 25, timeout=60) as s:
        s.ehlo()
        s.mail(EXTERNAL)
        code, resp = s.rcpt("nobody@example.test")
        if not 500 <= code < 600:
            fail(f"unknown recipient answered {code}, want 5xx")
    print(f"unknown recipient refused ({code})")


def forged_sender(user, password):
    """Authenticated on 587, but claiming to be someone the login does not own."""
    with smtplib.SMTP(SMTP, 587, timeout=60) as s:
        s.starttls(context=TLS)
        s.login(user, password)
        code, resp = s.mail("mallory@example.test")
        if code == 250:
            code, resp = s.rcpt(EXTERNAL)
        if not 500 <= code < 600:
            fail(f"forged sender answered {code}, want 5xx")
    print(f"forged sender refused ({code})")


def submission_ok(user, password):
    """The legitimate counterpart of forged_sender, so a refusal cannot be a broken stack."""
    with smtplib.SMTP_SSL(SMTP, 465, timeout=60, context=TLS) as s:
        s.login(user, password)
        code, resp = s.mail(user)
        if code != 250:
            fail(f"own sender refused on 465 ({code} {resp!r})")
        code, resp = s.rcpt(user)
        if code != 250:
            fail(f"local recipient refused on 465 ({code} {resp!r})")
    print("own sender accepted on 465")


def auth_needs_tls(user, password):
    with smtplib.SMTP(SMTP, 587, timeout=60) as s:
        s.ehlo()
        if s.has_extn("auth"):
            fail("587 offers AUTH before STARTTLS")
    print("587 offers no AUTH before STARTTLS")


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    funcs = {
        "wait": wait,
        "deliver": lambda r, s, b, *rest: deliver(r, s, b, bool(rest)),
        "fetch": fetch,
        "absent": absent,
        "relay-denied": relay_denied,
        "unknown-recipient": unknown_recipient,
        "forged-sender": forged_sender,
        "submission-ok": submission_ok,
        "auth-needs-tls": auth_needs_tls,
    }
    if cmd not in funcs:
        fail(f"unknown command {cmd}")
    try:
        funcs[cmd](*args)
    except (smtplib.SMTPException, imaplib.IMAP4.error, OSError) as e:
        fail(f"{cmd}: {e!r}")


main()
