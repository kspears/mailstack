"""A browser's view of the web front door, for deploy/ci/test.sh. It reaches the admin UI
and rspamd's UI only through the proxy, by hostname, the way a visitor would, and checks
what the proxy and mailctl each promise. One argument: an enrolment token for an admin
who has not enrolled yet. Exits non-zero on the first broken promise."""

import base64
import hashlib
import hmac
import http.client
import re
import socket
import ssl
import struct
import sys
import time
import urllib.parse

ADMIN, RSPAMD, PROXY = "admin.example.test", "rspamd.example.test", "proxy"
FORGED = "203.0.113.99"

# The proxy's certificates come from its own throwaway authority, so they are not
# verified here; nothing in this test depends on who signed them.
TLS = ssl.create_default_context()
TLS.check_hostname = False
TLS.verify_mode = ssl.CERT_NONE


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


class Browser:
    """Keeps cookies per hostname, as a real one does for host-only cookies."""

    def __init__(self):
        self.cookies = {}

    def request(self, method, url, form=None, headers=None, follow=False, sni=None):
        for _ in range(10):
            u = urllib.parse.urlsplit(url)
            conn = http.client.HTTPSConnection(sni or u.hostname, 443, context=TLS, timeout=20)
            send = {"Host": u.hostname}
            jar = self.cookies.setdefault(u.hostname, {})
            if jar:
                send["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
            body = None
            if method == "POST":
                send["Sec-Fetch-Site"] = "same-origin"
                send["Content-Type"] = "application/x-www-form-urlencoded"
                body = urllib.parse.urlencode(form or {})
            send.update(headers or {})
            conn.request(method, u.path + ("?" + u.query if u.query else ""), body, send)
            r = conn.getresponse()
            text = r.read().decode("utf-8", "replace")
            for line in r.msg.get_all("Set-Cookie") or []:
                name, _, rest = line.partition("=")
                value = rest.split(";", 1)[0]
                if "Max-Age=0" in line or not value:
                    jar.pop(name, None)
                else:
                    if not name.startswith("__Host-") or "Secure" not in line or "HttpOnly" not in line:
                        fail(f"cookie {name} from {u.hostname} is not host-bound, Secure and HttpOnly: {line}")
                    jar[name] = value
            conn.close()
            if not follow or r.status not in (302, 303):
                return r.status, r.msg, text, url
            url, method, form = urllib.parse.urljoin(url, r.msg["Location"]), "GET", None
        fail(f"redirect loop ending at {url}")


def field(page, pattern, what):
    m = re.search(pattern, page)
    if not m:
        fail(f"no {what} in the page")
    return m.group(1)


def csrf(page):
    return field(page, r'name="csrf" value="([0-9a-f]+)"', "CSRF token")


def code(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return "%06d" % ((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000)


def main(token):
    password = "a-password-made-for-this-test-run"
    b = Browser()

    # Signed out, every door leads to the sign-in page.
    status, msg, _, _ = b.request("GET", f"https://{ADMIN}/mailboxes")
    if status != 303 or msg["Location"] != "/signin":
        fail(f"signed-out /mailboxes: {status} to {msg['Location']}")
    status, msg, _, _ = b.request("GET", f"https://{RSPAMD}/")
    if status != 302 or msg["Location"] != f"https://{RSPAMD}/_mailstack/start":
        fail(f"signed-out rspamd UI: {status} to {msg['Location']}, want the gate")
    status, msg, page, at = b.request("GET", f"https://{RSPAMD}/", follow=True)
    if status != 200 or at != f"https://{ADMIN}/signin":
        fail(f"signed-out rspamd UI ends at {status} {at}, want the admin sign-in page")
    if "max-age" not in (msg["Strict-Transport-Security"] or ""):
        fail("no Strict-Transport-Security header from the proxy")
    print("ok: signed out, the admin UI and the rspamd UI both lead to the sign-in page")

    # A failed sign-in that claims to come from somewhere else. test.sh reads the log.
    status, _, page, _ = b.request("POST", f"https://{ADMIN}/signin", headers={"X-Forwarded-For": FORGED},
                                   form={"csrf": csrf(page), "address": "nobody@example.test", "password": "wrong-on-purpose", "code": "000000"})
    if status != 200 or "Sign-in failed." not in page:
        fail(f"a wrong sign-in: {status}")

    # Enrol through the link the operator was given.
    status, _, page, _ = b.request("GET", f"https://{ADMIN}/enrol?t={token}")
    if status != 200:
        fail(f"enrolment link: {status}")
    secret = field(page, r"Key: <code>([A-Z2-7]+)</code>", "authenticator key")
    status, msg, _, _ = b.request("POST", f"https://{ADMIN}/enrol", form={
        "csrf": csrf(page), "token": token, "password": password, "password2": password, "code": code(secret)})
    if status != 303:
        fail(f"completing enrolment: {status}")
    status, _, page, _ = b.request("GET", f"https://{ADMIN}/mailboxes")
    if status != 200 or "alice@example.test" not in page:
        fail(f"signed-in /mailboxes: {status}")
    row = page[page.index("alice@example.test"):].split("</tr>", 1)[0]
    if " ago</td>" not in row:
        fail(f"alice's mailbox row shows no delivery: {row}")
    print("ok: enrolled through the link and signed in, through the proxy")

    status, msg, _, _ = b.request("GET", f"https://{ADMIN}/")
    if status != 303 or msg["Location"] != "/status":
        fail(f"signed-in /: {status} to {msg['Location']}, want /status")
    # Never the verdict: CI runners' disks are often more than 80% full.
    status, _, page, _ = b.request("GET", f"https://{ADMIN}/status")
    if status != 200 or "Postfix watcher" not in page:
        fail(f"signed-in /status: {status}")
    print("ok: the status page and last delivery per mailbox")

    # The hand-off carries the sign-in to the rspamd hostname and no further.
    status, _, page, at = b.request("GET", f"https://{RSPAMD}/", follow=True)
    if status != 200 or at != f"https://{RSPAMD}/" or "rspamd" not in page.lower():
        fail(f"rspamd UI after the hand-off: {status} at {at}")
    if "__Host-mailctl" in b.cookies[RSPAMD] or "__Host-mailctl-rspamd" in b.cookies[ADMIN]:
        fail("a cookie crossed between the two hostnames")
    # rspamd still wants its own password, and its own /auth path still reaches rspamd.
    status, _, _, _ = b.request("GET", f"https://{RSPAMD}/stat")
    if status not in (401, 403):
        fail(f"rspamd /stat with no controller password: {status}, want a refusal")
    with open("/rspamd-controller-password") as f:
        status, _, page, _ = b.request("GET", f"https://{RSPAMD}/auth", headers={"Password": f.read().strip()})
    if status != 200 or "version" not in page:
        fail(f"rspamd's own /auth through the gate: {status} {page[:80]}")
    print("ok: a signed-in admin reaches the rspamd UI, which still asks for its own password")

    # Signing out of the admin UI closes the rspamd UI too.
    _, _, page, _ = b.request("GET", f"https://{ADMIN}/mailboxes")
    status, _, _, _ = b.request("POST", f"https://{ADMIN}/signout", form={"csrf": csrf(page)})
    if status != 303:
        fail(f"sign-out: {status}")
    status, _, _, _ = b.request("GET", f"https://{RSPAMD}/")
    if status != 302:
        fail(f"rspamd UI after signing out of the admin UI: {status}, want the gate again")
    print("ok: signing out of the admin UI closes the rspamd UI")

    # The proxy itself: one hostname's certificate does not open another's backend, an
    # unknown name gets no page, and nothing listens on port 80.
    status, _, page, _ = Browser().request("GET", f"https://{RSPAMD}/_mailstack/start", sni=ADMIN)
    if status == 302:
        fail("a request naming one host in TLS and another in HTTP was served")
    try:
        with socket.create_connection((PROXY, 443), timeout=10) as raw:
            with TLS.wrap_socket(raw, server_hostname="other.example.test") as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: other.example.test\r\n\r\n")
                if s.recv(1024):
                    fail("the proxy answered for a hostname it does not serve")
    except (ssl.SSLError, ConnectionError):
        pass
    try:
        socket.create_connection((PROXY, 80), timeout=5).close()
        fail("the proxy listens on port 80")
    except OSError:
        pass
    print("ok: the proxy serves only its two hostnames, and nothing on port 80")


main(sys.argv[1])
