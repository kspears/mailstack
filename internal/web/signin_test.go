package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/kspears/mailstack/internal/auth"
)

// browser is a visitor with a cookie jar, for the flows that start signed out.
type browser struct {
	u       *ui
	cookies map[string]string
	from    string // socket address; the proxy's unless a test says otherwise
	forward string // what the proxy says the visitor's address is
}

func (u *ui) browser() *browser {
	return &browser{u: u, cookies: map[string]string{}, from: "192.0.2.1:4000", forward: "203.0.113.7"}
}

func (b *browser) send(method, host, path, contentType string, body []byte, headers map[string]string) resp {
	b.u.t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Host, r.RemoteAddr = host, b.from
	r.Header.Set("X-Forwarded-For", b.forward)
	for name, value := range b.cookies {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	if method == http.MethodPost {
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", contentType)
	}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	b.u.h.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			if !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" || !strings.HasPrefix(c.Name, "__Host-") {
				b.u.t.Errorf("cookie %s is not host-bound, Secure and HttpOnly: %+v", c.Name, c)
			}
			b.cookies[c.Name] = c.Value
		}
	}
	out, _ := io.ReadAll(w.Result().Body)
	return resp{w.Code, string(out), w.Result().Header}
}

func (b *browser) get(path string) resp {
	return b.send(http.MethodGet, adminHost, path, "", nil, nil)
}

func csrfIn(t *testing.T, body string) string {
	t.Helper()
	const marker = `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("no csrf field in:\n%s", body)
	}
	rest := body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
}

// post fills in the form found on page and submits it to path.
func (b *browser) post(page, path string, form url.Values) resp {
	b.u.t.Helper()
	form.Set("csrf", csrfIn(b.u.t, b.get(page).body))
	return b.send(http.MethodPost, adminHost, path, "application/x-www-form-urlencoded", []byte(form.Encode()), nil)
}

func (b *browser) signIn(address, password, code string) resp {
	b.u.t.Helper()
	return b.post("/signin", "/signin", url.Values{"address": {address}, "password": {password}, "code": {code}})
}

func (b *browser) signedIn() bool {
	r := b.get("/mailboxes")
	return r.code == http.StatusOK
}

func wantFailed(t *testing.T, what string, r resp) {
	t.Helper()
	if r.code != http.StatusOK || !strings.Contains(r.body, ">Sign-in failed.</p>") || r.header.Get("Set-Cookie") != "" && strings.Contains(r.header.Get("Set-Cookie"), "__Host-mailctl=") {
		t.Errorf("%s: status %d, want the sign-in page saying only that it failed:\n%s", what, r.code, r.body)
	}
}

// tick moves the clock to the next authenticator step, where a fresh code is due.
func (u *ui) tick() { u.now = u.now.Add(30 * time.Second) }

func TestSignIn(t *testing.T) {
	u := newUI(t)
	u.tick()
	for what, try := range map[string][3]string{
		"password alone":               {adminEmail, adminPw, ""},
		"wrong code":                   {adminEmail, adminPw, "000000"},
		"wrong password, right code":   {adminEmail, "not the password at all", u.code(u.secret)},
		"unknown address":              {"nobody@example.test", adminPw, u.code(u.secret)},
		"a mailbox, not an admin":      {"alice@example.test", pw, u.code(u.secret)},
		"password over bcrypt's limit": {adminEmail, strings.Repeat("x", 100), u.code(u.secret)},
	} {
		b := u.browser()
		wantFailed(t, what, b.signIn(try[0], try[1], try[2]))
		if b.signedIn() {
			t.Errorf("%s: signed in", what)
		}
	}

	b := u.browser()
	code := u.code(u.secret)
	if r := b.signIn("  Admin@Example.test ", adminPw, code); r.code != http.StatusSeeOther || r.header.Get("Location") != "/mailboxes" || !b.signedIn() {
		t.Fatalf("right password and code: status %d, signed in %v", r.code, b.signedIn())
	}
	wantFailed(t, "the same code again", u.browser().signIn(adminEmail, adminPw, code))

	// The failures were logged with the visitor's address first, as the proxy gave it.
	var failures int
	for _, line := range u.log {
		if strings.HasPrefix(line, "sign-in failed from=203.0.113.7 ") {
			failures++
		}
	}
	if failures != 7 {
		t.Errorf("%d failures logged with the visitor's address, want 7:\n%s", failures, strings.Join(u.log, "\n"))
	}
}

func TestSignInFormIsNotForgeable(t *testing.T) {
	u := newUI(t)
	u.tick()
	form := func(b *browser) url.Values {
		return url.Values{"csrf": {csrfIn(t, b.get("/signin").body)}, "address": {adminEmail}, "password": {adminPw}, "code": {u.code(u.secret)}}
	}
	post := func(b *browser, f url.Values, headers map[string]string) resp {
		return b.send(http.MethodPost, adminHost, "/signin", "application/x-www-form-urlencoded", []byte(f.Encode()), headers)
	}
	b := u.browser()
	if r := post(b, form(b), map[string]string{"Sec-Fetch-Site": "same-site"}); r.code != http.StatusForbidden {
		t.Errorf("sign-in posted from a sibling hostname: %d, want 403", r.code)
	}
	b = u.browser()
	f := form(b)
	if r := post(u.browser(), f, nil); r.code != http.StatusForbidden {
		t.Errorf("sign-in with another visitor's token: %d, want 403", r.code)
	}
	if r := post(b, f, nil); r.code != http.StatusSeeOther {
		t.Errorf("the untouched form: %d, want 303", r.code)
	}
}

func TestWrongCodesLockPasswordSignInButWrongPasswordsDoNot(t *testing.T) {
	u := newUI(t)
	for range 50 {
		u.browser().signIn(adminEmail, "a guess from a stranger", "123456")
	}
	u.tick()
	if b := u.browser(); b.signIn(adminEmail, adminPw, u.code(u.secret)).code != http.StatusSeeOther {
		t.Fatal("50 wrong passwords locked the admin out")
	}
	for range auth.CodeFailureLimit {
		u.browser().signIn(adminEmail, adminPw, "000000")
	}
	u.tick()
	wantFailed(t, "right password and code after 10 wrong codes", u.browser().signIn(adminEmail, adminPw, u.code(u.secret)))
	u.now = u.now.Add(auth.CodeFailureWindow + time.Minute)
	if b := u.browser(); b.signIn(adminEmail, adminPw, u.code(u.secret)).code != http.StatusSeeOther {
		t.Error("still locked an hour after the last wrong code")
	}
}

func TestSessionsEnd(t *testing.T) {
	u := newUI(t)
	signIn := func() *browser {
		u.tick()
		b := u.browser()
		if b.signIn(adminEmail, adminPw, u.code(u.secret)).code != http.StatusSeeOther {
			t.Fatal("could not sign in")
		}
		return b
	}

	b := signIn()
	u.now = u.now.Add(auth.SessionLife - time.Minute)
	if !b.signedIn() {
		t.Error("session ended early")
	}
	u.now = u.now.Add(2 * time.Minute)
	if b.signedIn() {
		t.Error("session outlived 12 hours")
	}

	b = signIn()
	stolen := b.cookies["__Host-"+sessionCookie]
	if r := b.post("/mailboxes", "/signout", url.Values{}); r.code != http.StatusSeeOther || r.header.Get("Location") != "/signin" {
		t.Fatalf("sign-out: %d", r.code)
	}
	b.cookies["__Host-"+sessionCookie] = stolen
	if b.signedIn() {
		t.Error("a copy of the cookie still works after sign-out")
	}

	b = signIn()
	if _, err := u.auth.ResetAdmin("cli:test", adminEmail); err != nil {
		t.Fatal(err)
	}
	if b.signedIn() {
		t.Error("session survived a reset")
	}
	u.tick()
	wantFailed(t, "old password after a reset", u.browser().signIn(adminEmail, adminPw, u.code(u.secret)))
}

func TestEnrolmentLink(t *testing.T) {
	u := newUI(t)
	newLink := func() string {
		token, err := u.auth.ResetAdmin("cli:test", adminEmail)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	secretIn := func(body string) string {
		const marker = "Key: <code>"
		i := strings.Index(body, marker)
		if i < 0 {
			t.Fatalf("no authenticator key in:\n%s", body)
		}
		rest := body[i+len(marker):]
		return rest[:strings.Index(rest, "<")]
	}
	enrol := func(b *browser, token, password, code string) resp {
		return b.post("/enrol?t="+token, "/enrol", url.Values{"token": {token}, "password": {password}, "password2": {password}, "code": {code}})
	}
	const newPw = "a brand new admin password"

	token := newLink()
	b := u.browser()
	// A link preview, or the admin looking twice, must not spend it.
	for range 3 {
		if r := u.browser().get("/enrol?t=" + token); r.code != http.StatusOK || !strings.Contains(r.body, adminEmail) {
			t.Fatalf("opening the link: %d", r.code)
		}
	}
	page := b.get("/enrol?t=" + token)
	if qr := b.get("/enrol/qr?t=" + token); qr.code != http.StatusOK || qr.header.Get("Content-Type") != "image/png" {
		t.Errorf("QR code: %d %s", qr.code, qr.header.Get("Content-Type"))
	}
	if !strings.Contains(page.header.Get("Content-Security-Policy"), "img-src 'self'") {
		t.Error("the enrolment page may not show its QR code")
	}
	secret := secretIn(page.body)
	// The key belongs to the browser it was shown to. Whatever else opened the
	// link, a preview bot or someone reading a log, saw a key that is never stored.
	if elsewhere := secretIn(u.browser().get("/enrol?t=" + token).body); elsewhere == secret {
		t.Error("two browsers opening the link were shown the same authenticator key")
	}
	if again := secretIn(b.get("/enrol?t=" + token).body); again != secret {
		t.Error("reloading the page changed the key, so a code already scanned would stop matching")
	}
	if strings.Contains(page.body, "<script") || strings.Contains(page.header.Get("Content-Security-Policy"), "script-src") {
		t.Error("the enrolment page carries a script")
	}
	// Mistakes leave the link usable.
	if r := enrol(b, token, "short", u.code(secret)); r.code != http.StatusOK || !strings.Contains(r.body, "error: password must be at least 12 characters") {
		t.Errorf("short password: %d\n%s", r.code, r.body)
	}
	if r := enrol(b, token, newPw, "000000"); r.code != http.StatusOK || !strings.Contains(r.body, "error: that code does not match") {
		t.Errorf("wrong code: %d\n%s", r.code, r.body)
	}
	if r := enrol(b, token, newPw, u.code(secret)); r.code != http.StatusSeeOther || !b.signedIn() {
		t.Fatalf("completing enrolment: %d, signed in %v", r.code, b.signedIn())
	}
	if r := u.browser().get("/enrol?t=" + token); r.code != http.StatusNotFound || strings.Contains(r.body, "<form") {
		t.Errorf("a used link: %d", r.code)
	}
	u.tick()
	if r := u.browser().signIn(adminEmail, newPw, u.code(secret)); r.code != http.StatusSeeOther {
		t.Errorf("signing in with what enrolment set: %d", r.code)
	}

	older, newer := newLink(), newLink()
	if r := u.browser().get("/enrol?t=" + older); r.code != http.StatusNotFound {
		t.Errorf("a link replaced by a newer one: %d, want 404", r.code)
	}
	u.now = u.now.Add(auth.EnrolmentLife + time.Minute)
	if r := u.browser().get("/enrol?t=" + newer); r.code != http.StatusNotFound {
		t.Errorf("a link after 24 hours: %d, want 404", r.code)
	}
	if r := u.browser().get("/enrol?t=nonsense"); r.code != http.StatusNotFound {
		t.Errorf("a made-up link: %d, want 404", r.code)
	}
}

func TestChangingCredentialsNeedsFreshProof(t *testing.T) {
	u := newUI(t)
	u.tick()
	b := u.browser()
	b.signIn(adminEmail, adminPw, u.code(u.secret))
	const newPw = "the second admin password"
	change := func() resp {
		r := b.post("/account", "/account/password", url.Values{"password": {newPw}, "password2": {newPw}})
		return b.get(r.header.Get("Location"))
	}

	u.now = u.now.Add(auth.ProofLife + time.Minute)
	if r := change(); !strings.Contains(r.body, "error: confirm it is you first") {
		t.Errorf("password changed 6 minutes after sign-in:\n%s", r.body)
	}
	if page := b.get("/account"); strings.Contains(page.body, `action="/account/password"`) || !strings.Contains(page.body, `action="/account/prove"`) {
		t.Error("a stale session is offered the change forms, or not offered a way to confirm")
	}
	if r := b.get(b.post("/account", "/account/prove", url.Values{"password": {adminPw}, "code": {"000000"}}).header.Get("Location")); !strings.Contains(r.body, "error: Sign-in failed.") {
		t.Errorf("a wrong proof:\n%s", r.body)
	}
	u.tick()
	b.post("/account", "/account/prove", url.Values{"password": {adminPw}, "code": {u.code(u.secret)}})
	other := u.browser()
	u.tick()
	other.signIn(adminEmail, adminPw, u.code(u.secret))
	if r := change(); !strings.Contains(r.body, "ok: changed your password") {
		t.Fatalf("password change after a fresh proof:\n%s", r.body)
	}
	if !b.signedIn() || other.signedIn() {
		t.Errorf("after a password change: this session %v (want true), the other %v (want false)", b.signedIn(), other.signedIn())
	}

	// Replacing the authenticator: the old one works until the new one is confirmed.
	page := b.post("/account", "/account/authenticator/new", url.Values{})
	i := strings.Index(page.body, "Key: <code>")
	if i < 0 {
		t.Fatalf("no new key shown:\n%s", page.body)
	}
	replacement := page.body[i+len("Key: <code>"):]
	replacement = replacement[:strings.Index(replacement, "<")]
	if qr := b.get("/account/authenticator/qr"); qr.code != http.StatusOK || qr.header.Get("Content-Type") != "image/png" {
		t.Errorf("replacement QR code: %d", qr.code)
	}
	b.post("/account", "/account/authenticator", url.Values{"code": {"000000"}})
	u.tick()
	if u.browser().signIn(adminEmail, newPw, u.code(u.secret)).code != http.StatusSeeOther {
		t.Error("the old authenticator stopped working before the new one was confirmed")
	}
	// The replacement page was opened once; its key is still the pending one.
	third := u.browser()
	u.tick()
	third.signIn(adminEmail, newPw, u.code(u.secret))
	b.post("/account", "/account/authenticator", url.Values{"code": {u.code(replacement)}})
	if !b.signedIn() || third.signedIn() {
		t.Errorf("after replacing the authenticator: this session %v (want true), another %v (want false)", b.signedIn(), third.signedIn())
	}
	u.tick()
	wantFailed(t, "the old authenticator after replacement", u.browser().signIn(adminEmail, newPw, u.code(u.secret)))
	if u.browser().signIn(adminEmail, newPw, u.code(replacement)).code != http.StatusSeeOther {
		t.Error("the new authenticator does not sign in")
	}

	entries, _ := u.admin.Log()
	var actions []string
	for _, e := range entries {
		if strings.HasPrefix(e.Action, "admin.") && e.Actor == adminEmail {
			actions = append(actions, e.Action)
		}
	}
	if got := strings.Join(actions, " "); got != "admin.enrol admin.password admin.authenticator" {
		t.Errorf("logged credential changes: %q", got)
	}
}

func TestVisitorAddressIsBelievedOnlyFromTheProxy(t *testing.T) {
	u := newUI(t)
	b := u.browser()
	b.from, b.forward = "198.51.100.9:5000", "203.0.113.7"
	b.signIn(adminEmail, "wrong password entirely", "000000")
	b = u.browser()
	b.forward = "not-an-address"
	b.signIn(adminEmail, "wrong password entirely", "000000")
	b = u.browser()
	b.forward = "198.51.100.200, 203.0.113.8"
	b.signIn(adminEmail, "wrong password entirely", "000000")
	var got []string
	for _, line := range u.log {
		if rest, ok := strings.CutPrefix(line, "sign-in failed from="); ok {
			got = append(got, strings.Fields(rest)[0])
		}
	}
	// A stranger's header is ignored; an unreadable one falls back to the
	// proxy's own address; of a list, the entry the proxy appended counts.
	if want := "198.51.100.9 192.0.2.1 203.0.113.8"; strings.Join(got, " ") != want {
		t.Errorf("logged addresses %q, want %q", strings.Join(got, " "), want)
	}
}

func TestHostnamesKeepToTheirOwnPaths(t *testing.T) {
	u := newUI(t)
	b := u.browser()
	for _, tc := range []struct {
		host, path string
		want       int
	}{
		{adminHost, "/signin", http.StatusOK},
		{"MAIL.example.test", "/signin", http.StatusOK},
		{rspamdHost, "/signin", http.StatusMisdirectedRequest},
		{rspamdHost, "/mailboxes", http.StatusMisdirectedRequest},
		{"evil.example.org", "/signin", http.StatusMisdirectedRequest},
		{adminHost, gatePrefix + "start", http.StatusMisdirectedRequest},
		{adminHost, gatePrefix + "finish", http.StatusMisdirectedRequest},
		{rspamdHost, gatePrefix + "start", http.StatusFound},
		{"admin:8080", gatePrefix + "check", http.StatusFound},
	} {
		if r := b.send(http.MethodGet, tc.host, tc.path, "", nil, nil); r.code != tc.want {
			t.Errorf("%s%s: %d, want %d", tc.host, tc.path, r.code, tc.want)
		}
	}
}

// --- the rspamd gate ---------------------------------------------------------

func TestRspamdHandOff(t *testing.T) {
	u := newUI(t)
	u.tick()
	b := u.browser()
	b.signIn(adminEmail, adminPw, u.code(u.secret))
	gate := func(b *browser, path string) resp { return b.send(http.MethodGet, rspamdHost, path, "", nil, nil) }
	allowed := func(b *browser) bool { return gate(b, gatePrefix+"check").code == http.StatusNoContent }

	// The browser's cookies are per name here, not per host, so keep two jars:
	// what the browser would send the rspamd hostname, and the admin hostname.
	rs := u.browser()
	check := gate(rs, gatePrefix+"check")
	if check.code != http.StatusFound || check.header.Get("Location") != "https://"+rspamdHost+gatePrefix+"start" {
		t.Fatalf("no rspamd session: %d to %q", check.code, check.header.Get("Location"))
	}
	start := gate(rs, gatePrefix+"start")
	to, err := url.Parse(start.header.Get("Location"))
	if err != nil || to.Host != adminHost || to.Path != "/handoff" {
		t.Fatalf("start redirects to %q", start.header.Get("Location"))
	}
	if r := u.browser().get(to.RequestURI()); r.code != http.StatusSeeOther || r.header.Get("Location") != "/signin" {
		t.Errorf("hand-off without an admin session: %d to %q, want the sign-in page", r.code, r.header.Get("Location"))
	}
	back := b.get(to.RequestURI())
	finish, err := url.Parse(back.header.Get("Location"))
	if err != nil || finish.Host != rspamdHost || finish.Path != gatePrefix+"finish" {
		t.Fatalf("hand-off redirects to %q", back.header.Get("Location"))
	}

	// The ticket in another browser, which has no nonce: refused, and spent.
	if r := gate(u.browser(), finish.RequestURI()); r.code != http.StatusForbidden {
		t.Errorf("ticket without the nonce: %d, want 403", r.code)
	}
	if r := gate(rs, finish.RequestURI()); r.code != http.StatusForbidden {
		t.Errorf("a ticket already tried once: %d, want 403", r.code)
	}

	// Again, undisturbed.
	handOff := func() *browser {
		rs := u.browser()
		to, _ := url.Parse(gate(rs, gatePrefix+"start").header.Get("Location"))
		finish, _ := url.Parse(b.get(to.RequestURI()).header.Get("Location"))
		if r := gate(rs, finish.RequestURI()); r.code != http.StatusFound || r.header.Get("Location") != "/" {
			t.Fatalf("finish: %d to %q", r.code, r.header.Get("Location"))
		}
		return rs
	}
	rs = handOff()
	if !allowed(rs) {
		t.Fatal("no rspamd session after the hand-off")
	}
	if r := gate(rs, finish.RequestURI()); r.code != http.StatusForbidden {
		t.Errorf("a used ticket: %d, want 403", r.code)
	}

	// Each cookie opens only its own hostname's door.
	asAdmin := u.browser()
	asAdmin.cookies["__Host-"+sessionCookie] = rs.cookies["__Host-"+rspamdCookie]
	if asAdmin.signedIn() {
		t.Error("the rspamd cookie signs in to the admin UI")
	}
	asRspamd := u.browser()
	asRspamd.cookies["__Host-"+rspamdCookie] = b.cookies["__Host-"+sessionCookie]
	if allowed(asRspamd) {
		t.Error("the admin cookie opens the rspamd UI")
	}

	// Signing out of the admin UI closes the rspamd UI too, and so does a reset.
	b.post("/mailboxes", "/signout", url.Values{})
	if allowed(rs) {
		t.Error("the rspamd session outlived the admin session it came from")
	}
	u.tick()
	b.signIn(adminEmail, adminPw, u.code(u.secret))
	rs = handOff()
	if _, err := u.auth.ResetAdmin("cli:test", adminEmail); err != nil {
		t.Fatal(err)
	}
	if allowed(rs) {
		t.Error("the rspamd session outlived a reset of its admin")
	}
}

// --- passkeys ----------------------------------------------------------------

// authenticator is a software passkey: one credential, bound to one user
// handle, that always verifies its user.
type authenticator struct {
	t      *testing.T
	key    *ecdsa.PrivateKey
	id     []byte
	handle []byte
	count  uint32
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (a *authenticator) clientData(kind, challenge string) []byte {
	out, _ := json.Marshal(map[string]any{"type": kind, "challenge": challenge, "origin": "https://" + adminHost, "crossOrigin": false})
	return out
}

func (a *authenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(adminHost))
	flags := byte(0x01 | 0x04) // user present, user verified
	if attested {
		flags |= 0x40
	}
	a.count++
	out := append(rp[:], flags)
	out = binary.BigEndian.AppendUint32(out, a.count)
	if !attested {
		return out
	}
	out = append(out, make([]byte, 16)...) // AAGUID
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.id)))
	out = append(out, a.id...)
	pub := a.key.PublicKey
	cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pub.X.FillBytes(make([]byte, 32)), -3: pub.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		a.t.Fatal(err)
	}
	return append(out, cose...)
}

// create answers a registration challenge.
func (a *authenticator) create(options []byte) []byte {
	var o struct {
		PublicKey struct {
			Challenge string
			User      struct{ ID string }
		}
	}
	if err := json.Unmarshal(options, &o); err != nil {
		a.t.Fatal(err)
	}
	a.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a.id = make([]byte, 16)
	rand.Read(a.id)
	a.handle, _ = base64.RawURLEncoding.DecodeString(o.PublicKey.User.ID)
	attestation, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(true)})
	if err != nil {
		a.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(a.clientData("webauthn.create", o.PublicKey.Challenge)), "attestationObject": b64(attestation)}})
	return out
}

// get answers a sign-in challenge.
func (a *authenticator) get(options []byte) []byte {
	var o struct{ PublicKey struct{ Challenge string } }
	if err := json.Unmarshal(options, &o); err != nil {
		a.t.Fatal(err)
	}
	clientData, authData := a.clientData("webauthn.get", o.PublicKey.Challenge), a.authData(false)
	hash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(authData, hash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	out, _ := json.Marshal(map[string]any{"id": b64(a.id), "rawId": b64(a.id), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64(clientData), "authenticatorData": b64(authData), "signature": b64(sig), "userHandle": b64(a.handle)}})
	return out
}

// script does what passkey.js does: begin, let answer respond, finish.
func (b *browser) script(page, begin, finish string, answer func(options []byte) []byte) resp {
	b.u.t.Helper()
	headers := map[string]string{"X-CSRF": csrfIn(b.u.t, b.get(page).body)}
	started := b.send(http.MethodPost, adminHost, begin, "", nil, headers)
	if started.code != http.StatusOK {
		return started
	}
	return b.send(http.MethodPost, adminHost, finish, "application/json", answer([]byte(started.body)), headers)
}

func TestPasskeys(t *testing.T) {
	u := newUI(t)
	const otherEmail = "other@example.test"
	otherSecret, _ := u.enrol(otherEmail)
	u.tick()
	admin, other := u.browser(), u.browser()
	admin.signIn(adminEmail, adminPw, u.code(u.secret))
	other.signIn(otherEmail, adminPw, u.code(otherSecret))

	if page := admin.get("/account"); !strings.Contains(page.header.Get("Content-Security-Policy"), "script-src 'self'") || !strings.Contains(page.body, `<script src="/static/passkey.js" defer>`) {
		t.Error("the account page cannot run the passkey script")
	}
	if page := admin.get("/mailboxes"); strings.Contains(page.header.Get("Content-Security-Policy"), "script-src") || strings.Contains(page.body, "<script") {
		t.Error("a page with no passkey button carries a script")
	}

	key := &authenticator{t: t}
	if r := admin.script("/account", "/account/passkeys/begin?label=Test+phone", "/account/passkeys/finish", key.create); r.code != http.StatusNoContent {
		t.Fatalf("adding a passkey: %d %s", r.code, r.body)
	}
	if page := admin.get("/account"); !strings.Contains(page.body, "<td>Test phone</td>") {
		t.Errorf("the new passkey is not listed:\n%s", page.body)
	}

	// Signing in with it needs no address, password or code.
	b := u.browser()
	if r := b.script("/signin", "/signin/passkey/begin", "/signin/passkey/finish", key.get); r.code != http.StatusNoContent || !b.signedIn() {
		t.Fatalf("passkey sign-in: %d %s", r.code, r.body)
	}
	if page := b.get("/account"); !strings.Contains(page.body, ">"+adminEmail+"</a>") {
		t.Error("the passkey signed in as someone other than its owner")
	}

	// It proves only its own admin.
	u.now = u.now.Add(auth.ProofLife + time.Minute)
	if r := other.script("/account", "/account/prove/passkey/begin", "/account/prove/passkey/finish", key.get); r.code != http.StatusBadRequest || strings.TrimSpace(r.body) != "Sign-in failed." {
		t.Errorf("another admin's passkey as proof: %d %q", r.code, r.body)
	}
	if page := other.get("/account"); strings.Contains(page.body, `action="/account/password"`) {
		t.Error("another admin's passkey refreshed this session")
	}
	if r := admin.script("/account", "/account/prove/passkey/begin", "/account/prove/passkey/finish", key.get); r.code != http.StatusNoContent {
		t.Errorf("own passkey as proof: %d %s", r.code, r.body)
	}

	// An answer signed by a different key, an answer replayed, and a request
	// from another site are all refused.
	forged := &authenticator{t: t, id: key.id, handle: key.handle}
	forged.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if r := u.browser().script("/signin", "/signin/passkey/begin", "/signin/passkey/finish", forged.get); r.code != http.StatusBadRequest {
		t.Errorf("an answer from the wrong key: %d", r.code)
	}
	var answer []byte
	b = u.browser()
	b.script("/signin", "/signin/passkey/begin", "/signin/passkey/finish", func(o []byte) []byte { answer = key.get(o); return answer })
	replay := u.browser()
	if r := replay.script("/signin", "/signin/passkey/begin", "/signin/passkey/finish", func([]byte) []byte { return answer }); r.code != http.StatusBadRequest || replay.signedIn() {
		t.Errorf("a replayed answer: %d", r.code)
	}
	b = u.browser()
	token := csrfIn(t, b.get("/signin").body)
	if r := b.send(http.MethodPost, adminHost, "/signin/passkey/begin", "", nil, map[string]string{"X-CSRF": token, "Sec-Fetch-Site": "same-site"}); r.code != http.StatusForbidden {
		t.Errorf("a challenge requested from a sibling hostname: %d", r.code)
	}
	if r := b.send(http.MethodPost, adminHost, "/signin/passkey/begin", "", nil, nil); r.code != http.StatusForbidden {
		t.Errorf("a challenge requested without the token: %d", r.code)
	}

	// A passkey answers only for the admin it was made for: the same credential
	// presented with the other admin's handle is refused.
	otherKey := &authenticator{t: t}
	u.tick()
	other.post("/account", "/account/prove", url.Values{"password": {adminPw}, "code": {u.code(otherSecret)}})
	if r := other.script("/account", "/account/passkeys/begin", "/account/passkeys/finish", otherKey.create); r.code != http.StatusNoContent {
		t.Fatalf("the other admin adding a passkey: %d %s", r.code, r.body)
	}
	crossed := &authenticator{t: t, key: key.key, id: key.id, handle: otherKey.handle}
	b = u.browser()
	if r := b.script("/signin", "/signin/passkey/begin", "/signin/passkey/finish", crossed.get); r.code != http.StatusBadRequest || b.signedIn() {
		t.Errorf("one admin's passkey with another admin's handle: %d, signed in %v", r.code, b.signedIn())
	}

	// One visitor may hold only a few challenges, so a flood cannot crowd the admins out.
	flood := u.browser()
	flood.forward = "203.0.113.50"
	headers := map[string]string{"X-CSRF": csrfIn(t, flood.get("/signin").body)}
	var refused int
	for range 15 {
		if flood.send(http.MethodPost, adminHost, "/signin/passkey/begin", "", nil, headers).code != http.StatusOK {
			refused++
		}
	}
	if refused != 5 {
		t.Errorf("%d of 15 challenges refused to one visitor, want 5", refused)
	}
	if r := u.browser().script("/signin", "/signin/passkey/begin", "/signin/passkey/finish", key.get); r.code != http.StatusNoContent {
		t.Errorf("another visitor's passkey sign-in during the flood: %d %s", r.code, r.body)
	}

	// Removing it, which only its owner can do, ends its use.
	id := b64(key.id)
	if r := other.get(other.post("/account", "/account/passkeys/remove", url.Values{"id": {id}}).header.Get("Location")); !strings.Contains(r.body, "error:") {
		t.Errorf("another admin removed the passkey:\n%s", r.body)
	}
	if r := admin.get(admin.post("/account", "/account/passkeys/remove", url.Values{"id": {id}}).header.Get("Location")); !strings.Contains(r.body, "ok: removed the passkey") {
		t.Errorf("removing own passkey:\n%s", r.body)
	}
	if r := u.browser().script("/signin", "/signin/passkey/begin", "/signin/passkey/finish", key.get); r.code != http.StatusBadRequest {
		t.Errorf("a removed passkey still signs in: %d", r.code)
	}
}

// The log is what bans are made from, and the path of a request is the
// visitor's to choose. It must not be able to forge a line, or part of one.
func TestRequestPathCannotForgeALogLine(t *testing.T) {
	u := newUI(t)
	u.log = nil
	b := u.browser()
	b.send(http.MethodGet, adminHost, "/x%0A2026/11/18%2009:00:00%20sign-in%20failed%20from=198.51.100.9%20address=%22a%22:%20wrong", "", nil, nil)
	b.send(http.MethodGet, adminHost, "/sign-in%20failed%20from=198.51.100.9", "", nil, nil)
	b.send(http.MethodPost, adminHost, "/signin%0Asign-in%20failed%20from=198.51.100.9", "application/x-www-form-urlencoded", nil, nil)
	if len(u.log) == 0 {
		t.Fatal("nothing was logged")
	}
	for _, line := range u.log {
		if strings.ContainsAny(line, "\n\r") || strings.HasPrefix(line, "sign-in failed") || strings.HasPrefix(line, "proof failed") {
			t.Errorf("a request path produced the log line %q", line)
		}
	}
}

func TestFailedProofIsLoggedLikeAFailedSignIn(t *testing.T) {
	u := newUI(t)
	u.tick()
	b := u.browser()
	b.signIn(adminEmail, adminPw, u.code(u.secret))
	u.now = u.now.Add(auth.ProofLife + time.Minute)
	u.log = nil
	b.post("/account", "/account/prove", url.Values{"password": {adminPw}, "code": {"000000"}})
	var logged bool
	for _, line := range u.log {
		logged = logged || strings.HasPrefix(line, "proof failed from=203.0.113.7 ")
	}
	if !logged {
		t.Errorf("a failed proof was not logged with the visitor's address:\n%s", strings.Join(u.log, "\n"))
	}
}
