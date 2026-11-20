package web

import (
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/kspears/mailstack/internal/auth"
	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/store"
)

const (
	adminEmail = "admin@example.test"
	adminPw    = "the admin's own long password"
	pw         = "correct horse battery staple"
)

const (
	adminHost  = "mail.example.test"
	rspamdHost = "rspamd.example.test"
)

type ui struct {
	t       *testing.T
	admin   *generate.Admin
	auth    *auth.Service
	h       http.Handler
	flash   *http.Cookie
	session string // the signed-in admin's cookie value; empty sends none
	secret  string // that admin's authenticator key
	now     time.Time
	log     []string
}

// code is what the admin's authenticator shows at the test's current time.
func (u *ui) code(secret string) string {
	u.t.Helper()
	c, err := auth.CodeAt(secret, u.now)
	if err != nil {
		u.t.Fatal(err)
	}
	return c
}

// enrol makes an admin the way the operator and the admin do between them,
// and returns the admin's authenticator key and a signed-in session.
func (u *ui) enrol(address string) (secret, session string) {
	u.t.Helper()
	_, token, err := u.auth.AddAdmin("cli:test", address)
	if err != nil {
		u.t.Fatal(err)
	}
	e, ok, err := u.auth.Enrolment(token, "the test's browser")
	if err != nil || !ok {
		u.t.Fatalf("enrolment link: %v %v", ok, err)
	}
	session, err = u.auth.Enrol(token, "the test's browser", adminPw, adminPw, u.code(e.Secret))
	if err != nil {
		u.t.Fatal(err)
	}
	return e.Secret, session
}

func newUI(t *testing.T) *ui {
	t.Helper()
	dir := t.TempDir()
	admin, err := generate.Open(generate.Config{State: filepath.Join(dir, "state"), MailRoot: filepath.Join(dir, "mail"), WatcherOff: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	if _, err := admin.AddDomain("cli:test", "example.test"); err != nil {
		t.Fatal(err)
	}
	u := &ui{t: t, admin: admin, now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	logf := func(format string, args ...any) {
		u.log = append(u.log, fmt.Sprintf(format, args...))
		t.Logf(format, args...)
	}
	u.auth, err = auth.New(admin.Store(), auth.Config{AdminHost: adminHost, Origin: "https://" + adminHost, Now: func() time.Time { return u.now }, Logf: logf, BcryptCost: bcrypt.MinCost, Sleep: func(time.Duration) {}})
	if err != nil {
		t.Fatal(err)
	}
	u.h, err = New(Config{Admin: admin, Auth: u.auth, AdminHost: adminHost, RspamdHost: rspamdHost,
		TrustedProxy: netip.MustParseAddr("192.0.2.1"), ClientAddrHeader: "X-Forwarded-For", Logf: logf})
	if err != nil {
		t.Fatal(err)
	}
	u.secret, u.session = u.enrol(adminEmail)
	return u
}

type resp struct {
	code   int
	body   string
	header http.Header
}

func (u *ui) do(method, path string, form url.Values, mod func(*http.Request)) resp {
	u.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r := httptest.NewRequest(method, path, body)
	r.Host = adminHost
	if u.session != "" {
		r.AddCookie(&http.Cookie{Name: "__Host-" + sessionCookie, Value: u.session})
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	if u.flash != nil {
		r.AddCookie(u.flash)
	}
	if mod != nil {
		mod(r)
	}
	w := httptest.NewRecorder()
	u.h.ServeHTTP(w, r)
	u.flash = nil
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-"+flashCookie && c.MaxAge > 0 {
			u.flash = c
		}
	}
	b, _ := io.ReadAll(w.Result().Body)
	return resp{w.Code, string(b), w.Result().Header}
}

func (u *ui) get(path string) resp { return u.do(http.MethodGet, path, nil, nil) }

func (u *ui) token() string {
	u.t.Helper()
	return csrfIn(u.t, u.get("/mailboxes").body)
}

// post submits a change with a valid token, follows the redirect and returns the flashed page.
func (u *ui) post(path string, form url.Values) resp {
	u.t.Helper()
	form.Set("csrf", u.token())
	r := u.do(http.MethodPost, path, form, nil)
	if r.code != http.StatusSeeOther {
		u.t.Fatalf("POST %s: status %d, body %q", path, r.code, r.body)
	}
	return u.get(r.header.Get("Location"))
}

func (u *ui) snapshot() store.Snapshot {
	u.t.Helper()
	s, err := u.admin.Snapshot()
	if err != nil {
		u.t.Fatal(err)
	}
	return s
}

func wantFlash(t *testing.T, r resp, line string) {
	t.Helper()
	if !strings.Contains(r.body, ">"+html.EscapeString(line)+"</p>") {
		t.Errorf("flash %q not shown in:\n%s", line, r.body)
	}
}

func (u *ui) addAlice() {
	u.t.Helper()
	if _, err := u.admin.AddMailbox("cli:test", "alice@example.test", "Alice A", pw, false); err != nil {
		u.t.Fatal(err)
	}
}

func TestEveryRouteNeedsASession(t *testing.T) {
	u := newUI(t)
	signedIn := u.session
	for _, session := range []string{"", "not-a-session", signedIn + "x"} {
		u.session = session
		for _, tc := range []struct{ method, path string }{
			{"GET", "/"}, {"GET", "/status"}, {"GET", "/mailboxes"}, {"GET", "/mailboxes/edit?address=a@example.test"}, {"GET", "/mailboxes/remove?address=a@example.test"},
			{"POST", "/mailboxes/add"}, {"POST", "/mailboxes/password"}, {"POST", "/mailboxes/state"}, {"POST", "/mailboxes/remove"},
			{"GET", "/aliases"}, {"GET", "/aliases/edit?address=a@example.test"}, {"POST", "/aliases/add"}, {"POST", "/aliases/targets"}, {"POST", "/aliases/remove"},
			{"POST", "/sendas/add"}, {"POST", "/sendas/remove"},
			{"GET", "/domains"}, {"GET", "/sendas"}, {"GET", "/log"},
			{"GET", "/account"}, {"POST", "/account/authenticator/new"}, {"GET", "/account/authenticator/qr"}, {"GET", "/handoff"},
			{"POST", "/signout"}, {"POST", "/account/prove"}, {"POST", "/account/password"}, {"POST", "/account/authenticator"},
			{"POST", "/account/passkeys/begin"}, {"POST", "/account/passkeys/finish"}, {"POST", "/account/passkeys/remove"},
			{"POST", "/account/prove/passkey/begin"}, {"POST", "/account/prove/passkey/finish"},
		} {
			var form url.Values
			if tc.method == "POST" {
				form = url.Values{}
			}
			r := u.do(tc.method, tc.path, form, nil)
			switch {
			case tc.method == "GET" && (r.code != http.StatusSeeOther || r.header.Get("Location") != "/signin"):
				t.Errorf("%s %s with session %q: %d to %q, want a redirect to /signin", tc.method, tc.path, session, r.code, r.header.Get("Location"))
			case tc.method == "POST" && (r.code != http.StatusForbidden || strings.TrimSpace(r.body) != "forbidden"):
				t.Errorf("%s %s with session %q: %d %q, want bare 403", tc.method, tc.path, session, r.code, r.body)
			}
		}
	}
	// A path that is no page of ours is not worth a redirect: browsers ask for
	// icons on every page load.
	for _, path := range []string{"/no/such/page", "/favicon.ico", "/signout"} {
		if r := u.get(path); r.code != http.StatusNotFound {
			t.Errorf("signed-out GET %s: %d, want 404", path, r.code)
		}
	}
	u.session = signedIn
	if r := u.get("/no/such/page"); r.code != http.StatusNotFound {
		t.Errorf("unknown path when signed in: %d, want 404", r.code)
	}
}

func TestGetNeverMutates(t *testing.T) {
	u := newUI(t)
	u.addAlice()
	before, _ := u.admin.Log()
	for _, p := range []string{"/mailboxes", "/mailboxes/edit?address=alice@example.test", "/mailboxes/remove?address=alice@example.test", "/mailboxes/add", "/aliases", "/domains", "/sendas", "/log", "/status", "/"} {
		u.get(p)
	}
	after, _ := u.admin.Log()
	if len(after) != len(before) || len(u.snapshot().Mailboxes) != 1 {
		t.Errorf("a GET changed state: log %d -> %d", len(before), len(after))
	}
}

func TestMailboxLifecycle(t *testing.T) {
	u := newUI(t)

	r := u.post("/mailboxes/add", url.Values{"address": {"Alice@example.test"}, "name": {"Alice A"}, "password": {pw}, "password2": {pw}})
	wantFlash(t, r, "ok: added mailbox alice@example.test")
	if !strings.Contains(r.body, "alice@example.test") || !strings.Contains(r.body, "Alice A") {
		t.Errorf("list does not show the new mailbox:\n%s", r.body)
	}
	if m := u.snapshot().Mailboxes; len(m) != 1 || m[0].Name != "Alice A" || m[0].State != store.Active {
		t.Fatalf("mailboxes = %+v", m)
	}
	oldHash := u.snapshot().Mailboxes[0].Hash

	r = u.post("/mailboxes/password", url.Values{"address": {"alice@example.test"}, "password": {pw + "2"}, "password2": {pw + "2"}})
	wantFlash(t, r, "ok: changed password for alice@example.test")
	if u.snapshot().Mailboxes[0].Hash == oldHash {
		t.Error("password hash did not change")
	}

	r = u.post("/mailboxes/state", url.Values{"address": {"alice@example.test"}, "state": {"receive-only"}})
	wantFlash(t, r, "ok: set alice@example.test to receive-only")
	if u.snapshot().Mailboxes[0].State != store.ReceiveOnly {
		t.Error("state did not change")
	}
	if page := u.get("/mailboxes/edit?address=alice@example.test").body; !strings.Contains(page, `value="receive-only" selected`) {
		t.Errorf("edit page does not preselect the state:\n%s", page)
	}

	confirm := u.get("/mailboxes/remove?address=alice@example.test").body
	if !strings.Contains(confirm, "Mail on disk is kept") || len(u.snapshot().Mailboxes) != 1 {
		t.Errorf("confirmation page wrong or removed early:\n%s", confirm)
	}
	r = u.post("/mailboxes/remove", url.Values{"address": {"alice@example.test"}})
	wantFlash(t, r, "ok: removed alice@example.test; mail left in place at "+u.admin.MailPath("alice@example.test"))
	if len(u.snapshot().Mailboxes) != 0 {
		t.Error("mailbox still present")
	}
}

func TestAliasLifecycle(t *testing.T) {
	u := newUI(t)
	u.addAlice()
	if _, err := u.admin.AddMailbox("cli:test", "bob@example.test", "", pw, false); err != nil {
		t.Fatal(err)
	}
	r := u.post("/aliases/add", url.Values{"address": {"info@example.test"}, "targets": {"alice@example.test, bob@example.test"}})
	wantFlash(t, r, "ok: added alias info@example.test -> alice@example.test,bob@example.test")
	if a := u.snapshot().Aliases; len(a) != 1 || a[0].Address != "info@example.test" {
		t.Fatalf("aliases = %+v", a)
	}
	if !strings.Contains(r.body, `info@example.test</a></td><td class="wrap">alice@example.test, bob@example.test</td>`) {
		t.Errorf("alias list lacks targets:\n%s", r.body)
	}
	if e := u.get("/aliases/edit?address=info@example.test"); !strings.Contains(e.body, `value="alice@example.test, bob@example.test"`) {
		t.Errorf("edit page lacks current targets:\n%s", e.body)
	}
	r = u.post("/aliases/targets", url.Values{"address": {"info@example.test"}, "targets": {"bob@example.test"}})
	wantFlash(t, r, "ok: alias info@example.test now delivers to bob@example.test")
	if a := u.snapshot().Aliases; len(a) != 1 || !slices.Equal(a[0].Targets, []string{"bob@example.test"}) {
		t.Fatalf("aliases after edit = %+v", a)
	}
	r = u.post("/aliases/targets", url.Values{"address": {"info@example.test"}, "targets": {""}})
	wantFlash(t, r, "error: alias info@example.test needs at least one target")
	if a := u.snapshot().Aliases; len(a) != 1 || len(a[0].Targets) != 1 {
		t.Fatalf("a refused edit changed the alias: %+v", a)
	}
	if e := u.get("/aliases/edit?address=nobody@example.test"); e.code != http.StatusNotFound {
		t.Errorf("edit of unknown alias: %d, want 404", e.code)
	}
	r = u.post("/aliases/remove", url.Values{"address": {"info@example.test"}})
	wantFlash(t, r, "ok: removed alias info@example.test")
	if len(u.snapshot().Aliases) != 0 {
		t.Error("alias still present")
	}
}

func TestValidationFailuresChangeNothing(t *testing.T) {
	u := newUI(t)
	u.addAlice()
	logBefore, _ := u.admin.Log()
	for _, tc := range []struct {
		path string
		form url.Values
		want string
	}{
		{"/mailboxes/add", url.Values{"address": {"bob@example.test"}, "password": {pw}, "password2": {"different"}}, "error: passwords do not match"},
		{"/mailboxes/add", url.Values{"address": {"bob@example.test"}, "password": {"short"}, "password2": {"short"}}, "error: password must be at least 12 characters"},
		{"/mailboxes/add", url.Values{"address": {"not-an-address"}, "password": {pw}, "password2": {pw}}, `error: invalid address "not-an-address": expected local@domain`},
		{"/mailboxes/state", url.Values{"address": {"alice@example.test"}, "state": {"asleep"}}, `error: unknown state "asleep"; use active, receive-only or disabled`},
		{"/mailboxes/remove", url.Values{"address": {"nobody@example.test"}}, "error: no mailbox nobody@example.test"},
	} {
		wantFlash(t, u.post(tc.path, tc.form), tc.want)
	}
	if after, _ := u.admin.Log(); len(after) != len(logBefore) || len(u.snapshot().Mailboxes) != 1 {
		t.Error("a failed change altered state or the log")
	}
}

func TestCSRFRefusals(t *testing.T) {
	u := newUI(t)
	_, other := u.enrol("other@example.test")
	good := func() url.Values {
		return url.Values{"csrf": {u.token()}, "address": {"bob@example.test"}, "password": {pw}, "password2": {pw}}
	}
	site := func(v string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", v) }
	}
	for name, tc := range map[string]struct {
		form url.Values
		mod  func(*http.Request)
	}{
		// Only the browser's own word that the page making the request is ours
		// will do. A sibling hostname under the same domain is "same-site".
		"cross-site":          {good(), site("cross-site")},
		"same-site":           {good(), site("same-site")},
		"typed or bookmarked": {good(), site("none")},
		"no metadata, matching origin": {good(), func(r *http.Request) {
			r.Header.Del("Sec-Fetch-Site")
			r.Header.Set("Origin", "https://"+adminHost)
		}},
		"missing token": {url.Values{"address": {"bob@example.test"}, "password": {pw}, "password2": {pw}}, nil},
		"wrong token":   {url.Values{"csrf": {"deadbeef"}, "address": {"bob@example.test"}, "password": {pw}, "password2": {pw}}, nil},
		"another session's token": {good(), func(r *http.Request) {
			r.Header.Del("Cookie")
			r.AddCookie(&http.Cookie{Name: "__Host-" + sessionCookie, Value: other})
		}},
	} {
		if r := u.do(http.MethodPost, "/mailboxes/add", tc.form, tc.mod); r.code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, r.code)
		}
	}
	if len(u.snapshot().Mailboxes) != 0 {
		t.Error("a refused request created a mailbox")
	}
	if r := u.do(http.MethodPost, "/mailboxes/add", good(), nil); r.code != http.StatusSeeOther || len(u.snapshot().Mailboxes) != 1 {
		t.Errorf("a same-origin post with the right token: status %d", r.code)
	}
}

func TestChangeLogRecordsIdentityAndNoSecrets(t *testing.T) {
	u := newUI(t)
	u.post("/mailboxes/add", url.Values{"address": {"alice@example.test"}, "password": {pw}, "password2": {pw}})
	u.post("/mailboxes/password", url.Values{"address": {"alice@example.test"}, "password": {pw + "x"}, "password2": {pw + "x"}})
	entries, _ := u.admin.Log()
	if last := entries[len(entries)-1]; last.Actor != adminEmail || last.Action != "mailbox.passwd" {
		t.Errorf("last log entry = %+v", last)
	}
	page := u.get("/log")
	if i, j := strings.Index(page.body, "mailbox.passwd"), strings.Index(page.body, "mailbox.add"); i < 0 || j < 0 || i > j {
		t.Errorf("log is not newest first:\n%s", page.body)
	}
	if !strings.Contains(page.body, adminEmail) {
		t.Error("log page does not show the actor")
	}
	for _, e := range entries {
		if strings.Contains(e.Subject+e.Action+e.Actor, "correct horse") {
			t.Errorf("log entry leaks a password: %+v", e)
		}
	}
}

func TestNoPasswordInAnyResponse(t *testing.T) {
	u := newUI(t)
	u.addAlice()
	var bodies []string
	form := url.Values{"csrf": {u.token()}, "address": {"alice@example.test"}, "password": {pw}, "password2": {pw}}
	r := u.do(http.MethodPost, "/mailboxes/password", form, nil)
	bodies = append(bodies, r.body, r.header.Get("Location"), r.header.Get("Set-Cookie"))
	bad := url.Values{"csrf": {u.token()}, "address": {"alice@example.test"}, "password": {pw}, "password2": {pw + "mismatch"}}
	r = u.do(http.MethodPost, "/mailboxes/password", bad, nil)
	bodies = append(bodies, r.body, r.header.Get("Location"), r.header.Get("Set-Cookie"))
	for _, p := range []string{"/mailboxes", "/mailboxes/edit?address=alice@example.test", "/log", "/aliases"} {
		bodies = append(bodies, u.get(p).body)
	}
	if slices.ContainsFunc(bodies, func(b string) bool { return strings.Contains(b, "correct horse") || strings.Contains(b, "$2") }) {
		t.Error("a password or hash appeared in a response")
	}
}

func TestSecurityHeadersAndReadOnlyPages(t *testing.T) {
	u := newUI(t)
	for _, p := range []string{"/status", "/mailboxes", "/aliases", "/domains", "/sendas", "/log", "/static/style.css", "/no/such/page"} {
		r := u.get(p)
		for k, v := range map[string]string{
			"Content-Security-Policy": csp,
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "same-origin",
			"Cache-Control":           "no-store",
		} {
			if r.header.Get(k) != v {
				t.Errorf("%s: %s = %q, want %q", p, k, r.header.Get(k), v)
			}
		}
	}
	if d := u.get("/domains"); !strings.Contains(d.body, "example.test") || !strings.Contains(d.body, "added from the command line") || strings.Count(d.body, "<form") != 1 { // only the sign-out button
		t.Errorf("domains page:\n%s", d.body)
	}
}

func TestBodyLimit(t *testing.T) {
	u := newUI(t)
	form := url.Values{"csrf": {u.token()}, "name": {strings.Repeat("x", maxBody+1)}}
	if r := u.do(http.MethodPost, "/mailboxes/add", form, nil); r.code == http.StatusSeeOther {
		t.Errorf("oversized body accepted")
	}
}

func checkPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(strings.TrimPrefix(hash, store.HashPrefix)), []byte(password)) == nil
}

func TestSendAsLifecycle(t *testing.T) {
	u := newUI(t)
	if s := u.get("/sendas"); strings.Contains(s.body, `action="/sendas/add"`) {
		t.Error("send-as page offers a form with no mailbox to grant to")
	}
	u.addAlice()
	r := u.post("/sendas/add", url.Values{"mailbox": {"alice@example.test"}, "address": {"sales@example.test"}})
	wantFlash(t, r, "ok: alice@example.test may now send as sales@example.test")
	if g := u.snapshot().Grants; len(g) != 1 || g[0] != (store.Grant{Mailbox: "alice@example.test", Address: "sales@example.test"}) {
		t.Fatalf("grants = %+v", g)
	}
	r = u.post("/sendas/add", url.Values{"mailbox": {"nobody@example.test"}, "address": {"sales@example.test"}})
	wantFlash(t, r, "error: no mailbox nobody@example.test")
	r = u.post("/sendas/remove", url.Values{"mailbox": {"alice@example.test"}, "address": {"sales@example.test"}})
	wantFlash(t, r, "ok: alice@example.test may no longer send as sales@example.test")
	if len(u.snapshot().Grants) != 0 {
		t.Error("grant still present")
	}
}

func TestGeneratedPasswordIsShownOnceAndWorks(t *testing.T) {
	u := newUI(t)
	generate := func(path string, form url.Values) string {
		t.Helper()
		form.Set("csrf", u.token())
		form.Set("generate", "1")
		r := u.do(http.MethodPost, path, form, nil)
		if r.code != http.StatusOK || u.flash != nil || len(r.header.Values("Set-Cookie")) != 0 {
			t.Fatalf("POST %s: status %d, cookies %q; want the password in the body only", path, r.code, r.header.Values("Set-Cookie"))
		}
		const marker = `<code class="secret">`
		i := strings.Index(r.body, marker)
		if i < 0 {
			t.Fatalf("no generated password in:\n%s", r.body)
		}
		rest := r.body[i+len(marker):]
		return rest[:strings.Index(rest, "<")]
	}
	hash := func() string { return u.snapshot().Mailboxes[0].Hash }

	first := generate("/mailboxes/add", url.Values{"address": {"alice@example.test"}})
	if len(first) != 23 || !checkPassword(hash(), first) {
		t.Fatalf("generated password %q does not match the stored hash", first)
	}
	second := generate("/mailboxes/password", url.Values{"address": {"alice@example.test"}, "password": {"ignored when generating"}})
	if second == first || !checkPassword(hash(), second) || checkPassword(hash(), first) {
		t.Fatal("reset did not replace the password with a new generated one")
	}
	for _, p := range []string{"/mailboxes", "/mailboxes/edit?address=alice@example.test", "/log"} {
		if strings.Contains(u.get(p).body, second) {
			t.Errorf("%s shows the generated password again", p)
		}
	}

	// A refused change shows no password at all.
	form := url.Values{"address": {"nobody@example.test"}, "generate": {"1"}, "csrf": {u.token()}}
	if r := u.do(http.MethodPost, "/mailboxes/password", form, nil); r.code != http.StatusSeeOther || strings.Contains(r.body, "secret") {
		t.Errorf("failed generate: status %d body %q", r.code, r.body)
	}
}

func TestStatusPage(t *testing.T) {
	u := newUI(t)
	if r := u.get("/"); r.code != http.StatusSeeOther || r.header.Get("Location") != "/status" {
		t.Errorf("GET /: %d to %q, want /status", r.code, r.header.Get("Location"))
	}
	r := u.get("/status")
	if r.code != http.StatusOK || strings.Contains(r.body, "<script") {
		t.Fatalf("status page: %d\n%s", r.code, r.body)
	}
	for _, want := range []string{`<a href="/status" aria-current="page">Status</a>`, "Postfix watcher", "Watcher is off",
		"Account files", "Matches the account store", "Pending change", "Last mail in", "No mail yet",
		"It does not check dovecot", "Checked at ", "Mail scanned at "} {
		if !strings.Contains(html.UnescapeString(r.body), want) {
			t.Errorf("status page lacks %q:\n%s", want, r.body)
		}
	}
	// The navigation lists Status first.
	if i, j := strings.Index(r.body, `href="/status"`), strings.Index(r.body, `href="/mailboxes"`); i < 0 || i > j {
		t.Errorf("Status is not the first nav link")
	}
	// With the watcher off, both the watcher and the pending card say so.
	if n := strings.Count(r.body, "Watcher is off"); n != 2 {
		t.Errorf("%d cards say the watcher is off, want 2", n)
	}
}

func TestStatusPageDoesNotFollowWatcherStatusLink(t *testing.T) {
	u := newUI(t)
	state := u.admin.Config().State
	secret := filepath.Join(state, "secret")
	// Shaped like a rejected change, so it would be shown if it were read.
	if err := os.WriteFile(secret, []byte("g9 error do-not-show-this"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(state, "watcher", "status")); err != nil {
		t.Fatal(err)
	}
	if body := u.get("/status").body; strings.Contains(body, "do-not-show-this") || strings.Contains(body, "Last change was rejected") {
		t.Errorf("watcher/status was followed through a symlink:\n%s", body)
	}
}

func TestMailboxesShowLastDelivery(t *testing.T) {
	u := newUI(t)
	u.addAlice()
	if _, err := u.admin.AddMailbox("cli:test", "bob@example.test", "", pw, false); err != nil {
		t.Fatal(err)
	}
	// A newer message in Junk and an older one in the Inbox: the row shows the Junk one.
	maildir := filepath.Join(u.admin.MailPath("alice@example.test"), "Maildir")
	for _, m := range []struct {
		dir string
		age time.Duration
	}{{filepath.Join(maildir, ".Junk", "new"), 3 * time.Minute}, {filepath.Join(maildir, "cur"), 3 * time.Hour}} {
		if err := os.MkdirAll(m.dir, 0o755); err != nil {
			t.Fatal(err)
		}
		msg := filepath.Join(m.dir, "1.eml")
		if err := os.WriteFile(msg, []byte("Subject: hi\n\nhello\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		then := time.Now().Add(-m.age)
		if err := os.Chtimes(msg, then, then); err != nil {
			t.Fatal(err)
		}
	}
	body := html.UnescapeString(u.get("/mailboxes").body)
	if !regexpMatch(`alice@example\.test</a></td><td>Alice A</td><td>active</td><td>3 min ago</td><td>[0-9.]+ KiB</td>`, body) {
		t.Errorf("alice's row lacks her last delivery:\n%s", body)
	}
	if !strings.Contains(body, "bob@example.test</a></td><td></td><td>active</td><td>No mail yet</td><td>0 B</td>") {
		t.Errorf("bob's row:\n%s", body)
	}
	// The add form comes before the list, so a long list does not push it out of reach.
	if i := strings.Index(body, "<summary>Add a mailbox</summary>"); i < 0 || i > strings.Index(body, "alice@example.test") {
		t.Error("the add form is missing or below the mailbox list")
	}
	// Folded while there are mailboxes; open when the list is empty or an add just failed.
	if strings.Contains(body, `<details class="card add" open>`) {
		t.Error("the add form is open above a non-empty list")
	}
}

func TestAddFormOpensWhenListIsEmptyOrAddFailed(t *testing.T) {
	u := newUI(t)
	if body := u.get("/aliases").body; !strings.Contains(body, `<details class="card add" open>`) {
		t.Errorf("the add form is folded above an empty alias list:\n%s", body)
	}
	u.addAlice()
	r := u.post("/mailboxes/add", url.Values{"address": {"alice@example.test"}, "password": {pw}, "password2": {pw}})
	if !strings.Contains(r.body, "error:") || !strings.Contains(r.body, `<details class="card add" open>`) {
		t.Errorf("the add form is folded after a failed add:\n%s", r.body)
	}
}

func TestLogTimesArePacific(t *testing.T) {
	u := newUI(t)
	if body := u.get("/log").body; !strings.Contains(body, "<th>Time</th>") || !regexpMatch(`<td>\d{4}-\d\d-\d\d \d\d:\d\d P[SD]T</td>`, body) {
		t.Errorf("log times are not in Pacific time:\n%s", body)
	}
}

func regexpMatch(pattern, s string) bool { return regexp.MustCompile(pattern).MatchString(s) }
