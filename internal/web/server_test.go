package web

import (
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kspears/mailstack/internal/access"
	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/store"
)

const (
	adminEmail = "admin@example.test"
	pw         = "correct horse battery staple"
)

type headerID struct{}

func (headerID) Identify(r *http.Request) (string, error) {
	if who := r.Header.Get("X-Test-Actor"); who != "" {
		return who, nil
	}
	return "", errors.New("no test identity")
}

type ui struct {
	t     *testing.T
	admin *generate.Admin
	h     http.Handler
	flash *http.Cookie
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
	h, err := New(Config{Admin: admin, Identifier: headerID{}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return &ui{t: t, admin: admin, h: h}
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
	r.Host = "mail.example.test"
	r.Header.Set("X-Test-Actor", adminEmail)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://mail.example.test")
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
		if c.Name == flashCookie && c.MaxAge > 0 {
			u.flash = c
		}
	}
	b, _ := io.ReadAll(w.Result().Body)
	return resp{w.Code, string(b), w.Result().Header}
}

func (u *ui) get(path string) resp { return u.do(http.MethodGet, path, nil, nil) }

func (u *ui) token() string {
	u.t.Helper()
	body := u.get("/mailboxes").body
	const marker = `name="csrf" value="`
	i := strings.Index(body, marker)
	if i < 0 {
		u.t.Fatalf("no csrf field in:\n%s", body)
	}
	rest := body[i+len(marker):]
	return rest[:strings.Index(rest, `"`)]
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

func TestEveryRouteNeedsIdentity(t *testing.T) {
	u := newUI(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/mailboxes"}, {"GET", "/mailboxes/edit?address=a@example.test"}, {"GET", "/mailboxes/remove?address=a@example.test"},
		{"POST", "/mailboxes/add"}, {"POST", "/mailboxes/password"}, {"POST", "/mailboxes/state"}, {"POST", "/mailboxes/remove"},
		{"GET", "/aliases"}, {"POST", "/aliases/add"}, {"POST", "/aliases/remove"},
		{"GET", "/domains"}, {"GET", "/sendas"}, {"GET", "/log"},
		{"GET", "/static/style.css"}, {"GET", "/static/nope.css"}, {"GET", "/no/such/page"},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		w := httptest.NewRecorder()
		u.h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || strings.TrimSpace(w.Body.String()) != "forbidden" {
			t.Errorf("%s %s: %d %q, want bare 403", tc.method, tc.path, w.Code, w.Body.String())
		}
	}
	if r := u.get("/no/such/page"); r.code != http.StatusNotFound {
		t.Errorf("unknown path with identity: %d, want 404", r.code)
	}
}

func TestGetNeverMutates(t *testing.T) {
	u := newUI(t)
	u.addAlice()
	before, _ := u.admin.Log()
	for _, p := range []string{"/mailboxes", "/mailboxes/edit?address=alice@example.test", "/mailboxes/remove?address=alice@example.test", "/mailboxes/add", "/aliases", "/domains", "/sendas", "/log", "/"} {
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
	if !strings.Contains(r.body, "delivers to alice@example.test") {
		t.Errorf("alias list lacks targets:\n%s", r.body)
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
	good := func() url.Values {
		return url.Values{"csrf": {u.token()}, "address": {"bob@example.test"}, "password": {pw}, "password2": {pw}}
	}
	for name, tc := range map[string]struct {
		form url.Values
		mod  func(*http.Request)
	}{
		"foreign origin":           {good(), func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.org") }},
		"null origin":              {good(), func(r *http.Request) { r.Header.Set("Origin", "null") }},
		"foreign referer":          {good(), func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://evil.example.org/x") }},
		"no origin/referer":        {good(), func(r *http.Request) { r.Header.Del("Origin") }},
		"cross-site fetch":         {good(), func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		"same-site fetch":          {good(), func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
		"missing token":            {url.Values{"address": {"bob@example.test"}, "password": {pw}, "password2": {pw}}, nil},
		"wrong token":              {url.Values{"csrf": {"deadbeef"}, "address": {"bob@example.test"}, "password": {pw}, "password2": {pw}}, nil},
		"another identity's token": {good(), func(r *http.Request) { r.Header.Set("X-Test-Actor", "other@example.test") }},
	} {
		if r := u.do(http.MethodPost, "/mailboxes/add", tc.form, tc.mod); r.code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, r.code)
		}
	}
	if len(u.snapshot().Mailboxes) != 0 {
		t.Error("a refused request created a mailbox")
	}
	okForm := good()
	if r := u.do(http.MethodPost, "/mailboxes/add", okForm, func(r *http.Request) {
		r.Header.Del("Origin")
		r.Header.Set("Referer", "https://mail.example.test/mailboxes")
	}); r.code != http.StatusSeeOther {
		t.Errorf("same-origin Referer: status %d, want 303", r.code)
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
	for _, p := range []string{"/mailboxes", "/aliases", "/domains", "/sendas", "/log", "/static/style.css", "/no/such/page"} {
		r := u.get(p)
		for k, v := range map[string]string{
			"Content-Security-Policy": "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
			"X-Content-Type-Options":  "nosniff",
			"Referrer-Policy":         "same-origin",
			"Cache-Control":           "no-store",
		} {
			if r.header.Get(k) != v {
				t.Errorf("%s: %s = %q, want %q", p, k, r.header.Get(k), v)
			}
		}
	}
	if d := u.get("/domains"); !strings.Contains(d.body, "example.test") || !strings.Contains(d.body, "added from the command line") || strings.Contains(d.body, "<form") {
		t.Errorf("domains page:\n%s", d.body)
	}
	if s := u.get("/sendas"); strings.Contains(s.body, "<form") {
		t.Error("send-as page offers a form")
	}
}

func TestBodyLimit(t *testing.T) {
	u := newUI(t)
	form := url.Values{"csrf": {u.token()}, "name": {strings.Repeat("x", maxBody+1)}}
	if r := u.do(http.MethodPost, "/mailboxes/add", form, nil); r.code == http.StatusSeeOther {
		t.Errorf("oversized body accepted")
	}
}

func TestDevIdentifierServes(t *testing.T) {
	u := newUI(t)
	h, err := New(Config{Admin: u.admin, Identifier: access.Dev{Email: "dev@example.test"}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/mailboxes", nil))
	if w.Code != http.StatusOK {
		t.Errorf("status %d", w.Code)
	}
}
