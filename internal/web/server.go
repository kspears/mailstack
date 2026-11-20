// Package web is the server-rendered admin UI. It is a second front end over
// the same operations the CLI uses, and works without JavaScript.
package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/kspears/mailstack/internal/auth"
	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/status"
	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	maxBody     = 64 << 10
	flashCookie = "flash"
	csp         = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
	// Only the pages that offer a passkey carry a script, and only from here.
	cspScript = csp + "; script-src 'self'; connect-src 'self'"
	// Only the pages that show an authenticator QR code carry an image.
	cspImage = csp + "; img-src 'self'"
)

// Config wires the server. Logf receives one line per request plus the reason
// for each refusal; it never receives query strings, bodies or tokens.
type Config struct {
	Admin *generate.Admin
	Auth  *auth.Service
	// AdminHost is the only Host the UI answers to. RspamdHost, if set, is the
	// hostname whose requests the proxy checks against /_mailstack/check.
	AdminHost  string
	RspamdHost string
	// Insecure is for local development over plain HTTP: cookies lose the
	// Secure flag and the __Host- prefix, and links use http.
	Insecure bool
	// TrustedProxy is the one address whose ClientAddrHeader is believed.
	TrustedProxy     netip.Addr
	ClientAddrHeader string
	Logf             func(format string, args ...any)
}

type server struct {
	cfg       Config
	admin     *generate.Admin
	auth      *auth.Service
	logf      func(string, ...any)
	csrfKey   []byte
	templates *template.Template
	mail      *status.Cache // mail scans for the Status and Mailboxes pages
}

type ctxKey struct{}

// New returns the handler for the whole UI. Every request passes through guard.
func New(cfg Config) (http.Handler, error) {
	cfg.AdminHost, cfg.RspamdHost = strings.ToLower(cfg.AdminHost), strings.ToLower(cfg.RspamdHost)
	if cfg.AdminHost == "" {
		return nil, fmt.Errorf("the admin UI needs the hostname it is served on")
	}
	s := &server{cfg: cfg, admin: cfg.Admin, auth: cfg.Auth, logf: auth.SingleLine(cfg.Logf), csrfKey: make([]byte, 32),
		mail: status.NewCache(time.Minute, cfg.Admin.Config().Now, status.ScanMailbox)}
	if _, err := rand.Read(s.csrfKey); err != nil {
		return nil, fmt.Errorf("generate CSRF key: %w", err)
	}
	t, err := template.New("").Funcs(template.FuncMap{"stamp": status.Stamp, "join": strings.Join,
		// soft lets a comma-joined target list wrap between addresses instead of inside one.
		"soft": func(s string) string { return strings.ReplaceAll(s, ",", ",\u200b") }}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.templates = t
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	static := http.StripPrefix("/static/", http.FileServerFS(sub))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/status", http.StatusSeeOther) })
	mux.HandleFunc("GET /status", s.statusPage)
	mux.Handle("GET /static/", static)
	mux.HandleFunc("GET /mailboxes", s.mailboxes)
	mux.HandleFunc("GET /mailboxes/edit", s.mailboxEdit)
	mux.HandleFunc("GET /mailboxes/remove", s.mailboxRemoveConfirm)
	mux.HandleFunc("POST /mailboxes/add", s.mailboxAdd)
	mux.HandleFunc("POST /mailboxes/password", s.mailboxPassword)
	mux.HandleFunc("POST /mailboxes/state", s.mailboxState)
	mux.HandleFunc("POST /mailboxes/remove", s.mailboxRemove)
	mux.HandleFunc("GET /aliases", s.list("aliases", "Aliases", func(snap store.Snapshot) any { return snap.Aliases }))
	mux.HandleFunc("GET /aliases/edit", s.aliasEdit)
	mux.HandleFunc("POST /aliases/add", s.aliasAdd)
	mux.HandleFunc("POST /aliases/targets", s.aliasTargets)
	mux.HandleFunc("POST /aliases/remove", s.aliasRemove)
	mux.HandleFunc("GET /domains", s.list("domains", "Domains", func(snap store.Snapshot) any { return snap.Domains }))
	mux.HandleFunc("GET /sendas", s.list("sendas", "Send-as grants", func(snap store.Snapshot) any { return snap }))
	mux.HandleFunc("POST /sendas/add", s.sendAsAdd)
	mux.HandleFunc("POST /sendas/remove", s.sendAsRemove)
	mux.HandleFunc("GET /log", s.changeLog)
	s.authRoutes(mux)
	return s.guard(mux), nil
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// guard is the one place every request passes, and the one place that decides
// whether it may proceed: the right hostname, a session where one is needed,
// and for anything that is not a plain read, proof that one of this origin's
// own pages sent it. Handlers behind it check none of that themselves, so a
// new one cannot forget to.
func (s *server) guard(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h := sw.Header()
		h.Set("Content-Security-Policy", cspFor(r.URL.Path))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cache-Control", "no-store")

		path, actor := r.URL.Path, "-"
		hostOK, signedIn := s.hostAllowed(r), false
		// Static files and the rspamd gate never act for an admin, so they are
		// spared the lookup: the gate runs before every request to rspamd's UI.
		if hostOK && !strings.HasPrefix(path, "/static/") && !strings.HasPrefix(path, gatePrefix) {
			var sess store.Session
			if sess, signedIn = s.auth.Session(s.cookie(r, sessionCookie), store.AdminSession); signedIn {
				actor = sess.Admin
				r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess))
			}
		}
		r.Body = http.MaxBytesReader(sw, r.Body, maxBody)
		read := r.Method == http.MethodGet || r.Method == http.MethodHead
		_, route := mux.Handler(r)
		switch {
		case !hostOK:
			s.logf("refused %s %q: host %q is not served here", r.Method, path, r.Host)
			http.Error(sw, "misdirected request", http.StatusMisdirectedRequest)
		case !signedIn && !public(path) && read && route == "":
			// Browsers ask for icons on every page; no page of ours is behind them.
			http.NotFound(sw, r)
		case !signedIn && !public(path) && read:
			http.Redirect(sw, r, "/signin", http.StatusSeeOther)
		case !signedIn && !public(path):
			http.Error(sw, "forbidden", http.StatusForbidden)
		case signedIn && path == "/signin":
			// Also a sign-in form left open in one tab and submitted after signing
			// in from another: its token is the signed-out one, and there is
			// nothing left for it to do.
			http.Redirect(sw, r, "/status", http.StatusSeeOther)
		case !read && s.refuseChange(sw, r):
		default:
			mux.ServeHTTP(sw, r)
		}
		// rspamd's UI polls, and the proxy asks about every request it makes. Those
		// lines would bury the failures that bans are made from.
		if path == gatePrefix+"check" && sw.status == http.StatusNoContent {
			return
		}
		// The path is the visitor's to choose, so it is quoted: it must not be able
		// to make this line read as a failed sign-in from an address of the
		// visitor's choosing.
		s.logf("%s %q %d %s %s", r.Method, path, sw.status, actor, time.Since(start).Round(time.Millisecond))
	})
}

// token is the CSRF token for key: the session for a signed-in admin, the
// pre-session cookie for the sign-in and enrolment forms.
func (s *server) token(key string) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write([]byte(key))
	return hex.EncodeToString(m.Sum(nil))
}

// checkChange decides whether a request that changes something may proceed.
// The browser must say that one of this origin's own pages made it:
// Sec-Fetch-Site is set by the browser and cannot be forged by a page, and
// sibling hostnames under one domain count as "same-site", so nothing served
// from them passes. It must also carry the CSRF token, in the X-CSRF header
// (the passkey script, whose bodies are JSON) or the form's csrf field.
func (s *server) checkChange(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "same-origin" {
		return fmt.Errorf("Sec-Fetch-Site is %q, not same-origin", site)
	}
	got := r.Header.Get("X-CSRF")
	if got == "" {
		if err := r.ParseForm(); err != nil {
			return fmt.Errorf("read form: %w", err)
		}
		got = r.PostFormValue("csrf")
	}
	if !hmac.Equal([]byte(got), []byte(s.token(s.csrfKeyOf(r)))) {
		return fmt.Errorf("bad or missing CSRF token")
	}
	return nil
}

// refuseChange answers 403 and reports true unless the request passes checkChange.
func (s *server) refuseChange(w http.ResponseWriter, r *http.Request) bool {
	err := s.checkChange(r)
	if err != nil {
		s.logf("refused %s %q: %v", r.Method, r.URL.Path, err)
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return err != nil
}

// do runs a change and redirects to the page with the exact CLI line as a flash.
func (s *server) do(w http.ResponseWriter, r *http.Request, back string, op func(actor string) (string, error)) {
	line := ""
	if summary, err := op(actorOf(r)); err != nil {
		line = "error: " + err.Error()
	} else {
		line = "ok: " + summary
	}
	s.flash(w, r, back, line)
}

// setFlash leaves a line for the next page to show once.
func (s *server) setFlash(w http.ResponseWriter, line string) {
	s.setCookie(w, flashCookie, base64.RawURLEncoding.EncodeToString([]byte(line)), 60, http.SameSiteStrictMode)
}

func (s *server) flash(w http.ResponseWriter, r *http.Request, back, line string) {
	s.setFlash(w, line)
	http.Redirect(w, r, back, http.StatusSeeOther)
}

type page struct {
	Title  string
	Nav    string
	CSRF   string
	Flash  string
	IsErr  bool
	Actor  string
	Rspamd string // link to the spam filter's own UI, if it is published
	Script bool   // this page offers a passkey
	Data   any
}

func (s *server) render(w http.ResponseWriter, r *http.Request, name, nav, title string, data any) {
	s.renderPage(w, r, name, page{Title: title, Nav: nav, Data: data})
}

func (s *server) renderPage(w http.ResponseWriter, r *http.Request, name string, p page) {
	p.CSRF, p.Actor = s.token(s.csrfKeyOf(r)), actorOf(r)
	p.Script = strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src")
	if p.Actor != "" && s.cfg.RspamdHost != "" {
		p.Rspamd = s.origin(s.cfg.RspamdHost) + "/"
	}
	if v := s.cookie(r, flashCookie); v != "" && p.Flash == "" {
		if b, err := base64.RawURLEncoding.DecodeString(v); err == nil {
			p.Flash = string(b)
			p.IsErr = strings.HasPrefix(p.Flash, "error:")
		}
		s.setCookie(w, flashCookie, "", -1, http.SameSiteStrictMode)
	}
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, p); err != nil {
		s.logf("render %s: %v", name, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *server) fail(w http.ResponseWriter, what string, err error) {
	s.logf("%s: %v", what, err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// list serves one of the account list pages: the template is name, which is
// also its nav entry, and pick chooses the rows.
func (s *server) list(name, title string, pick func(store.Snapshot) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap, err := s.admin.Snapshot()
		if err != nil {
			s.fail(w, "snapshot", err)
			return
		}
		s.render(w, r, name, name, title, pick(snap))
	}
}

// find answers the request itself (500 or 404) and reports false unless pick's
// rows hold the one whose address is the ?address= query parameter.
func find[T any](s *server, w http.ResponseWriter, r *http.Request, pick func(store.Snapshot) []T, address func(T) string) (T, bool) {
	var zero T
	snap, err := s.admin.Snapshot()
	if err != nil {
		s.fail(w, "snapshot", err)
		return zero, false
	}
	rows := pick(snap)
	i := slices.IndexFunc(rows, func(row T) bool { return address(row) == r.URL.Query().Get("address") })
	if i < 0 {
		http.NotFound(w, r)
		return zero, false
	}
	return rows[i], true
}

func (s *server) mailbox(w http.ResponseWriter, r *http.Request) (store.Mailbox, bool) {
	return find(s, w, r, func(snap store.Snapshot) []store.Mailbox { return snap.Mailboxes }, func(m store.Mailbox) string { return m.Address })
}

func (s *server) mailboxEdit(w http.ResponseWriter, r *http.Request) {
	if m, ok := s.mailbox(w, r); ok {
		s.render(w, r, "mailbox_edit", "mailboxes", m.Address, struct {
			store.Mailbox
			States []store.State
		}{m, []store.State{store.Active, store.ReceiveOnly, store.Disabled}})
	}
}

func (s *server) mailboxRemoveConfirm(w http.ResponseWriter, r *http.Request) {
	if m, ok := s.mailbox(w, r); ok {
		s.render(w, r, "mailbox_remove", "mailboxes", "Remove "+m.Address, m)
	}
}

func (s *server) mailboxAdd(w http.ResponseWriter, r *http.Request) {
	s.withPassword(w, r, func(actor, pw string) (string, error) {
		return s.admin.AddMailbox(actor, r.PostFormValue("address"), strings.TrimSpace(r.PostFormValue("name")), pw, false)
	})
}

func (s *server) mailboxPassword(w http.ResponseWriter, r *http.Request) {
	s.withPassword(w, r, func(actor, pw string) (string, error) {
		return s.admin.SetPassword(actor, r.PostFormValue("address"), pw)
	})
}

// withPassword runs a change that sets a password. The typed pair is used unless
// the form's "generate" button was pressed; a generated password is shown once,
// in the response to this POST, and is never put in a cookie or a redirect.
func (s *server) withPassword(w http.ResponseWriter, r *http.Request, op func(actor, pw string) (string, error)) {
	if r.PostFormValue("generate") == "" {
		s.do(w, r, "/mailboxes", func(actor string) (string, error) {
			pw, err := samePassword(r)
			if err != nil {
				return "", err
			}
			return op(actor, pw)
		})
		return
	}
	pw := newPassword()
	summary, err := op(actorOf(r), pw)
	if err != nil {
		s.flash(w, r, "/mailboxes", "error: "+err.Error())
		return
	}
	s.render(w, r, "password_once", "mailboxes", "New password", struct{ Summary, Password string }{summary, pw})
}

// rand32 returns 160 random bits as text, for cookies that are not sessions.
func rand32() string { return rand.Text() + rand.Text()[:6] }

// newPassword returns 100 random bits as four groups of five base32 characters.
func newPassword() string {
	t := strings.ToLower(rand.Text())
	return t[0:5] + "-" + t[5:10] + "-" + t[10:15] + "-" + t[15:20]
}

func (s *server) mailboxState(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/mailboxes", func(actor string) (string, error) {
		return s.admin.SetMailboxState(actor, r.PostFormValue("address"), store.State(r.PostFormValue("state")))
	})
}

func (s *server) mailboxRemove(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/mailboxes", func(actor string) (string, error) {
		return s.admin.RemoveMailbox(actor, r.PostFormValue("address"))
	})
}

func samePassword(r *http.Request) (string, error) {
	return validate.SamePassword(r.PostFormValue("password"), r.PostFormValue("password2"))
}

func (s *server) aliasEdit(w http.ResponseWriter, r *http.Request) {
	a, ok := find(s, w, r, func(snap store.Snapshot) []store.Alias { return snap.Aliases }, func(a store.Alias) string { return a.Address })
	if ok {
		s.render(w, r, "alias_edit", "aliases", a.Address, a)
	}
}

func formTargets(r *http.Request) []string {
	return strings.FieldsFunc(r.PostFormValue("targets"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })
}

func (s *server) aliasAdd(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/aliases", func(actor string) (string, error) {
		return s.admin.AddAlias(actor, r.PostFormValue("address"), formTargets(r))
	})
}

func (s *server) aliasTargets(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/aliases", func(actor string) (string, error) {
		return s.admin.SetAliasTargets(actor, r.PostFormValue("address"), formTargets(r))
	})
}

func (s *server) aliasRemove(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/aliases", func(actor string) (string, error) {
		return s.admin.RemoveAlias(actor, r.PostFormValue("address"))
	})
}

func (s *server) sendAsAdd(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/sendas", func(actor string) (string, error) {
		return s.admin.AddSendAs(actor, r.PostFormValue("mailbox"), r.PostFormValue("address"))
	})
}

func (s *server) sendAsRemove(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/sendas", func(actor string) (string, error) {
		return s.admin.RemoveSendAs(actor, r.PostFormValue("mailbox"), r.PostFormValue("address"))
	})
}

func (s *server) changeLog(w http.ResponseWriter, r *http.Request) {
	entries, err := s.admin.Log()
	if err != nil {
		s.fail(w, "log", err)
		return
	}
	slices.Reverse(entries)
	s.render(w, r, "log", "log", "Change log", entries)
}
