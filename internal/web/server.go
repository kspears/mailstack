// Package web is the server-rendered admin UI. It is a second front end over
// the same operations the CLI uses, and works without JavaScript.
package web

import (
	"bytes"
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
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/kspears/mailstack/internal/access"
	"github.com/kspears/mailstack/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	maxBody     = 64 << 10
	flashCookie = "flash"
	csp         = "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
)

// Admin is the set of operations the UI needs; *generate.Admin satisfies it.
type Admin interface {
	Snapshot() (store.Snapshot, error)
	Log() ([]store.LogEntry, error)
	AddMailbox(actor, address, name, password string, adoptExisting bool) (string, error)
	SetPassword(actor, address, password string) (string, error)
	SetMailboxState(actor, address string, state store.State) (string, error)
	RemoveMailbox(actor, address string) (string, error)
	AddAlias(actor, address string, targets []string) (string, error)
	RemoveAlias(actor, address string) (string, error)
}

// Config wires the server. Logf receives one line per request plus the reason
// for each refused identity; it never receives query strings, bodies or tokens.
type Config struct {
	Admin      Admin
	Identifier access.Identifier
	Logf       func(format string, args ...any)
	Now        func() time.Time
}

type server struct {
	admin     Admin
	id        access.Identifier
	logf      func(string, ...any)
	now       func() time.Time
	csrfKey   []byte
	templates *template.Template
	static    http.Handler
}

type ctxKey struct{}

// New returns the handler for the whole UI. Every request is identified first.
func New(cfg Config) (http.Handler, error) {
	s := &server{admin: cfg.Admin, id: cfg.Identifier, logf: cfg.Logf, now: cfg.Now, csrfKey: make([]byte, 32)}
	if s.now == nil {
		s.now = time.Now
	}
	if _, err := rand.Read(s.csrfKey); err != nil {
		return nil, fmt.Errorf("generate CSRF key: %w", err)
	}
	t, err := template.New("").Funcs(template.FuncMap{"stamp": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.templates = t
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	s.static = http.StripPrefix("/static/", http.FileServerFS(sub))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/mailboxes", http.StatusSeeOther) })
	mux.HandleFunc("GET /static/", s.static.ServeHTTP)
	mux.HandleFunc("GET /mailboxes", s.mailboxes)
	mux.HandleFunc("GET /mailboxes/edit", s.mailboxEdit)
	mux.HandleFunc("GET /mailboxes/remove", s.mailboxRemoveConfirm)
	mux.HandleFunc("POST /mailboxes/add", s.mailboxAdd)
	mux.HandleFunc("POST /mailboxes/password", s.mailboxPassword)
	mux.HandleFunc("POST /mailboxes/state", s.mailboxState)
	mux.HandleFunc("POST /mailboxes/remove", s.mailboxRemove)
	mux.HandleFunc("GET /aliases", s.aliases)
	mux.HandleFunc("POST /aliases/add", s.aliasAdd)
	mux.HandleFunc("POST /aliases/remove", s.aliasRemove)
	mux.HandleFunc("GET /domains", s.domains)
	mux.HandleFunc("GET /sendas", s.sendAs)
	mux.HandleFunc("GET /log", s.changeLog)
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

func (s *server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		h := sw.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")

		actor, err := s.id.Identify(r)
		if err != nil {
			s.logf("denied %s %s: %v", r.Method, r.URL.Path, err)
			http.Error(sw, "forbidden", http.StatusForbidden)
			actor = "-"
		} else {
			r.Body = http.MaxBytesReader(sw, r.Body, maxBody)
			next.ServeHTTP(sw, r.WithContext(contextWithActor(r, actor)))
		}
		s.logf("%s %s %d %s %s", r.Method, r.URL.Path, sw.status, actor, s.now().Sub(start).Round(time.Millisecond))
	})
}

func (s *server) token(actor string) string {
	m := hmac.New(sha256.New, s.csrfKey)
	m.Write([]byte(actor))
	return hex.EncodeToString(m.Sum(nil))
}

// checkPost enforces same-origin and the per-identity token, then parses the form.
func (s *server) checkPost(r *http.Request) error {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		return fmt.Errorf("Sec-Fetch-Site is %q", site)
	}
	source := r.Header.Get("Origin")
	if source == "" {
		source = r.Header.Get("Referer")
	}
	u, err := url.Parse(source)
	if source == "" || err != nil || u.Host != r.Host {
		return fmt.Errorf("origin does not match host %q", r.Host)
	}
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("read form: %w", err)
	}
	if !hmac.Equal([]byte(r.PostFormValue("csrf")), []byte(s.token(actorOf(r)))) {
		return fmt.Errorf("bad or missing CSRF token")
	}
	return nil
}

// do runs a change from a POST, then redirects to the page with the exact CLI line as a flash.
func (s *server) do(w http.ResponseWriter, r *http.Request, back string, op func(actor string) (string, error)) {
	if err := s.checkPost(r); err != nil {
		s.logf("refused %s %s: %v", r.Method, r.URL.Path, err)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	line := ""
	if summary, err := op(actorOf(r)); err != nil {
		line = "error: " + err.Error()
	} else {
		line = "ok: " + summary
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(line)), Path: "/", MaxAge: 60, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, back, http.StatusSeeOther)
}

type page struct {
	Title string
	Nav   string
	CSRF  string
	Flash string
	IsErr bool
	Actor string
	Data  any
}

func (s *server) render(w http.ResponseWriter, r *http.Request, name, nav, title string, data any) {
	p := page{Title: title, Nav: nav, CSRF: s.token(actorOf(r)), Actor: actorOf(r), Data: data}
	if c, err := r.Cookie(flashCookie); err == nil {
		if b, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil {
			p.Flash = string(b)
			p.IsErr = strings.HasPrefix(p.Flash, "error:")
		}
		http.SetCookie(w, &http.Cookie{Name: flashCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
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

func (s *server) mailboxes(w http.ResponseWriter, r *http.Request) {
	snap, err := s.admin.Snapshot()
	if err != nil {
		s.fail(w, "snapshot", err)
		return
	}
	s.render(w, r, "mailboxes", "mailboxes", "Mailboxes", snap.Mailboxes)
}

func (s *server) mailbox(w http.ResponseWriter, r *http.Request) (store.Mailbox, bool) {
	snap, err := s.admin.Snapshot()
	if err != nil {
		s.fail(w, "snapshot", err)
		return store.Mailbox{}, false
	}
	i := slices.IndexFunc(snap.Mailboxes, func(m store.Mailbox) bool { return m.Address == r.URL.Query().Get("address") })
	if i < 0 {
		http.NotFound(w, r)
		return store.Mailbox{}, false
	}
	return snap.Mailboxes[i], true
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
	s.do(w, r, "/mailboxes", func(actor string) (string, error) {
		pw, err := samePassword(r)
		if err != nil {
			return "", err
		}
		return s.admin.AddMailbox(actor, r.PostFormValue("address"), strings.TrimSpace(r.PostFormValue("name")), pw, false)
	})
}

func (s *server) mailboxPassword(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/mailboxes", func(actor string) (string, error) {
		pw, err := samePassword(r)
		if err != nil {
			return "", err
		}
		return s.admin.SetPassword(actor, r.PostFormValue("address"), pw)
	})
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
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		return "", fmt.Errorf("passwords do not match")
	}
	return pw, nil
}

func (s *server) aliases(w http.ResponseWriter, r *http.Request) {
	snap, err := s.admin.Snapshot()
	if err != nil {
		s.fail(w, "snapshot", err)
		return
	}
	s.render(w, r, "aliases", "aliases", "Aliases", snap.Aliases)
}

func (s *server) aliasAdd(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/aliases", func(actor string) (string, error) {
		targets := strings.FieldsFunc(r.PostFormValue("targets"), func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t' })
		return s.admin.AddAlias(actor, r.PostFormValue("address"), targets)
	})
}

func (s *server) aliasRemove(w http.ResponseWriter, r *http.Request) {
	s.do(w, r, "/aliases", func(actor string) (string, error) {
		return s.admin.RemoveAlias(actor, r.PostFormValue("address"))
	})
}

func (s *server) domains(w http.ResponseWriter, r *http.Request) {
	snap, err := s.admin.Snapshot()
	if err != nil {
		s.fail(w, "snapshot", err)
		return
	}
	s.render(w, r, "domains", "domains", "Domains", snap.Domains)
}

func (s *server) sendAs(w http.ResponseWriter, r *http.Request) {
	snap, err := s.admin.Snapshot()
	if err != nil {
		s.fail(w, "snapshot", err)
		return
	}
	s.render(w, r, "sendas", "sendas", "Send-as grants", snap.Grants)
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
