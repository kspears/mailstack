package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"rsc.io/qr"

	"github.com/kspears/mailstack/internal/auth"
	"github.com/kspears/mailstack/internal/store"
)

// Cookie names. Outside local development each carries the __Host- prefix,
// which makes the browser refuse it unless it is Secure, has Path=/ and no
// Domain: no other hostname can set one or be sent one.
const (
	sessionCookie  = "mailctl"
	preCookie      = "mailctl-pre"     // keys the CSRF token before sign-in
	ceremonyCookie = "mailctl-passkey" // which passkey challenge is in flight
	rspamdCookie   = "mailctl-rspamd"  // on the rspamd hostname only
	nonceCookie    = "mailctl-handoff" // on the rspamd hostname only

	gatePrefix = "/_mailstack/" // rspamd's own controller serves /auth, so not that
)

func (s *server) cookieName(name string) string {
	if s.cfg.Insecure {
		return name
	}
	return "__Host-" + name
}

func (s *server) cookie(r *http.Request, name string) string {
	c, err := r.Cookie(s.cookieName(name))
	if err != nil {
		return ""
	}
	return c.Value
}

// setCookie sets a host-only cookie; maxAge < 0 removes it.
func (s *server) setCookie(w http.ResponseWriter, name, value string, maxAge int, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(name), Value: value, Path: "/", MaxAge: maxAge,
		Secure: !s.cfg.Insecure, HttpOnly: true, SameSite: sameSite})
}

func (s *server) origin(host string) string {
	if s.cfg.Insecure {
		return "http://" + host
	}
	return "https://" + host
}

// hostAllowed keeps each hostname to its own paths. The gate paths belong to
// the rspamd hostname; the check itself is a sub-request from the proxy, whose
// Host header is the proxy's business. Everything else is the admin hostname's.
func (s *server) hostAllowed(r *http.Request) bool {
	host := strings.ToLower(r.Host)
	switch {
	case r.URL.Path == gatePrefix+"check":
		return true
	case strings.HasPrefix(r.URL.Path, gatePrefix):
		return s.cfg.RspamdHost != "" && host == s.cfg.RspamdHost
	}
	return host == s.cfg.AdminHost
}

// public lists what a visitor with no session may reach.
func public(path string) bool {
	switch path {
	case "/signin", "/signin/passkey/begin", "/signin/passkey/finish", "/enrol", "/enrol/qr":
		return true
	}
	return strings.HasPrefix(path, "/static/") || strings.HasPrefix(path, gatePrefix)
}

func cspFor(path string) string {
	switch path {
	case "/signin", "/account":
		return cspScript
	case "/enrol", "/account/authenticator/new":
		return cspImage
	}
	return csp
}

// csrfKeyOf is what the CSRF token is keyed to: the session once signed in,
// the pre-session cookie before.
func (s *server) csrfKeyOf(r *http.Request) string {
	if sess, ok := sessionOf(r); ok {
		return "session:" + base64.RawURLEncoding.EncodeToString(sess.IDHash)
	}
	return "pre:" + s.cookie(r, preCookie)
}

// ensurePre gives a signed-out visitor the cookie the sign-in form's token is
// keyed to, and returns the request as it will look once the cookie is set.
func (s *server) ensurePre(w http.ResponseWriter, r *http.Request) *http.Request {
	if s.cookie(r, preCookie) != "" {
		return r
	}
	value := rand32()
	s.setCookie(w, preCookie, value, 0, http.SameSiteStrictMode)
	r = r.Clone(r.Context())
	r.AddCookie(&http.Cookie{Name: s.cookieName(preCookie), Value: value})
	return r
}

// from is the visitor's address for the log lines bans are made from. The
// header is believed only on a connection from the proxy's own address:
// anything else could name an innocent address and have it banned.
func (s *server) from(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !s.cfg.TrustedProxy.IsValid() || peer.Unmap() != s.cfg.TrustedProxy.Unmap() {
		return host
	}
	// The proxy appends, so the last entry is the one it wrote.
	parts := strings.Split(r.Header.Get(s.cfg.ClientAddrHeader), ",")
	if visitor, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
		return visitor.Unmap().String()
	}
	// Said out loud, because the consequence is quiet: failures would be logged,
	// and banned, under the proxy's own address.
	s.logf("warning: the proxy sent no usable %s header; treating its own address %s as the visitor's", s.cfg.ClientAddrHeader, host)
	return host
}

func (s *server) authRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /signin", s.signInPage)
	mux.HandleFunc("POST /signin", s.signIn)
	mux.HandleFunc("POST /signin/passkey/begin", s.passkeyBegin)
	mux.HandleFunc("POST /signin/passkey/finish", s.passkeySignIn)
	mux.HandleFunc("POST /signout", s.signOut)
	mux.HandleFunc("GET /enrol", s.enrolPage)
	mux.HandleFunc("GET /enrol/qr", s.enrolQR)
	mux.HandleFunc("POST /enrol", s.enrol)
	mux.HandleFunc("GET /account", s.account)
	mux.HandleFunc("POST /account/prove", s.prove)
	mux.HandleFunc("POST /account/prove/passkey/begin", s.passkeyBegin)
	mux.HandleFunc("POST /account/prove/passkey/finish", s.passkeyProve)
	mux.HandleFunc("POST /account/password", s.changePassword)
	mux.HandleFunc("POST /account/passkeys/begin", s.passkeyAddBegin)
	mux.HandleFunc("POST /account/passkeys/finish", s.passkeyAddFinish)
	mux.HandleFunc("POST /account/passkeys/remove", s.passkeyRemove)
	mux.HandleFunc("POST /account/authenticator/new", s.authenticatorPage)
	mux.HandleFunc("GET /account/authenticator/qr", s.authenticatorQR)
	mux.HandleFunc("POST /account/authenticator", s.authenticatorConfirm)
	mux.HandleFunc("GET /handoff", s.handoff)
	mux.HandleFunc("GET "+gatePrefix+"check", s.gateCheck)
	mux.HandleFunc("GET "+gatePrefix+"start", s.gateStart)
	mux.HandleFunc("GET "+gatePrefix+"finish", s.gateFinish)
}

// --- sign-in -----------------------------------------------------------------

func (s *server) signInPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, s.ensurePre(w, r), "signin", "", "Sign in", nil)
}

func (s *server) signInFailed(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, s.ensurePre(w, r), "signin", page{Title: "Sign in", Flash: auth.ErrSignIn.Error(), IsErr: true})
}

func (s *server) startSession(w http.ResponseWriter, token string) {
	s.setCookie(w, sessionCookie, token, int(auth.SessionLife.Seconds()), http.SameSiteStrictMode)
	s.setCookie(w, preCookie, "", -1, http.SameSiteStrictMode)
}

func (s *server) signIn(w http.ResponseWriter, r *http.Request) {
	token, err := s.auth.SignIn(s.from(r), r.PostFormValue("address"), r.PostFormValue("password"), r.PostFormValue("code"))
	if errors.Is(err, auth.ErrSignIn) {
		s.signInFailed(w, r)
		return
	}
	if err != nil {
		s.fail(w, "sign-in", err)
		return
	}
	s.startSession(w, token)
	http.Redirect(w, r, "/mailboxes", http.StatusSeeOther)
}

func (s *server) signOut(w http.ResponseWriter, r *http.Request) {
	if sess, ok := sessionOf(r); ok {
		if err := s.auth.SignOut(sess); err != nil {
			s.fail(w, "sign-out", err)
			return
		}
	}
	s.setCookie(w, sessionCookie, "", -1, http.SameSiteStrictMode)
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

// --- passkeys ----------------------------------------------------------------

// showable is what to tell the visitor about err. Only a mistake they can
// correct is described; a fault is logged here and shown as nothing more.
func (s *server) showable(what string, err error) string {
	var problem auth.Problem
	if errors.As(err, &problem) || errors.Is(err, auth.ErrSignIn) {
		return err.Error()
	}
	s.logf("%q: %v", what, err)
	return "internal error"
}

func (s *server) sendOptions(w http.ResponseWriter, options any, id string, err error) {
	if err != nil {
		http.Error(w, s.showable("passkey challenge", err), http.StatusBadRequest)
		return
	}
	s.setCookie(w, ceremonyCookie, id, 300, http.SameSiteStrictMode)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

// scriptResult answers the passkey script: empty 204 on success, otherwise a
// line of text it shows as is.
func (s *server) scriptResult(w http.ResponseWriter, err error) bool {
	s.setCookie(w, ceremonyCookie, "", -1, http.SameSiteStrictMode)
	if err != nil {
		http.Error(w, s.showable("passkey", err), http.StatusBadRequest)
		return false
	}
	w.WriteHeader(http.StatusNoContent)
	return true
}

// passkeyBegin issues a challenge for signing in or for proving a session.
func (s *server) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	s.auth.DropCeremony(s.cookie(r, ceremonyCookie))
	options, id, err := s.auth.BeginPasskeySignIn(s.from(r))
	s.sendOptions(w, options, id, err)
}

func (s *server) passkeySignIn(w http.ResponseWriter, r *http.Request) {
	token, err := s.auth.FinishPasskeySignIn(s.from(r), s.cookie(r, ceremonyCookie), r)
	if err == nil {
		s.startSession(w, token)
	}
	s.scriptResult(w, err)
}

func (s *server) passkeyProve(w http.ResponseWriter, r *http.Request) {
	if sess, ok := sessionOf(r); ok {
		s.scriptResult(w, s.auth.ProveWithPasskey(s.from(r), sess, s.cookie(r, ceremonyCookie), r))
	}
}

func (s *server) passkeyAddBegin(w http.ResponseWriter, r *http.Request) {
	if sess, ok := sessionOf(r); ok {
		s.auth.DropCeremony(s.cookie(r, ceremonyCookie))
		options, id, err := s.auth.BeginPasskey(s.from(r), sess, r.URL.Query().Get("label"))
		s.sendOptions(w, options, id, err)
	}
}

func (s *server) passkeyAddFinish(w http.ResponseWriter, r *http.Request) {
	if sess, ok := sessionOf(r); ok {
		if s.scriptResult(w, s.auth.FinishPasskey(sess, s.cookie(r, ceremonyCookie), r)) {
			s.setFlash(w, "ok: passkey added")
		}
	}
}

func (s *server) passkeyRemove(w http.ResponseWriter, r *http.Request) {
	s.accountChange(w, r, "removed the passkey", func(sess store.Session) error {
		id, err := base64.RawURLEncoding.DecodeString(r.PostFormValue("id"))
		if err != nil {
			return auth.Problem("no such passkey")
		}
		return s.auth.RemovePasskey(sess, id)
	})
}

// --- enrolment ---------------------------------------------------------------

// enrolment shows the link's page to the browser r comes from; the
// authenticator key on it is that browser's alone until it is confirmed.
func (s *server) enrolment(w http.ResponseWriter, r *http.Request, token string) (auth.Enrolment, bool) {
	e, ok, err := s.auth.Enrolment(token, s.cookie(r, preCookie))
	if err != nil {
		s.fail(w, "enrolment", err)
		return e, false
	}
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		s.render(w, r, "enrol_gone", "", "Enrolment link", nil)
	}
	return e, ok
}

type enrolData struct {
	auth.Enrolment
	Token string
}

func (s *server) enrolPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	r = s.ensurePre(w, r)
	if e, ok := s.enrolment(w, r, token); ok {
		s.render(w, r, "enrol", "", "Set up your admin sign-in", enrolData{e, token})
	}
}

func (s *server) enrolQR(w http.ResponseWriter, r *http.Request) {
	e, ok, err := s.auth.Enrolment(r.URL.Query().Get("t"), s.cookie(r, preCookie))
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	writeQR(w, e.URI)
}

func writeQR(w http.ResponseWriter, text string) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	code.Scale = 5
	w.Header().Set("Content-Type", "image/png")
	w.Write(code.PNG())
}

func (s *server) enrol(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("token")
	session, err := s.auth.Enrol(token, s.cookie(r, preCookie), r.PostFormValue("password"), r.PostFormValue("password2"), r.PostFormValue("code"))
	if err != nil {
		line := "error: " + s.showable("enrolment", err)
		if e, ok := s.enrolment(w, r, token); ok {
			s.renderPage(w, r, "enrol", page{Title: "Set up your admin sign-in", Flash: line, IsErr: true, Data: enrolData{e, token}})
		}
		return
	}
	s.startSession(w, session)
	s.flash(w, r, "/account", "ok: you are signed in; add a passkey below to skip the password next time")
}

// --- the account page ----------------------------------------------------------

func (s *server) account(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionOf(r)
	keys, err := s.auth.Passkeys(sess)
	if err != nil {
		s.fail(w, "passkeys", err)
		return
	}
	type row struct {
		ID, Label, Created string
	}
	rows := make([]row, len(keys))
	for i, k := range keys {
		rows[i] = row{base64.RawURLEncoding.EncodeToString(k.ID), k.Label, k.Created.UTC().Format("2006-01-02")}
	}
	s.render(w, r, "account", "account", "Your sign-in", struct {
		Fresh    bool
		Passkeys []row
	}{s.auth.Fresh(sess), rows})
}

// accountChange runs one change to the admin's own credentials and returns to
// the account page with the outcome.
func (s *server) accountChange(w http.ResponseWriter, r *http.Request, done string, change func(store.Session) error) {
	sess, _ := sessionOf(r)
	line := "ok: " + done
	if err := change(sess); err != nil {
		line = "error: " + s.showable(r.URL.Path, err)
	}
	s.flash(w, r, "/account", line)
}

func (s *server) prove(w http.ResponseWriter, r *http.Request) {
	s.accountChange(w, r, "confirmed; you can make changes for the next 5 minutes", func(sess store.Session) error {
		return s.auth.Prove(s.from(r), sess, r.PostFormValue("password"), r.PostFormValue("code"))
	})
}

func (s *server) changePassword(w http.ResponseWriter, r *http.Request) {
	s.accountChange(w, r, "changed your password; your other sessions were signed out", func(sess store.Session) error {
		return s.auth.ChangePassword(sess, r.PostFormValue("password"), r.PostFormValue("password2"))
	})
}

// authenticatorPage starts a replacement. It is a POST because it makes a new
// pending key, discarding one the admin may be half-way through confirming.
func (s *server) authenticatorPage(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionOf(r)
	e, err := s.auth.NewAuthenticator(sess)
	if err != nil {
		s.flash(w, r, "/account", "error: "+s.showable("authenticator", err))
		return
	}
	s.render(w, r, "authenticator", "account", "Replace your authenticator", e)
}

func (s *server) authenticatorQR(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionOf(r)
	e, ok := s.auth.PendingAuthenticator(sess)
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeQR(w, e.URI)
}

func (s *server) authenticatorConfirm(w http.ResponseWriter, r *http.Request) {
	s.accountChange(w, r, "replaced your authenticator; the old one no longer works", func(sess store.Session) error {
		return s.auth.ConfirmAuthenticator(sess, r.PostFormValue("code"))
	})
}

// --- the gate in front of the rspamd UI ---------------------------------------
//
// The rspamd hostname has its own cookie, which opens the rspamd UI and
// nothing else. A signed-in admin gets one through a hand-off:
//
//	rspamd host  /_mailstack/start   sets a nonce cookie, sends its hash to...
//	admin host   /handoff            which, for a signed-in admin, issues a
//	                                 single-use ticket bound to that hash...
//	rspamd host  /_mailstack/finish  which swaps ticket plus nonce for the cookie.
//
// The redirect targets are the two configured hostnames and never come from
// the request. The nonce means a ticket works only in the browser that asked.

// gateCheck answers the proxy's question before it passes a request to rspamd.
func (s *server) gateCheck(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth.Session(s.cookie(r, rspamdCookie), store.RspamdSession); ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if s.cfg.RspamdHost == "" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	http.Redirect(w, r, s.origin(s.cfg.RspamdHost)+gatePrefix+"start", http.StatusFound)
}

func (s *server) gateStart(w http.ResponseWriter, r *http.Request) {
	nonce := rand32()
	// Lax, not Strict: the browser arrives back here from the admin hostname.
	s.setCookie(w, nonceCookie, nonce, 120, http.SameSiteLaxMode)
	q := url.Values{"n": {base64.RawURLEncoding.EncodeToString(auth.Hash(nonce))}}
	http.Redirect(w, r, s.origin(s.cfg.AdminHost)+"/handoff?"+q.Encode(), http.StatusFound)
}

// handoff is a GET that issues a ticket, and it has to be: the browser arrives
// by redirect from the rspamd hostname. What makes that safe is the nonce. A
// page that sends an admin's browser here learns nothing, and the ticket it
// causes to exist is useless without a cookie only this browser holds for the
// rspamd hostname, set by a /_mailstack/start that this browser itself made.
func (s *server) handoff(w http.ResponseWriter, r *http.Request) {
	sess, _ := sessionOf(r)
	nonceHash, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("n"))
	if err != nil || len(nonceHash) != 32 || s.cfg.RspamdHost == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ticket, err := s.auth.NewTicket(sess, nonceHash)
	if err != nil {
		s.fail(w, "hand-off", err)
		return
	}
	q := url.Values{"t": {ticket}}
	http.Redirect(w, r, s.origin(s.cfg.RspamdHost)+gatePrefix+"finish?"+q.Encode(), http.StatusFound)
}

func (s *server) gateFinish(w http.ResponseWriter, r *http.Request) {
	token, ok := s.auth.RedeemTicket(r.URL.Query().Get("t"), s.cookie(r, nonceCookie))
	s.setCookie(w, nonceCookie, "", -1, http.SameSiteLaxMode)
	if !ok {
		http.Error(w, "The hand-off to the spam filter failed. Open it again from the admin page.", http.StatusForbidden)
		return
	}
	s.setCookie(w, rspamdCookie, token, int(auth.SessionLife.Seconds()), http.SameSiteLaxMode)
	http.Redirect(w, r, "/", http.StatusFound)
}
