// Package auth is the admin UI's own sign-in: passwords with an authenticator
// code, passkeys, sessions, enrolment links and the hand-off to the rspamd UI.
// It decides; internal/web only carries cookies and renders pages.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/bcrypt"

	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

const (
	SessionLife   = 12 * time.Hour
	EnrolmentLife = 24 * time.Hour
	ProofLife     = 5 * time.Minute
	ticketLife    = time.Minute
	// A right password followed by a wrong code is the only thing that counts
	// toward this limit. Counting wrong passwords would let anyone who knows an
	// admin's address keep that admin locked out.
	CodeFailureLimit  = 10
	CodeFailureWindow = time.Hour

	bcryptCost     = 12
	ceremonyLife   = 5 * time.Minute
	maxCeremonies  = 1000
	maxLabelLength = 40
)

// ErrSignIn is the one failure a caller may show. Why it failed is logged by
// Service and never returned.
var ErrSignIn = errors.New("Sign-in failed.")

// Config names the site. AdminHost is host[:port] as browsers send it.
type Config struct {
	AdminHost string
	// Origin is the scheme and host passkeys are bound to, such as
	// https://admin.example.test.
	Origin string
	Now    func() time.Time
	// BcryptCost is for tests, which hash hundreds of passwords; zero means 12.
	BcryptCost int
	// Logf receives one line per failed sign-in or proof. The visitor's address
	// comes first so that a ban rule can anchor on it.
	Logf func(format string, args ...any)
}

type Service struct {
	st   *store.Store
	cfg  Config
	wa   *webauthn.WebAuthn
	fake []byte

	mu         sync.Mutex
	ceremonies map[string]ceremony
	pending    map[string]pendingSecret
}

func New(st *store.Store, cfg Config) (*Service, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = bcryptCost
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	host := cfg.AdminHost
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: host, RPDisplayName: "mailctl", RPOrigins: []string{cfg.Origin}})
	if err != nil {
		return nil, fmt.Errorf("passkey configuration for %s: %w", cfg.Origin, err)
	}
	// Compared against when the address is unknown, so that an unknown address
	// costs the same bcrypt work as a known one.
	fake, err := bcrypt.GenerateFromPassword([]byte(rand.Text()), cfg.BcryptCost)
	if err != nil {
		return nil, err
	}
	return &Service{st: st, cfg: cfg, wa: wa, fake: fake, ceremonies: map[string]ceremony{}, pending: map[string]pendingSecret{}}, nil
}

// newToken returns 256 random bits for a cookie or a link, and the hash that
// is stored in its place.
func newToken() (token string, hash []byte) {
	raw := make([]byte, 32)
	rand.Read(raw)
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, Hash(token)
}

// Hash is how every token is stored and looked up.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func (s *Service) hashPassword(a, b string) (string, error) {
	pw, err := validate.SamePassword(a, b)
	if err != nil {
		return "", err
	}
	if err := validate.Password(pw); err != nil {
		return "", err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), s.cfg.BcryptCost)
	return string(h), err
}

// --- accounts, managed from the command line --------------------------------

// AddAdmin creates an admin with no way in yet and returns an enrolment token.
func (s *Service) AddAdmin(actor, address string) (token string, err error) {
	addr, err := validate.Address(address)
	if err != nil {
		return "", err
	}
	handle := make([]byte, 32)
	rand.Read(handle)
	if err := s.st.AddAdmin(s.cfg.Now(), actor, addr, handle); err != nil {
		return "", err
	}
	return s.newEnrolment(addr)
}

// ResetAdmin strips every credential and session and returns a new enrolment token.
func (s *Service) ResetAdmin(actor, address string) (token string, err error) {
	addr := strings.ToLower(strings.TrimSpace(address))
	if err := s.st.ResetAdmin(s.cfg.Now(), actor, addr); err != nil {
		return "", noAdmin(err, addr)
	}
	return s.newEnrolment(addr)
}

func (s *Service) RemoveAdmin(actor, address string) error {
	addr := strings.ToLower(strings.TrimSpace(address))
	return noAdmin(s.st.RemoveAdmin(s.cfg.Now(), actor, addr), addr)
}

func noAdmin(err error, address string) error {
	if errors.Is(err, store.ErrNoAdmin) {
		return fmt.Errorf("admin %s does not exist", address)
	}
	return err
}

func (s *Service) newEnrolment(address string) (string, error) {
	token, hash := newToken()
	secret := make([]byte, 20)
	rand.Read(secret)
	return token, s.st.NewEnrolment(address, hash, secret, s.cfg.Now().Add(EnrolmentLife))
}

// --- enrolment ---------------------------------------------------------------

// Enrolment is what the enrolment page shows. Looking never uses the link up.
type Enrolment struct {
	Address string
	Secret  string // base32, for typing into an authenticator by hand
	URI     string // for the QR code
}

func (s *Service) Enrolment(token string) (Enrolment, bool, error) {
	address, secret, ok, err := s.st.Enrolment(Hash(token), s.cfg.Now())
	if !ok || err != nil {
		return Enrolment{}, false, err
	}
	return Enrolment{address, secretEncoding.EncodeToString(secret), totpURI(s.cfg.AdminHost, address, secret)}, true, nil
}

// Enrol completes a link: it sets the password, confirms the authenticator
// with one code, and signs the new admin in. An error whose text may be shown
// is a mistake the person can correct; the link survives it.
func (s *Service) Enrol(token, pw, pw2, code string) (session string, err error) {
	now := s.cfg.Now()
	_, secret, ok, err := s.st.Enrolment(Hash(token), now)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("this enrolment link has been used, replaced or has expired; ask for a new one")
	}
	hash, err := s.hashPassword(pw, pw2)
	if err != nil {
		return "", err
	}
	step, ok := totpMatch(secret, code, now)
	if !ok {
		return "", errors.New("that code does not match; check the authenticator app and the clock on this device")
	}
	address, ok, err := s.st.CompleteEnrolment(now, Hash(token), hash, step)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("this enrolment link has been used, replaced or has expired; ask for a new one")
	}
	return s.newSession(address)
}

// --- sign-in -----------------------------------------------------------------

// SignIn checks an address, password and authenticator code sent together and
// returns a new session's cookie value. from is the visitor's address, for the
// log line a ban is made from.
func (s *Service) SignIn(from, address, password, code string) (session string, err error) {
	admin, err := s.checkPasswordAndCode(from, "sign-in", strings.ToLower(strings.TrimSpace(address)), password, code)
	if err != nil {
		return "", err
	}
	return s.newSession(admin)
}

func (s *Service) checkPasswordAndCode(from, what, address, password, code string) (string, error) {
	now := s.cfg.Now()
	refuse := func(why string) (string, error) {
		s.cfg.Logf("%s failed from=%s address=%q: %s", what, from, address, why)
		return "", ErrSignIn
	}
	admin, found, err := s.st.AdminByAddress(address)
	if err != nil {
		return "", err
	}
	hash := s.fake
	if found && admin.Hash != "" {
		hash = []byte(admin.Hash)
	}
	// bcrypt refuses more than 72 bytes outright; such a password was never
	// set, and the comparison still has to run for its cost.
	if len(password) > 72 {
		password, hash = "", s.fake
	}
	passwordOK := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	if !found || admin.Hash == "" || !passwordOK {
		return refuse("wrong address or password")
	}
	failures, err := s.st.CodeFailures(admin.Address, now.Add(-CodeFailureWindow))
	if err != nil {
		return "", err
	}
	if failures >= CodeFailureLimit {
		return refuse("too many wrong codes in the last hour")
	}
	step, ok := totpMatch(admin.TOTPSecret, code, now)
	if ok {
		// Spending the step is what makes a code single-use, including against
		// two requests racing with the same one.
		if ok, err = s.st.SpendTOTPStep(admin.Address, step); err != nil {
			return "", err
		}
	}
	if !ok {
		if err := s.st.AddCodeFailure(admin.Address, now); err != nil {
			return "", err
		}
		return refuse("wrong or reused code")
	}
	return admin.Address, nil
}

func (s *Service) newSession(address string) (string, error) {
	now := s.cfg.Now()
	// Sign-ins are rare enough to carry the housekeeping.
	if err := s.st.PruneAuth(now); err != nil {
		return "", err
	}
	token, hash := newToken()
	return token, s.st.CreateSession(store.Session{IDHash: hash, Admin: address, Kind: store.AdminSession, Expires: now.Add(SessionLife), Proved: now})
}

// Session returns the live session of the given kind for a cookie value.
func (s *Service) Session(token, kind string) (store.Session, bool) {
	if token == "" {
		return store.Session{}, false
	}
	sess, ok, err := s.st.SessionByHash(Hash(token), s.cfg.Now())
	if err != nil {
		s.cfg.Logf("session lookup: %v", err)
		return store.Session{}, false
	}
	return sess, ok && sess.Kind == kind
}

// SignOut ends the session and the rspamd session made from it.
func (s *Service) SignOut(sess store.Session) error { return s.st.DeleteSession(sess.IDHash) }

// --- fresh proof and the changes it guards -----------------------------------

// Fresh reports whether the session signed in, or proved itself again, recently
// enough to change a credential.
func (s *Service) Fresh(sess store.Session) bool {
	return s.cfg.Now().Sub(sess.Proved) < ProofLife
}

// Prove renews a session's proof with the password and a code.
func (s *Service) Prove(from string, sess store.Session, password, code string) error {
	if _, err := s.checkPasswordAndCode(from, "proof", sess.Admin, password, code); err != nil {
		return err
	}
	return s.st.MarkProved(sess.IDHash, s.cfg.Now())
}

var errStale = errors.New("confirm it is you first")

func (s *Service) ChangePassword(sess store.Session, pw, pw2 string) error {
	if !s.Fresh(sess) {
		return errStale
	}
	hash, err := s.hashPassword(pw, pw2)
	if err != nil {
		return err
	}
	return s.st.SetAdminPassword(s.cfg.Now(), sess.Admin, hash, sess.IDHash)
}

type pendingSecret struct {
	secret  []byte
	expires time.Time
}

// NewAuthenticator starts replacing the authenticator and returns what to
// show. Nothing changes until ConfirmAuthenticator sees a code from it.
func (s *Service) NewAuthenticator(sess store.Session) (Enrolment, error) {
	if !s.Fresh(sess) {
		return Enrolment{}, errStale
	}
	secret := make([]byte, 20)
	rand.Read(secret)
	s.mu.Lock()
	s.pending[string(sess.IDHash)] = pendingSecret{secret, s.cfg.Now().Add(ceremonyLife)}
	s.mu.Unlock()
	return Enrolment{sess.Admin, secretEncoding.EncodeToString(secret), totpURI(s.cfg.AdminHost, sess.Admin, secret)}, nil
}

// PendingAuthenticator is the replacement NewAuthenticator last started for
// this session, for drawing its QR code.
func (s *Service) PendingAuthenticator(sess store.Session) (Enrolment, bool) {
	s.mu.Lock()
	p, ok := s.pending[string(sess.IDHash)]
	s.mu.Unlock()
	if !ok || !s.cfg.Now().Before(p.expires) {
		return Enrolment{}, false
	}
	return Enrolment{sess.Admin, secretEncoding.EncodeToString(p.secret), totpURI(s.cfg.AdminHost, sess.Admin, p.secret)}, true
}

func (s *Service) ConfirmAuthenticator(sess store.Session, code string) error {
	if !s.Fresh(sess) {
		return errStale
	}
	now := s.cfg.Now()
	s.mu.Lock()
	p, ok := s.pending[string(sess.IDHash)]
	s.mu.Unlock()
	if !ok || !now.Before(p.expires) {
		return errors.New("that took too long; start replacing the authenticator again")
	}
	step, ok := totpMatch(p.secret, code, now)
	if !ok {
		return errors.New("that code does not match the new authenticator; nothing was changed")
	}
	s.mu.Lock()
	delete(s.pending, string(sess.IDHash))
	s.mu.Unlock()
	return s.st.SetAdminTOTP(now, sess.Admin, p.secret, step)
}

// --- hand-off to the rspamd hostname -----------------------------------------

// NewTicket lets the browser that holds nonce turn an admin session into an
// rspamd session, once, within a minute. nonceHash arrives from the rspamd
// hostname; the nonce itself stays in that hostname's cookie.
func (s *Service) NewTicket(sess store.Session, nonceHash []byte) (string, error) {
	token, hash := newToken()
	return token, s.st.NewTicket(hash, sess.IDHash, nonceHash, s.cfg.Now().Add(ticketLife))
}

// RedeemTicket returns an rspamd session's cookie value. That session opens
// the rspamd UI and nothing else, and ends with the admin session it came from.
func (s *Service) RedeemTicket(ticket, nonce string) (string, bool) {
	now := s.cfg.Now()
	parent, nonceHash, ok, err := s.st.TakeTicket(Hash(ticket), now)
	if err != nil {
		s.cfg.Logf("ticket: %v", err)
	}
	if !ok || nonce == "" || subtle.ConstantTimeCompare(nonceHash, Hash(nonce)) != 1 {
		return "", false
	}
	admin, ok, err := s.st.SessionByHash(parent, now)
	if err != nil || !ok || admin.Kind != store.AdminSession {
		return "", false
	}
	token, hash := newToken()
	err = s.st.CreateSession(store.Session{IDHash: hash, Admin: admin.Admin, Kind: store.RspamdSession, Parent: parent, Expires: admin.Expires, Proved: time.Unix(0, 0)})
	if err != nil {
		s.cfg.Logf("ticket: %v", err)
		return "", false
	}
	return token, true
}
