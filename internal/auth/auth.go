// Package auth is the admin UI's own sign-in: passwords with an authenticator
// code, passkeys, sessions, enrolment links and the hand-off to the rspamd UI.
// It decides; internal/web only carries cookies and renders pages.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

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
	pendingLife    = 15 * time.Minute
	maxPending     = 1000
	maxLabelLength = 40
	// Passkey challenges are kept in memory and anyone may ask for one, so
	// they are capped per visitor, and the oldest go first when the whole
	// table is full: a flood cannot fill it and lock the admins out.
	maxCeremonies           = 1000
	maxCeremoniesPerVisitor = 10
	// Every refused sign-in takes at least this long, measured from its start,
	// so the time taken does not say which check refused it.
	failureFloor = 750 * time.Millisecond
	// Passwords are compared one at a time, and a sign-in waits at most
	// checkWait for its turn. bcrypt is the costly step anyone may trigger
	// without an account; unbounded, a flood of sign-ins takes every CPU the
	// mail server has, and one at a time leaves the host's other CPU to mail.
	checkSlots = 1
	checkWait  = 2 * time.Second
	// The longest line Logf writes, in bytes. Docker's journald driver splits a
	// line over 16 KiB into separate entries, and the second would start with
	// text the visitor chose, so a ban rule anchored on the start of an entry
	// could be made to match it.
	maxLogLine = 1024
)

// ErrSignIn is the one failure a caller may show. Why it failed is logged by
// Service and never returned.
var ErrSignIn = errors.New("Sign-in failed.")

// ErrBusy is returned instead of checking a password while other checks hold
// every slot. It says nothing about the account. Passkey sign-in never waits
// for a slot.
var ErrBusy = Problem("Too many sign-ins at once. Try again in a moment.")

// A Problem is a mistake the person can correct, worded for them. Any other
// error from this package is a fault and must not be shown.
type Problem string

func (p Problem) Error() string { return string(p) }

// Config names the site. AdminHost is host[:port] as browsers send it.
type Config struct {
	AdminHost string
	// Origin is the scheme and host passkeys are bound to, such as
	// https://admin.example.test.
	Origin string
	Now    func() time.Time
	// BcryptCost is for tests, which hash hundreds of passwords; zero means 12.
	BcryptCost int
	// Sleep is time.Sleep unless a test, which fails on purpose hundreds of
	// times, replaces it.
	Sleep func(time.Duration)
	// Logf receives one line per failed sign-in or proof. The visitor's address
	// comes first so that a ban rule can anchor on it.
	Logf func(format string, args ...any)
}

type Service struct {
	st   *store.Store
	cfg  Config
	wa   *webauthn.WebAuthn
	fake []byte

	// codes serialises the count-then-record of wrong codes, so concurrent
	// requests cannot each see nine failures and all be allowed a tenth.
	codes sync.Mutex

	// checking holds one token per password comparison in progress; see compare.
	checking  chan struct{}
	checkWait time.Duration

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
	if cfg.Sleep == nil {
		cfg.Sleep = time.Sleep
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	cfg.Logf = SingleLine(cfg.Logf)
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
	return &Service{st: st, cfg: cfg, wa: wa, fake: fake, checking: make(chan struct{}, checkSlots), checkWait: checkWait,
		ceremonies: map[string]ceremony{}, pending: map[string]pendingSecret{}}, nil
}

// newToken returns 256 random bits for a cookie or a link, and the hash that
// is stored in its place.
func newToken() (token string, hash []byte) {
	raw := make([]byte, 32)
	rand.Read(raw)
	token = base64.RawURLEncoding.EncodeToString(raw)
	return token, Hash(token)
}

// SingleLine wraps logf so that one call writes exactly one line of at most
// maxLogLine bytes, whatever the arguments hold. Bans are made from this log,
// and several things in it (a path, an address, a library's error text) are
// chosen by the visitor: none of them may start a line of its own.
func SingleLine(logf func(format string, args ...any)) func(format string, args ...any) {
	const cut = " [truncated]"
	return func(format string, args ...any) {
		line := strings.Map(func(r rune) rune {
			if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
				return ' '
			}
			return r
		}, fmt.Sprintf(format, args...))
		if len(line) > maxLogLine {
			n := maxLogLine - len(cut)
			for n > 0 && !utf8.RuneStart(line[n]) {
				n--
			}
			line = line[:n] + cut
		}
		logf("%s", line)
	}
}

// refused logs a failure in the one format a ban rule matches,
// "<what> failed from=<address> <detail>", and returns the only error a
// visitor is shown for it.
func (s *Service) refused(what, from, detail string) error {
	s.cfg.Logf("%s failed from=%s %s", what, from, detail)
	return ErrSignIn
}

// Hash is how every token is stored and looked up.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// checkedPassword returns the password when both entries match and it is acceptable.
func checkedPassword(a, b string) (string, error) {
	pw, err := validate.SamePassword(a, b)
	if err == nil {
		err = validate.Password(pw)
	}
	if err != nil {
		return "", Problem(err.Error())
	}
	return pw, nil
}

func (s *Service) hash(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	return string(h), err
}

// --- accounts, managed from the command line --------------------------------

// AddAdmin creates an admin with no way in yet. It returns the address as
// stored and an enrolment token.
func (s *Service) AddAdmin(actor, address string) (addr, token string, err error) {
	if addr, err = validate.Address(address); err != nil {
		return "", "", err
	}
	handle := make([]byte, 32)
	rand.Read(handle)
	if err := s.st.AddAdmin(s.cfg.Now(), actor, addr, handle); err != nil {
		return "", "", err
	}
	token, err = s.newEnrolment(addr)
	return addr, token, err
}

// ResetAdmin strips every credential and session and returns a new enrolment token.
func (s *Service) ResetAdmin(actor, address string) (addr, token string, err error) {
	addr = normalise(address)
	if err := s.st.ResetAdmin(s.cfg.Now(), actor, addr); err != nil {
		return "", "", noAdmin(err, addr)
	}
	token, err = s.newEnrolment(addr)
	return addr, token, err
}

func (s *Service) RemoveAdmin(actor, address string) (addr string, err error) {
	addr = normalise(address)
	return addr, noAdmin(s.st.RemoveAdmin(s.cfg.Now(), actor, addr), addr)
}

// normalise is how an address is compared. Sign-in must not validate beyond
// this: refusing a malformed address early would skip the password comparison
// that makes an unknown address cost what a known one does.
func normalise(address string) string { return strings.ToLower(strings.TrimSpace(address)) }

func noAdmin(err error, address string) error {
	if errors.Is(err, store.ErrNoAdmin) {
		return fmt.Errorf("admin %s does not exist", address)
	}
	return err
}

func (s *Service) newEnrolment(address string) (string, error) {
	token, hash := newToken()
	return token, s.st.NewEnrolment(address, hash, s.cfg.Now().Add(EnrolmentLife))
}

// --- enrolment ---------------------------------------------------------------

// Enrolment is what the enrolment page shows.
type Enrolment struct {
	Address string
	Secret  string // base32, for typing into an authenticator by hand
	URI     string // for the QR code
}

func (s *Service) show(address string, secret []byte) Enrolment {
	return Enrolment{address, secretEncoding.EncodeToString(secret), totpURI(s.cfg.AdminHost, address, secret)}
}

// pendingSecret is an authenticator key that has been shown but not yet
// confirmed with a code. Until then it is nobody's second factor.
type pendingSecret struct {
	secret  []byte
	expires time.Time
}

// offer returns the pending key under name, making one if there is none, so
// that reloading a page does not invalidate the QR code already scanned.
func (s *Service) offer(name string, fresh bool) []byte {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, p := range s.pending {
		if !now.Before(p.expires) {
			delete(s.pending, k)
		}
	}
	if p, ok := s.pending[name]; ok && !fresh {
		return p.secret
	}
	// Each browser that opens a live enrolment link is offered a key, so the
	// table is bounded: when it is full the oldest offer gives way.
	if len(s.pending) >= maxPending {
		var oldest string
		for k, p := range s.pending {
			if oldest == "" || p.expires.Before(s.pending[oldest].expires) {
				oldest = k
			}
		}
		delete(s.pending, oldest)
	}
	secret := make([]byte, 20)
	rand.Read(secret)
	s.pending[name] = pendingSecret{secret, now.Add(pendingLife)}
	return secret
}

func (s *Service) offered(name string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[name]
	return p.secret, ok && s.cfg.Now().Before(p.expires)
}

func (s *Service) withdraw(name string) {
	s.mu.Lock()
	delete(s.pending, name)
	s.mu.Unlock()
}

// enrolKey names the key offered to one browser for one link. The link alone
// is not enough to learn it: whatever else saw the address of the link, a
// preview bot or a log, is shown a different key that is never stored.
func enrolKey(token, browser string) string {
	return "enrol\x00" + string(Hash(token)) + "\x00" + browser
}

// Enrolment looks a link up for the browser identified by browser, a value
// only that browser holds. Looking never uses the link up.
func (s *Service) Enrolment(token, browser string) (Enrolment, bool, error) {
	address, ok, err := s.st.Enrolment(Hash(token), s.cfg.Now())
	if !ok || err != nil || browser == "" {
		return Enrolment{}, false, err
	}
	return s.show(address, s.offer(enrolKey(token, browser), false)), true, nil
}

// Enrol completes a link: it sets the password, confirms the authenticator
// with one code, and signs the new admin in. A Problem leaves the link usable.
func (s *Service) Enrol(token, browser, pw, pw2, code string) (session string, err error) {
	const gone = Problem("this enrolment link has been used, replaced or has expired; ask for a new one")
	now := s.cfg.Now()
	if _, ok, err := s.st.Enrolment(Hash(token), now); err != nil {
		return "", err
	} else if !ok {
		return "", gone
	}
	secret, ok := s.offered(enrolKey(token, browser))
	if !ok {
		return "", Problem("this page was open too long; scan the code shown now and try again")
	}
	password, err := checkedPassword(pw, pw2)
	if err != nil {
		return "", err
	}
	step, ok := totpMatch(secret, code, now)
	if !ok {
		return "", Problem("that code does not match; check the authenticator app and the clock on this device")
	}
	// Hashed last: it is the expensive step, and a mistyped code is common.
	hash, err := s.hash(password)
	if err != nil {
		return "", err
	}
	address, ok, err := s.st.CompleteEnrolment(now, Hash(token), hash, secret, step)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", gone
	}
	s.withdraw(enrolKey(token, browser))
	return s.newSession(address)
}

// --- sign-in -----------------------------------------------------------------

// SignIn checks an address, password and authenticator code sent together and
// returns a new session's cookie value. from is the visitor's address, for the
// log line a ban is made from.
func (s *Service) SignIn(ctx context.Context, from, address, password, code string) (session string, err error) {
	admin, err := s.checkPasswordAndCode(ctx, from, "sign-in", normalise(address), password, code)
	if err != nil {
		return "", err
	}
	return s.newSession(admin)
}

func (s *Service) checkPasswordAndCode(ctx context.Context, from, what, address, password, code string) (string, error) {
	started := time.Now()
	admin, err := s.passwordAndCode(ctx, from, what, address, password, code)
	if err != nil {
		s.cfg.Sleep(time.Until(started.Add(failureFloor)))
	}
	return admin, err
}

func (s *Service) passwordAndCode(ctx context.Context, from, what, address, password, code string) (string, error) {
	now := s.cfg.Now()
	refuse := func(why string) (string, error) {
		return "", s.refused(what, from, fmt.Sprintf("address=%q: %s", address, why))
	}
	admin, found, err := s.st.AdminByAddress(address)
	if err != nil {
		return "", err
	}
	usable := found && admin.Hash != ""
	hash := s.fake
	if usable {
		hash = []byte(admin.Hash)
	}
	// bcrypt refuses more than 72 bytes outright; such a password was never
	// set, and the comparison still has to run for its cost.
	if len(password) > 72 {
		password, hash = "", s.fake
	}
	passwordOK, compared := s.compare(ctx, hash, password)
	if !compared {
		// Logged as a failure, so a ban counts it: one source flooding the
		// sign-in is banned like one guessing passwords.
		s.refused(what, from, "busy: too many sign-ins at once")
		return "", ErrBusy
	}
	if !usable || !passwordOK {
		return refuse("wrong address or password")
	}
	s.codes.Lock()
	defer s.codes.Unlock()
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

// compare checks password against hash in one of the slots. It waits up to
// checkWait for a slot, or until the visitor goes away, and reports whether
// the comparison ran at all. The slot is freed as soon as the comparison is
// done, before any failure delay, so slow refusals cannot hold it.
func (s *Service) compare(ctx context.Context, hash []byte, password string) (match, ran bool) {
	t := time.NewTimer(s.checkWait)
	defer t.Stop()
	select {
	case s.checking <- struct{}{}:
	case <-t.C:
		return false, false
	case <-ctx.Done():
		return false, false
	}
	defer func() { <-s.checking }()
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil, true
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
func (s *Service) Prove(ctx context.Context, from string, sess store.Session, password, code string) error {
	if _, err := s.checkPasswordAndCode(ctx, from, "proof", sess.Admin, password, code); err != nil {
		return err
	}
	return s.st.MarkProved(sess.IDHash, s.cfg.Now())
}

const errStale = Problem("confirm it is you first")

func (s *Service) ChangePassword(sess store.Session, pw, pw2 string) error {
	if !s.Fresh(sess) {
		return errStale
	}
	password, err := checkedPassword(pw, pw2)
	if err != nil {
		return err
	}
	hash, err := s.hash(password)
	if err != nil {
		return err
	}
	return s.st.SetAdminPassword(s.cfg.Now(), sess.Admin, hash, sess.IDHash)
}

func replaceKey(sess store.Session) string { return "replace\x00" + string(sess.IDHash) }

// NewAuthenticator starts replacing the authenticator and returns what to
// show. Nothing changes until ConfirmAuthenticator sees a code from it.
func (s *Service) NewAuthenticator(sess store.Session) (Enrolment, error) {
	if !s.Fresh(sess) {
		return Enrolment{}, errStale
	}
	return s.show(sess.Admin, s.offer(replaceKey(sess), true)), nil
}

// PendingAuthenticator is the replacement NewAuthenticator last started for
// this session, for drawing its QR code.
func (s *Service) PendingAuthenticator(sess store.Session) (Enrolment, bool) {
	secret, ok := s.offered(replaceKey(sess))
	if !ok {
		return Enrolment{}, false
	}
	return s.show(sess.Admin, secret), true
}

// ConfirmAuthenticator makes the pending authenticator the admin's and ends
// the admin's other sessions.
func (s *Service) ConfirmAuthenticator(sess store.Session, code string) error {
	if !s.Fresh(sess) {
		return errStale
	}
	secret, ok := s.offered(replaceKey(sess))
	if !ok {
		return Problem("that took too long; start replacing the authenticator again")
	}
	now := s.cfg.Now()
	step, ok := totpMatch(secret, code, now)
	if !ok {
		return Problem("that code does not match the new authenticator; nothing was changed")
	}
	s.withdraw(replaceKey(sess))
	return s.st.SetAdminTOTP(now, sess.Admin, secret, step, sess.IDHash)
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
