package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/kspears/mailstack/internal/store"
)

// A ceremony is the server's half of one passkey exchange, kept between the
// request that issues a challenge and the one that answers it. It lives in
// memory: losing them on a restart only means pressing the button again.
type ceremony struct {
	data    webauthn.SessionData
	admin   string // set for registration, empty for sign-in and proof
	label   string
	from    string
	expires time.Time
}

// startCeremony keeps a challenge until it is answered. Beginning a sign-in
// needs no session, so the table is bounded two ways: one visitor may hold
// only a few, and when it is full the oldest gives way to the newest.
func (s *Service) startCeremony(c ceremony) (string, error) {
	now := s.cfg.Now()
	c.expires = now.Add(ceremonyLife)
	id, _ := newToken()
	s.mu.Lock()
	defer s.mu.Unlock()
	var held int
	var oldest string
	for k, old := range s.ceremonies {
		if !now.Before(old.expires) {
			delete(s.ceremonies, k)
			continue
		}
		if old.from == c.from {
			held++
		}
		if oldest == "" || old.expires.Before(s.ceremonies[oldest].expires) {
			oldest = k
		}
	}
	if held >= maxCeremoniesPerVisitor {
		s.refused("sign-in", c.from, "passkey: too many challenges requested")
		return "", Problem("too many passkey requests; wait a few minutes and try again")
	}
	if len(s.ceremonies) >= maxCeremonies {
		delete(s.ceremonies, oldest)
	}
	s.ceremonies[id] = c
	return id, nil
}

// DropCeremony forgets a challenge that will not be answered: the browser
// that held it has asked for another, as it does when a prompt is cancelled
// and the button pressed again. Without this, cancelling a few times would
// use up the visitor's allowance and be logged as failed sign-ins.
func (s *Service) DropCeremony(id string) {
	s.mu.Lock()
	delete(s.ceremonies, id)
	s.mu.Unlock()
}

// takeCeremony uses a ceremony up: a challenge is answered once.
func (s *Service) takeCeremony(id string) (ceremony, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ceremonies[id]
	delete(s.ceremonies, id)
	return c, ok && s.cfg.Now().Before(c.expires)
}

type user struct {
	account     store.AdminAccount
	credentials []webauthn.Credential
}

func (u user) WebAuthnID() []byte                         { return u.account.Handle }
func (u user) WebAuthnName() string                       { return u.account.Address }
func (u user) WebAuthnDisplayName() string                { return u.account.Address }
func (u user) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

func (s *Service) loadUser(account store.AdminAccount) (user, error) {
	keys, err := s.st.Passkeys(account.Address)
	if err != nil {
		return user{}, err
	}
	u := user{account: account}
	for _, k := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Credential, &c); err != nil {
			return user{}, fmt.Errorf("stored passkey %q of %s: %w", k.Label, account.Address, err)
		}
		u.credentials = append(u.credentials, c)
	}
	return u, nil
}

func (s *Service) userOf(address string) (user, error) {
	account, ok, err := s.st.AdminByAddress(address)
	if err != nil {
		return user{}, err
	}
	if !ok {
		return user{}, store.ErrNoAdmin
	}
	return s.loadUser(account)
}

func cleanLabel(label string) string {
	label = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return -1
	}, strings.TrimSpace(label))
	if label == "" {
		return "passkey"
	}
	if r := []rune(label); len(r) > maxLabelLength {
		label = string(r[:maxLabelLength])
	}
	return label
}

// BeginPasskey starts adding a passkey to the session's admin. The options go
// to the browser as JSON; the id comes back with the answer.
func (s *Service) BeginPasskey(from string, sess store.Session, label string) (options any, id string, err error) {
	if !s.Fresh(sess) {
		return nil, "", errStale
	}
	u, err := s.userOf(sess.Admin)
	if err != nil {
		return nil, "", err
	}
	// A discoverable credential is what lets sign-in ask for no address. User
	// verification makes the passkey two factors on its own.
	creation, data, err := s.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(webauthn.Credentials(u.credentials).CredentialDescriptors()))
	if err != nil {
		return nil, "", err
	}
	id, err = s.startCeremony(ceremony{data: *data, admin: sess.Admin, label: cleanLabel(label), from: from})
	return creation, id, err
}

// FinishPasskey stores the passkey the browser made. r carries its answer.
func (s *Service) FinishPasskey(sess store.Session, id string, r *http.Request) error {
	c, ok := s.takeCeremony(id)
	if !ok || c.admin != sess.Admin {
		return Problem("that took too long; add the passkey again")
	}
	if !s.Fresh(sess) {
		return errStale
	}
	u, err := s.userOf(sess.Admin)
	if err != nil {
		return err
	}
	credential, err := s.wa.FinishRegistration(u, c.data, r)
	if err != nil {
		s.cfg.Logf("passkey registration for %s: %v", sess.Admin, err)
		return Problem("the passkey could not be verified; nothing was added")
	}
	if !credential.Flags.UserVerified {
		return Problem("this passkey did not confirm who you are (no PIN or biometric); nothing was added")
	}
	record, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	return s.st.AddPasskey(store.Passkey{ID: credential.ID, Admin: sess.Admin, Credential: record, Label: c.label, Created: s.cfg.Now()})
}

func (s *Service) RemovePasskey(sess store.Session, id []byte) error {
	if !s.Fresh(sess) {
		return errStale
	}
	removed, err := s.st.RemovePasskey(s.cfg.Now(), sess.Admin, id, sess.IDHash)
	if err == nil && !removed {
		err = Problem("no such passkey")
	}
	return err
}

func (s *Service) Passkeys(sess store.Session) ([]store.Passkey, error) {
	return s.st.Passkeys(sess.Admin)
}

// BeginPasskeySignIn issues a challenge that names no account, so it reveals
// nothing about who has one.
func (s *Service) BeginPasskeySignIn(from string) (options any, id string, err error) {
	assertion, data, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", err
	}
	id, err = s.startCeremony(ceremony{data: *data, from: from})
	return assertion, id, err
}

// finishAssertion verifies a passkey answer and returns whose it is.
func (s *Service) finishAssertion(from, what, id string, r *http.Request) (string, error) {
	c, ok := s.takeCeremony(id)
	if !ok || c.admin != "" {
		return "", s.refused(what, from, "passkey: challenge unknown or expired")
	}
	found, credential, err := s.wa.FinishPasskeyLogin(func(_, handle []byte) (webauthn.User, error) {
		account, ok, err := s.st.AdminByHandle(handle)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, store.ErrNoAdmin
		}
		return s.loadUser(account)
	}, c.data, r)
	if err != nil {
		return "", s.refused(what, from, fmt.Sprintf("passkey: %v", err))
	}
	// The record holds the sign counter and backup flags, which a sign-in may
	// change. A counter that does not rise is normal for a synced passkey and
	// is not treated as a failure.
	if record, err := json.Marshal(credential); err == nil {
		if err := s.st.UpdatePasskey(credential.ID, record); err != nil {
			s.cfg.Logf("update passkey record: %v", err)
		}
	}
	return found.(user).account.Address, nil
}

// FinishPasskeySignIn returns a new session's cookie value.
func (s *Service) FinishPasskeySignIn(from, id string, r *http.Request) (string, error) {
	address, err := s.finishAssertion(from, "sign-in", id, r)
	if err != nil {
		return "", err
	}
	return s.newSession(address)
}

// ProveWithPasskey renews a session's proof with one of its admin's passkeys.
func (s *Service) ProveWithPasskey(from string, sess store.Session, id string, r *http.Request) error {
	address, err := s.finishAssertion(from, "proof", id, r)
	if err != nil {
		return err
	}
	if address != sess.Admin {
		return s.refused("proof", from, "passkey: belongs to another admin")
	}
	return s.st.MarkProved(sess.IDHash, s.cfg.Now())
}
