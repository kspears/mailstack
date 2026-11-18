package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// The tables behind the admin UI's own sign-in. Nothing here feeds the mail
// daemons, so these writes commit on their own and never make a generation.
const authSchema = `
CREATE TABLE admins (
	address        TEXT PRIMARY KEY,
	hash           TEXT NOT NULL DEFAULT '',
	totp_secret    BLOB,
	totp_last_step INTEGER NOT NULL DEFAULT 0,
	handle         BLOB NOT NULL UNIQUE
);
CREATE TABLE passkeys (
	id         BLOB PRIMARY KEY,
	admin      TEXT NOT NULL REFERENCES admins(address) ON DELETE CASCADE,
	credential BLOB NOT NULL,
	label      TEXT NOT NULL,
	created    INTEGER NOT NULL
);
CREATE TABLE sessions (
	id_hash BLOB PRIMARY KEY,
	admin   TEXT NOT NULL REFERENCES admins(address) ON DELETE CASCADE,
	kind    TEXT NOT NULL CHECK (kind IN ('admin','rspamd')),
	parent  BLOB REFERENCES sessions(id_hash) ON DELETE CASCADE,
	expires INTEGER NOT NULL,
	proved  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE enrolments (
	token_hash BLOB PRIMARY KEY,
	admin      TEXT NOT NULL REFERENCES admins(address) ON DELETE CASCADE,
	expires    INTEGER NOT NULL
);
CREATE TABLE code_failures (
	admin TEXT NOT NULL REFERENCES admins(address) ON DELETE CASCADE,
	at    INTEGER NOT NULL
);
CREATE TABLE tickets (
	token_hash BLOB PRIMARY KEY,
	session    BLOB NOT NULL REFERENCES sessions(id_hash) ON DELETE CASCADE,
	nonce_hash BLOB NOT NULL,
	expires    INTEGER NOT NULL
);`

func init() { migrations = append(migrations, authSchema) }

const (
	AdminSession  = "admin"
	RspamdSession = "rspamd"
)

// AdminAccount is one person who may sign in to the UI. Hash is empty and
// TOTPSecret nil until enrolment is completed. Handle is the random WebAuthn
// user handle; it never changes and is never shown.
type AdminAccount struct {
	Address    string
	Hash       string
	TOTPSecret []byte
	Handle     []byte
}

type AdminSummary struct {
	Address  string
	Enrolled bool
	Passkeys int
}

type Passkey struct {
	ID         []byte
	Admin      string
	Credential []byte
	Label      string
	Created    time.Time
}

// Session rows are keyed by the SHA-256 of the cookie value, so a copy of the
// database cannot be replayed as a cookie.
type Session struct {
	IDHash  []byte
	Admin   string
	Kind    string
	Parent  []byte
	Expires time.Time
	Proved  time.Time
}

// ErrNoAdmin is returned when an operation names an admin that does not exist.
var ErrNoAdmin = errors.New("no such admin")

func (s *Store) write(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func logTx(tx *sql.Tx, at time.Time, actor, action, subject string) error {
	_, err := tx.Exec("INSERT INTO log (time, actor, action, subject) VALUES (?, ?, ?, ?)",
		at.UTC().Format(time.RFC3339), actor, action, subject)
	return err
}

func mustExist(res sql.Result) error {
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNoAdmin
	}
	return nil
}

func (s *Store) AddAdmin(at time.Time, actor, address string, handle []byte) error {
	return s.write(func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRow("SELECT count(*) FROM admins WHERE address = ?", address).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return fmt.Errorf("admin %s already exists; use `mailctl admin reset` for a new enrolment link", address)
		}
		if _, err := tx.Exec("INSERT INTO admins (address, handle) VALUES (?, ?)", address, handle); err != nil {
			return err
		}
		return logTx(tx, at, actor, "admin.add", address)
	})
}

// RemoveAdmin deletes the admin with every credential, session and link.
func (s *Store) RemoveAdmin(at time.Time, actor, address string) error {
	return s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("DELETE FROM admins WHERE address = ?", address)
		if err != nil {
			return err
		}
		if err := mustExist(res); err != nil {
			return err
		}
		return logTx(tx, at, actor, "admin.remove", address)
	})
}

// ResetAdmin removes the admin's password, authenticator, passkeys, sessions
// and enrolment links, leaving an account that can only be enrolled again.
func (s *Store) ResetAdmin(at time.Time, actor, address string) error {
	return s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("UPDATE admins SET hash = '', totp_secret = NULL, totp_last_step = 0 WHERE address = ?", address)
		if err != nil {
			return err
		}
		if err := mustExist(res); err != nil {
			return err
		}
		for _, table := range []string{"passkeys", "sessions", "enrolments", "code_failures"} {
			if _, err := tx.Exec("DELETE FROM "+table+" WHERE admin = ?", address); err != nil {
				return err
			}
		}
		return logTx(tx, at, actor, "admin.reset", address)
	})
}

func (s *Store) Admins() ([]AdminSummary, error) {
	var out []AdminSummary
	err := scan(s.db, `SELECT address, hash <> '' AND totp_secret IS NOT NULL,
		(SELECT count(*) FROM passkeys WHERE admin = address) FROM admins ORDER BY address`, func(r *sql.Rows) error {
		var a AdminSummary
		if err := r.Scan(&a.Address, &a.Enrolled, &a.Passkeys); err != nil {
			return err
		}
		out = append(out, a)
		return nil
	})
	return out, err
}

func (s *Store) admin(where string, arg any) (AdminAccount, bool, error) {
	var a AdminAccount
	err := s.db.QueryRow("SELECT address, hash, totp_secret, handle FROM admins WHERE "+where+" = ?", arg).
		Scan(&a.Address, &a.Hash, &a.TOTPSecret, &a.Handle)
	if errors.Is(err, sql.ErrNoRows) {
		return a, false, nil
	}
	return a, err == nil, err
}

func (s *Store) AdminByAddress(address string) (AdminAccount, bool, error) {
	return s.admin("address", address)
}

func (s *Store) AdminByHandle(handle []byte) (AdminAccount, bool, error) {
	return s.admin("handle", handle)
}

// NewEnrolment stores a link for the admin and cancels any earlier one.
func (s *Store) NewEnrolment(address string, tokenHash []byte, expires time.Time) error {
	return s.write(func(tx *sql.Tx) error {
		if _, err := tx.Exec("DELETE FROM enrolments WHERE admin = ?", address); err != nil {
			return err
		}
		_, err := tx.Exec("INSERT INTO enrolments (token_hash, admin, expires) VALUES (?, ?, ?)", tokenHash, address, expires.Unix())
		return err
	})
}

// Enrolment looks a link up without using it.
func (s *Store) Enrolment(tokenHash []byte, now time.Time) (address string, ok bool, err error) {
	err = s.db.QueryRow("SELECT admin FROM enrolments WHERE token_hash = ? AND expires > ?", tokenHash, now.Unix()).Scan(&address)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return address, err == nil, err
}

// CompleteEnrolment uses the link up: it sets the password and authenticator,
// ends every session the admin had, and reports false if the link was no
// longer valid. secret is the authenticator key the person confirmed, and
// step the time step of the confirming code, which is thereby spent.
func (s *Store) CompleteEnrolment(now time.Time, tokenHash []byte, hash string, secret []byte, step int64) (address string, ok bool, err error) {
	err = s.write(func(tx *sql.Tx) error {
		err := tx.QueryRow("SELECT admin FROM enrolments WHERE token_hash = ? AND expires > ?", tokenHash, now.Unix()).Scan(&address)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec("UPDATE admins SET hash = ?, totp_secret = ?, totp_last_step = ? WHERE address = ?", hash, secret, step, address); err != nil {
			return err
		}
		for _, table := range []string{"enrolments", "sessions", "code_failures"} {
			if _, err := tx.Exec("DELETE FROM "+table+" WHERE admin = ?", address); err != nil {
				return err
			}
		}
		ok = true
		return logTx(tx, now, address, "admin.enrol", address)
	})
	return address, ok && err == nil, err
}

// SpendTOTPStep records that a code for step was accepted. It reports false
// when that step, or a later one, was already spent: a code works once.
func (s *Store) SpendTOTPStep(address string, step int64) (bool, error) {
	res, err := s.db.Exec("UPDATE admins SET totp_last_step = ? WHERE address = ? AND totp_last_step < ?", step, address, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *Store) AddCodeFailure(address string, at time.Time) error {
	_, err := s.db.Exec("INSERT INTO code_failures (admin, at) VALUES (?, ?)", address, at.Unix())
	return err
}

func (s *Store) CodeFailures(address string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow("SELECT count(*) FROM code_failures WHERE admin = ? AND at > ?", address, since.Unix()).Scan(&n)
	return n, err
}

// SetAdminPassword replaces the password and ends every other session of that
// admin; keep is the session making the change.
func (s *Store) SetAdminPassword(at time.Time, address, hash string, keep []byte) error {
	return s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("UPDATE admins SET hash = ? WHERE address = ?", hash, address)
		if err != nil {
			return err
		}
		if err := mustExist(res); err != nil {
			return err
		}
		if err := endOthers(tx, address, keep); err != nil {
			return err
		}
		return logTx(tx, at, address, "admin.password", address)
	})
}

// endOthers ends every admin session of address except keep. A credential is
// usually changed because it may have leaked, and a session opened with the
// old one must not outlive it.
func endOthers(tx *sql.Tx, address string, keep []byte) error {
	_, err := tx.Exec("DELETE FROM sessions WHERE admin = ? AND kind = 'admin' AND id_hash <> ?", address, keep)
	return err
}

// SetAdminTOTP replaces the authenticator and ends the admin's other
// sessions; step is the confirming code's step.
func (s *Store) SetAdminTOTP(at time.Time, address string, secret []byte, step int64, keep []byte) error {
	return s.write(func(tx *sql.Tx) error {
		res, err := tx.Exec("UPDATE admins SET totp_secret = ?, totp_last_step = ? WHERE address = ?", secret, step, address)
		if err != nil {
			return err
		}
		if err := mustExist(res); err != nil {
			return err
		}
		if err := endOthers(tx, address, keep); err != nil {
			return err
		}
		return logTx(tx, at, address, "admin.authenticator", address)
	})
}

func (s *Store) AddPasskey(p Passkey) error {
	return s.write(func(tx *sql.Tx) error {
		if _, err := tx.Exec("INSERT INTO passkeys (id, admin, credential, label, created) VALUES (?, ?, ?, ?, ?)",
			p.ID, p.Admin, p.Credential, p.Label, p.Created.Unix()); err != nil {
			return err
		}
		return logTx(tx, p.Created, p.Admin, "admin.passkey.add", p.Admin+" "+p.Label)
	})
}

// RemovePasskey deletes one of the admin's own passkeys, ends the admin's
// other sessions, and reports whether the passkey existed.
func (s *Store) RemovePasskey(at time.Time, address string, id, keep []byte) (bool, error) {
	removed := false
	err := s.write(func(tx *sql.Tx) error {
		var label string
		err := tx.QueryRow("SELECT label FROM passkeys WHERE id = ? AND admin = ?", id, address).Scan(&label)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM passkeys WHERE id = ? AND admin = ?", id, address); err != nil {
			return err
		}
		if err := endOthers(tx, address, keep); err != nil {
			return err
		}
		removed = true
		return logTx(tx, at, address, "admin.passkey.remove", address+" "+label)
	})
	return removed && err == nil, err
}

// UpdatePasskey stores the credential record after a sign-in changed it.
func (s *Store) UpdatePasskey(id, credential []byte) error {
	_, err := s.db.Exec("UPDATE passkeys SET credential = ? WHERE id = ?", credential, id)
	return err
}

func (s *Store) Passkeys(address string) ([]Passkey, error) {
	rows, err := s.db.Query("SELECT id, admin, credential, label, created FROM passkeys WHERE admin = ? ORDER BY created, id", address)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		var created int64
		if err := rows.Scan(&p.ID, &p.Admin, &p.Credential, &p.Label, &created); err != nil {
			return nil, err
		}
		p.Created = time.Unix(created, 0)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) CreateSession(sess Session) error {
	_, err := s.db.Exec("INSERT INTO sessions (id_hash, admin, kind, parent, expires, proved) VALUES (?, ?, ?, ?, ?, ?)",
		sess.IDHash, sess.Admin, sess.Kind, sess.Parent, sess.Expires.Unix(), sess.Proved.Unix())
	return err
}

// SessionByHash returns a session that exists and has not run out.
func (s *Store) SessionByHash(idHash []byte, now time.Time) (Session, bool, error) {
	sess := Session{IDHash: idHash}
	var expires, proved int64
	err := s.db.QueryRow("SELECT admin, kind, parent, expires, proved FROM sessions WHERE id_hash = ? AND expires > ?", idHash, now.Unix()).
		Scan(&sess.Admin, &sess.Kind, &sess.Parent, &expires, &proved)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, false, nil
	}
	sess.Expires, sess.Proved = time.Unix(expires, 0), time.Unix(proved, 0)
	return sess, err == nil, err
}

// DeleteSession ends a session and, through the parent link, any made from it.
func (s *Store) DeleteSession(idHash []byte) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id_hash = ?", idHash)
	return err
}

func (s *Store) MarkProved(idHash []byte, at time.Time) error {
	_, err := s.db.Exec("UPDATE sessions SET proved = ? WHERE id_hash = ?", at.Unix(), idHash)
	return err
}

func (s *Store) NewTicket(tokenHash, session, nonceHash []byte, expires time.Time) error {
	_, err := s.db.Exec("INSERT INTO tickets (token_hash, session, nonce_hash, expires) VALUES (?, ?, ?, ?)",
		tokenHash, session, nonceHash, expires.Unix())
	return err
}

// TakeTicket uses a ticket up, valid or not, and returns the admin session it
// was issued to and the nonce hash it is bound to.
func (s *Store) TakeTicket(tokenHash []byte, now time.Time) (session, nonceHash []byte, ok bool, err error) {
	err = s.write(func(tx *sql.Tx) error {
		var expires int64
		err := tx.QueryRow("SELECT session, nonce_hash, expires FROM tickets WHERE token_hash = ?", tokenHash).Scan(&session, &nonceHash, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		ok = expires > now.Unix()
		_, err = tx.Exec("DELETE FROM tickets WHERE token_hash = ?", tokenHash)
		return err
	})
	return session, nonceHash, ok && err == nil, err
}

// PruneAuth drops everything that has run out. Failures older than a day can
// no longer count toward any limit.
func (s *Store) PruneAuth(now time.Time) error {
	return s.write(func(tx *sql.Tx) error {
		for table, cutoff := range map[string]int64{
			"sessions": now.Unix(), "enrolments": now.Unix(), "tickets": now.Unix(),
		} {
			if _, err := tx.Exec("DELETE FROM "+table+" WHERE expires <= ?", cutoff); err != nil {
				return err
			}
		}
		_, err := tx.Exec("DELETE FROM code_failures WHERE at <= ?", now.Add(-24*time.Hour).Unix())
		return err
	})
}
