// Package store keeps accounts and the change log in one SQLite file.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

type State string

const (
	Active      State = "active"
	ReceiveOnly State = "receive-only"
	Disabled    State = "disabled"
)

const hashPrefix = "{BLF-CRYPT}"

func ParseState(s string) (State, error) {
	switch st := State(s); st {
	case Active, ReceiveOnly, Disabled:
		return st, nil
	}
	return "", fmt.Errorf("unknown state %q; use active, receive-only or disabled", s)
}

type Mailbox struct {
	Address string
	Hash    string
	State   State
	Name    string
}

type Alias struct {
	Address string
	Targets []string
}

type Grant struct {
	Mailbox string
	Address string
}

type LogEntry struct {
	Time    time.Time
	Actor   string
	Action  string
	Subject string
}

// Snapshot is the whole account set, every slice sorted by address.
type Snapshot struct {
	Domains   []string
	Mailboxes []Mailbox
	Aliases   []Alias
	Grants    []Grant
}

// HashPassword returns a bcrypt hash in dovecot's {BLF-CRYPT} form with the $2y$ prefix.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return hashPrefix + "$2y" + strings.TrimPrefix(string(h), "$2a"), nil
}

const schema = `
CREATE TABLE domains (name TEXT PRIMARY KEY);
CREATE TABLE mailboxes (
	address TEXT PRIMARY KEY,
	hash    TEXT NOT NULL,
	state   TEXT NOT NULL CHECK (state IN ('active','receive-only','disabled')),
	name    TEXT NOT NULL DEFAULT ''
);
CREATE TABLE aliases (address TEXT PRIMARY KEY);
CREATE TABLE alias_targets (
	alias    TEXT NOT NULL REFERENCES aliases(address) ON DELETE CASCADE,
	position INTEGER NOT NULL,
	target   TEXT NOT NULL,
	PRIMARY KEY (alias, position)
);
CREATE TABLE sendas (
	mailbox TEXT NOT NULL REFERENCES mailboxes(address) ON DELETE CASCADE,
	address TEXT NOT NULL,
	PRIMARY KEY (mailbox, address)
);
CREATE TABLE log (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	time    TEXT NOT NULL,
	actor   TEXT NOT NULL,
	action  TEXT NOT NULL,
	subject TEXT NOT NULL
);`

var migrations = []string{schema}

type Store struct{ db *sql.DB }

// Open opens or creates the database at path and migrates its schema.
func Open(path string) (*Store, error) {
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0o600); err == nil {
		f.Close()
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	db, err := sql.Open("sqlite", "file:"+url.PathEscape(path)+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate %s: %w", path, err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	for ; v < len(migrations); v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[v]); err != nil {
			tx.Rollback()
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

type querier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// Snapshot reads the current account set.
func (s *Store) Snapshot() (Snapshot, error) { return snapshot(s.db) }

// Log returns the change log, oldest first.
func (s *Store) Log() ([]LogEntry, error) {
	rows, err := s.db.Query("SELECT time, actor, action, subject FROM log ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LogEntry
	for rows.Next() {
		var e LogEntry
		var ts string
		if err := rows.Scan(&ts, &e.Actor, &e.Action, &e.Subject); err != nil {
			return nil, err
		}
		if e.Time, err = time.Parse(time.RFC3339, ts); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func snapshot(q querier) (Snapshot, error) {
	var snap Snapshot
	if err := scan(q, "SELECT name FROM domains ORDER BY name", func(r *sql.Rows) error {
		var d string
		if err := r.Scan(&d); err != nil {
			return err
		}
		snap.Domains = append(snap.Domains, d)
		return nil
	}); err != nil {
		return snap, err
	}
	if err := scan(q, "SELECT address, hash, state, name FROM mailboxes ORDER BY address", func(r *sql.Rows) error {
		var m Mailbox
		if err := r.Scan(&m.Address, &m.Hash, &m.State, &m.Name); err != nil {
			return err
		}
		snap.Mailboxes = append(snap.Mailboxes, m)
		return nil
	}); err != nil {
		return snap, err
	}
	byAlias := map[string]*Alias{}
	if err := scan(q, "SELECT address FROM aliases ORDER BY address", func(r *sql.Rows) error {
		var a Alias
		if err := r.Scan(&a.Address); err != nil {
			return err
		}
		snap.Aliases = append(snap.Aliases, a)
		return nil
	}); err != nil {
		return snap, err
	}
	for i := range snap.Aliases {
		byAlias[snap.Aliases[i].Address] = &snap.Aliases[i]
	}
	if err := scan(q, "SELECT alias, target FROM alias_targets ORDER BY alias, position", func(r *sql.Rows) error {
		var alias, target string
		if err := r.Scan(&alias, &target); err != nil {
			return err
		}
		byAlias[alias].Targets = append(byAlias[alias].Targets, target)
		return nil
	}); err != nil {
		return snap, err
	}
	err := scan(q, "SELECT mailbox, address FROM sendas ORDER BY mailbox, address", func(r *sql.Rows) error {
		var g Grant
		if err := r.Scan(&g.Mailbox, &g.Address); err != nil {
			return err
		}
		snap.Grants = append(snap.Grants, g)
		return nil
	})
	return snap, err
}

func scan(q querier, query string, each func(*sql.Rows) error) error {
	rows, err := q.Query(query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := each(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Tx is a write transaction. Nothing it does is visible until Commit.
type Tx struct{ tx *sql.Tx }

func (s *Store) Begin() (*Tx, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	return &Tx{tx}, nil
}

func (t *Tx) Commit() error { return t.tx.Commit() }

// Rollback is a no-op after Commit.
func (t *Tx) Rollback() {
	if err := t.tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		fmt.Fprintln(os.Stderr, "warning: rollback:", err)
	}
}

func (t *Tx) Snapshot() (Snapshot, error) { return snapshot(t.tx) }

func (t *Tx) AddDomain(name string) error {
	_, err := t.tx.Exec("INSERT INTO domains (name) VALUES (?)", name)
	return err
}

func (t *Tx) RemoveDomain(name string) error {
	_, err := t.tx.Exec("DELETE FROM domains WHERE name = ?", name)
	return err
}

// AddMailbox stores m.Hash verbatim.
func (t *Tx) AddMailbox(m Mailbox) error {
	_, err := t.tx.Exec("INSERT INTO mailboxes (address, hash, state, name) VALUES (?, ?, ?, ?)",
		m.Address, m.Hash, m.State, m.Name)
	return err
}

func (t *Tx) SetHash(address, hash string) error {
	_, err := t.tx.Exec("UPDATE mailboxes SET hash = ? WHERE address = ?", hash, address)
	return err
}

func (t *Tx) SetState(address string, state State) error {
	_, err := t.tx.Exec("UPDATE mailboxes SET state = ? WHERE address = ?", state, address)
	return err
}

// RemoveMailbox also removes the mailbox's send-as grants.
func (t *Tx) RemoveMailbox(address string) error {
	_, err := t.tx.Exec("DELETE FROM mailboxes WHERE address = ?", address)
	return err
}

func (t *Tx) AddAlias(a Alias) error {
	if _, err := t.tx.Exec("INSERT INTO aliases (address) VALUES (?)", a.Address); err != nil {
		return err
	}
	for i, target := range a.Targets {
		if _, err := t.tx.Exec("INSERT INTO alias_targets (alias, position, target) VALUES (?, ?, ?)",
			a.Address, i, target); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tx) RemoveAlias(address string) error {
	_, err := t.tx.Exec("DELETE FROM aliases WHERE address = ?", address)
	return err
}

func (t *Tx) AddGrant(g Grant) error {
	_, err := t.tx.Exec("INSERT INTO sendas (mailbox, address) VALUES (?, ?)", g.Mailbox, g.Address)
	return err
}

func (t *Tx) RemoveGrant(g Grant) error {
	_, err := t.tx.Exec("DELETE FROM sendas WHERE mailbox = ? AND address = ?", g.Mailbox, g.Address)
	return err
}

// Log records a change. Subject must never carry a password or hash.
func (t *Tx) Log(at time.Time, actor, action, subject string) error {
	_, err := t.tx.Exec("INSERT INTO log (time, actor, action, subject) VALUES (?, ?, ?, ?)",
		at.UTC().Format(time.RFC3339), actor, action, subject)
	return err
}
