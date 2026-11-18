package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "{BLF-CRYPT}$2y$10$") {
		t.Fatalf("hash = %q", h)
	}
	if err := bcrypt.CompareHashAndPassword([]byte("$2a$"+strings.TrimPrefix(h, "{BLF-CRYPT}$2y$")), []byte("correct horse battery")); err != nil {
		t.Errorf("hash does not verify: %v", err)
	}
}

func TestReopenAndVerbatimHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	const imported = "{BLF-CRYPT}$2y$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
	s, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.AddDomain("example.test"); err != nil {
		t.Fatal(err)
	}
	if err := tx.AddMailbox(Mailbox{Address: "a@example.test", Hash: imported, State: Active}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s.Close()
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Mailboxes) != 1 || snap.Mailboxes[0].Hash != imported {
		t.Errorf("snapshot = %+v", snap)
	}
}

func TestRollbackDiscards(t *testing.T) {
	s, err := Create(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	tx, _ := s.Begin()
	if err := tx.AddDomain("example.test"); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	if snap, _ := s.Snapshot(); len(snap.Domains) != 0 {
		t.Errorf("rolled-back domain visible: %+v", snap)
	}
}

func TestOpenNeverCreatesAndCreateNeverReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	if _, err := Open(path); err == nil {
		t.Fatal("Open succeeded on a missing file")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("Open created the file")
	}
	s, err := Create(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("created file: %v %v", st, err)
	}
	if _, err := Create(path); err == nil {
		t.Error("Create succeeded on an existing file")
	}
}
