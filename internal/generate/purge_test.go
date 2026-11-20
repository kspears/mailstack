package generate

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

const testPassword = "correct horse battery"

func TestPurgeRemoved(t *testing.T) {
	a := newAdmin(t, false)
	a.cfg.IndexRoot = t.TempDir()
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	a.cfg.Now = func() time.Time { return now }

	must := func(_ string, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(a.AddDomain("t", "example.test"))
	for _, addr := range []string{"old", "recent", "back", "gone"} {
		must(a.AddMailbox("t", addr+"@example.test", "", testPassword, false))
	}
	mkdir := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(p, "Maildir", "cur"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, addr := range []string{"old", "recent", "back"} {
		mkdir(a.MailPath(addr + "@example.test"))
		mkdir(filepath.Join(a.cfg.IndexRoot, addr+"@example.test"))
	}
	stray := filepath.Join(a.cfg.MailRoot, "example.test", "stray")
	mkdir(stray)

	for _, addr := range []string{"old", "back", "gone"} {
		must(a.RemoveMailbox("t", addr+"@example.test"))
	}
	must(a.AddMailbox("t", "back@example.test", "", testPassword, true))
	now = now.AddDate(0, 0, 20)
	must(a.RemoveMailbox("t", "recent@example.test"))
	now = now.AddDate(0, 0, 11)

	dry, err := a.PurgeRemoved("t", true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"would purge mail of old@example.test, removed 2026-11-01"}; !slices.Equal(dry, want) {
		t.Fatalf("dry run = %q, want %q", dry, want)
	}
	if _, err := os.Stat(a.MailPath("old@example.test")); err != nil {
		t.Fatalf("dry run deleted mail: %v", err)
	}

	done, err := a.PurgeRemoved("t", false)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"purged mail of old@example.test, removed 2026-11-01"}; !slices.Equal(done, want) {
		t.Fatalf("purge = %q, want %q", done, want)
	}
	for _, p := range []string{a.MailPath("old@example.test"), filepath.Join(a.cfg.IndexRoot, "old@example.test")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s still exists: %v", p, err)
		}
	}
	for _, p := range []string{a.MailPath("recent@example.test"), a.MailPath("back@example.test"), filepath.Join(a.cfg.IndexRoot, "back@example.test"), stray} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s was deleted: %v", p, err)
		}
	}
	log, err := a.Log()
	if err != nil {
		t.Fatal(err)
	}
	if last := log[len(log)-1]; last.Action != "mailbox.purge" || last.Subject != "old@example.test" {
		t.Errorf("last log entry = %+v", last)
	}

	if again, err := a.PurgeRemoved("t", false); err != nil || len(again) != 0 {
		t.Errorf("second run = %q, %v; want nothing", again, err)
	}
}

func TestPurgeRemovedRefusesSymlink(t *testing.T) {
	a := newAdmin(t, false)
	a.cfg.IndexRoot = t.TempDir()
	if _, err := a.AddDomain("t", "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddMailbox("t", "old@example.test", "", testPassword, false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RemoveMailbox("t", "old@example.test"); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(a.cfg.MailRoot, "example.test"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, a.MailPath("old@example.test")); err != nil {
		t.Fatal(err)
	}
	a.cfg.Now = func() time.Time { return time.Now().AddDate(0, 0, 31) }
	if _, err := a.PurgeRemoved("t", false); err == nil {
		t.Fatal("purge followed a symlink")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("symlink target removed: %v", err)
	}
}
