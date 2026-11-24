package generate

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testPassword = "correct horse battery"

// purgeFixture is an admin whose clock the test controls, with helpers to make
// mailboxes, their mail and index directories, and to remove them.
type purgeFixture struct {
	t   *testing.T
	a   *Admin
	now time.Time
}

func newPurgeFixture(t *testing.T) *purgeFixture {
	f := &purgeFixture{t: t, a: newAdmin(t, false), now: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	f.a.cfg.IndexRoot = t.TempDir()
	// Ticks on every read: a generation's id is its time plus a content hash, and
	// adding then removing a mailbox renders the same content twice.
	f.a.cfg.Now = func() time.Time {
		f.now = f.now.Add(time.Second)
		return f.now
	}
	f.must(f.a.AddDomain("t", "example.test"))
	return f
}

func (f *purgeFixture) must(_ string, err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}

func (f *purgeFixture) mkdir(p string) {
	f.t.Helper()
	if err := os.MkdirAll(filepath.Join(p, "Maildir", "cur"), 0o755); err != nil {
		f.t.Fatal(err)
	}
}

func (f *purgeFixture) mail(local string) string { return f.a.MailPath(local + "@example.test") }

func (f *purgeFixture) index(local string) string {
	return f.a.IndexPath(local + "@example.test")
}

// removed adds a mailbox, gives it mail and an index, and removes it.
func (f *purgeFixture) removed(local string) {
	f.t.Helper()
	f.must(f.a.AddMailbox("t", local+"@example.test", "", testPassword, false))
	f.mkdir(f.mail(local))
	f.mkdir(f.index(local))
	f.must(f.a.RemoveMailbox("t", local+"@example.test"))
}

func (f *purgeFixture) purge(dryRun bool) ([]string, error) {
	f.t.Helper()
	return f.a.PurgeRemoved("t", dryRun)
}

func exists(t *testing.T, p string) bool {
	t.Helper()
	_, err := os.Lstat(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return err == nil
}

func TestPurgeRemoved(t *testing.T) {
	f := newPurgeFixture(t)
	f.removed("old")
	f.removed("back")
	f.must(f.a.AddMailbox("t", "back@example.test", "", testPassword, true))
	f.removed("again")
	f.must(f.a.AddMailbox("t", "again@example.test", "", testPassword, true))
	stray := filepath.Join(f.a.cfg.MailRoot, "example.test", "stray")
	f.mkdir(stray)
	f.now = f.now.AddDate(0, 0, 20)
	f.removed("recent")
	f.must(f.a.RemoveMailbox("t", "again@example.test"))
	f.now = f.now.AddDate(0, 0, 11)

	dry, err := f.purge(true)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"would purge mail of old@example.test, removed 2026-11-01"}; !slices.Equal(dry, want) {
		t.Fatalf("dry run = %q, want %q", dry, want)
	}
	if !exists(t, f.mail("old")) {
		t.Fatal("dry run deleted mail")
	}

	done, err := f.purge(false)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"purged mail of old@example.test, removed 2026-11-01"}; !slices.Equal(done, want) {
		t.Fatalf("purge = %q, want %q", done, want)
	}
	for _, p := range []string{f.mail("old"), f.index("old")} {
		if exists(t, p) {
			t.Errorf("%s still exists", p)
		}
	}
	// recent: removed 11 days ago. back: added back. again: removed again 11 days ago.
	for _, p := range []string{f.mail("recent"), f.mail("back"), f.index("back"), f.mail("again"), stray} {
		if !exists(t, p) {
			t.Errorf("%s was deleted", p)
		}
	}
	log, err := f.a.Log()
	if err != nil {
		t.Fatal(err)
	}
	if last := log[len(log)-1]; last.Action != "mailbox.purge" || last.Subject != "old@example.test" || last.Actor != "t" {
		t.Errorf("last log entry = %+v", last)
	}

	// Mail put back by hand after a purge is not deleted again.
	f.mkdir(f.mail("old"))
	if again, err := f.purge(false); err != nil || len(again) != 0 {
		t.Errorf("second run = %q, %v; want nothing", again, err)
	}
	if !exists(t, f.mail("old")) {
		t.Error("restored mail was purged again")
	}
}

func TestPurgeRemovedIndexOnly(t *testing.T) {
	f := newPurgeFixture(t)
	f.removed("old")
	if err := os.RemoveAll(f.mail("old")); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.AddDate(0, 0, 31)
	if done, err := f.purge(false); err != nil || len(done) != 1 {
		t.Fatalf("purge = %q, %v; want one", done, err)
	}
	if exists(t, f.index("old")) {
		t.Error("index left behind")
	}
}

func TestPurgeRemovedRefusesSymlinks(t *testing.T) {
	f := newPurgeFixture(t)
	f.removed("aaa")
	f.removed("zzz")
	target := t.TempDir()
	if err := os.RemoveAll(f.mail("aaa")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, f.mail("aaa")); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.AddDate(0, 0, 31)

	done, err := f.purge(false)
	if err == nil || !strings.Contains(err.Error(), "aaa@example.test") {
		t.Fatalf("error = %v, want one naming aaa@example.test", err)
	}
	if want := []string{"purged mail of zzz@example.test, removed 2026-11-01"}; !slices.Equal(done, want) {
		t.Errorf("a bad entry blocked the rest: purged %q, want %q", done, want)
	}
	if !exists(t, target) || !exists(t, f.index("aaa")) {
		t.Error("purge followed a symlink or deleted part of a refused mailbox")
	}
}

func TestPurgeRemovedRefusesSymlinkedDomain(t *testing.T) {
	f := newPurgeFixture(t)
	f.removed("old")
	elsewhere := t.TempDir()
	f.mkdir(filepath.Join(elsewhere, "old"))
	domain := filepath.Join(f.a.cfg.MailRoot, "example.test")
	if err := os.RemoveAll(domain); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, domain); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.AddDate(0, 0, 31)
	if _, err := f.purge(false); err == nil {
		t.Fatal("purge went through a symlinked domain directory")
	}
	if !exists(t, filepath.Join(elsewhere, "old")) {
		t.Error("purge deleted through a symlinked domain directory")
	}
}

func TestPurgeRemovedRefusesMismatchedStore(t *testing.T) {
	f := newPurgeFixture(t)
	f.removed("old")
	f.now = f.now.AddDate(0, 0, 31)
	tamperCurrent(t, f.a)
	if _, err := f.purge(false); err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("error = %v, want the mismatch refusal", err)
	}
	if !exists(t, f.mail("old")) {
		t.Error("purged from a store that does not match the files in use")
	}
}

func TestConfigNeedsAbsoluteRoots(t *testing.T) {
	for _, env := range []map[string]string{
		{"MAILCTL_MAIL_ROOT": "vmail"},
		{"MAILCTL_INDEX_ROOT": "./index"},
		{"MAILCTL_DOVECOT_GID": "0"},
		{"MAILCTL_DOVECOT_GID": "dovecot"},
	} {
		if _, err := ConfigFromEnv(func(k string) string { return env[k] }); err == nil {
			t.Errorf("ConfigFromEnv accepted %v", env)
		}
	}
	cfg, err := ConfigFromEnv(func(string) string { return "" })
	if err != nil {
		t.Errorf("defaults rejected: %v", err)
	}
	if cfg.DovecotGID != defaultDovecotGID {
		t.Errorf("DovecotGID = %d, want %d", cfg.DovecotGID, defaultDovecotGID)
	}
}
