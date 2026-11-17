package generate

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kspears/mailstack/internal/store"
)

func fixture() store.Snapshot {
	return store.Snapshot{
		Domains: []string{"example.org", "example.test"},
		Mailboxes: []store.Mailbox{
			{Address: "alice@example.test", Hash: "{BLF-CRYPT}$2y$10$aaa", State: store.Active},
			{Address: "bob@example.test", Hash: "{BLF-CRYPT}$2y$10$bbb", State: store.ReceiveOnly},
			{Address: "carol@example.test", Hash: "{BLF-CRYPT}$2y$10$ccc", State: store.Disabled},
			{Address: "dave@example.org", Hash: "{BLF-CRYPT}$2y$10$ddd", State: store.Active},
		},
		Aliases: []store.Alias{
			{Address: "info@example.test", Targets: []string{"alice@example.test"}},
			{Address: "team@example.test", Targets: []string{"info@example.test", "bob@example.test", "away@example.net"}},
		},
		Grants: []store.Grant{{Mailbox: "dave@example.org", Address: "sales@example.test"}},
	}
}

func TestRender(t *testing.T) {
	cfg := Config{MailRoot: "/var/vmail", UID: 5000, GID: 5001}
	got := Render(fixture(), cfg)
	want := Files{
		FileUsers: "alice@example.test:{BLF-CRYPT}$2y$10$aaa:5000:5001::/var/vmail/example.test/alice::\n" +
			"bob@example.test:{BLF-CRYPT}$2y$10$bbb:5000:5001::/var/vmail/example.test/bob::nologin=y\n" +
			"dave@example.org:{BLF-CRYPT}$2y$10$ddd:5000:5001::/var/vmail/example.org/dave::\n",
		FileDomains:   "example.org OK\nexample.test OK\n",
		FileMailboxes: "alice@example.test OK\nbob@example.test OK\ndave@example.org OK\n",
		FileAliases: "info@example.test alice@example.test\n" +
			"team@example.test info@example.test,bob@example.test,away@example.net\n",
		FileSenderLogin: "alice@example.test alice@example.test\n" +
			"dave@example.org dave@example.org\n" +
			"info@example.test alice@example.test\n" +
			"sales@example.test dave@example.org\n" +
			"team@example.test alice@example.test\n",
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s:\n got %q\nwant %q", name, got[name], w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("rendered %d files, want %d", len(got), len(want))
	}
}

func TestRenderEmpty(t *testing.T) {
	for name, content := range Render(store.Snapshot{}, Config{}) {
		if content != "" {
			t.Errorf("%s = %q, want empty", name, content)
		}
	}
}

func TestSelfCheck(t *testing.T) {
	good := Render(fixture(), Config{MailRoot: "/var/vmail", UID: 5000, GID: 5000})
	tests := []struct {
		name    string
		mutate  func(Files)
		wantErr string
	}{
		{"valid", func(Files) {}, ""},
		{"unresolved alias target", func(f Files) { f[FileAliases] += "x@example.test ghost@example.test\n" }, "does not resolve"},
		{"mailbox and alias", func(f Files) { f[FileAliases] += "alice@example.test away@example.net\n" }, "both a mailbox and an alias"},
		{"no trailing newline", func(f Files) { f[FileDomains] = "example.test OK" }, "newline-terminated"},
		{"malformed users line", func(f Files) { f[FileUsers] = "alice@example.test:x\n" }, "malformed"},
		{"user without mailbox", func(f Files) { f[FileMailboxes] = "alice@example.test OK\ndave@example.org OK\n" }, "does not"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := Files{}
			for k, v := range good {
				f[k] = v
			}
			tc.mutate(f)
			dir := t.TempDir()
			if err := writeGeneration(dir, f); err != nil {
				t.Fatal(err)
			}
			err := SelfCheck(dir)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestIDSortsByTime(t *testing.T) {
	f := Render(fixture(), Config{})
	a := f.ID(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	b := f.ID(time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC))
	if a >= b {
		t.Errorf("IDs do not sort by time: %s >= %s", a, b)
	}
}

func newAdmin(t *testing.T, watcher bool) *Admin {
	t.Helper()
	cfg := Config{
		State: t.TempDir(), MailRoot: t.TempDir(), UID: 5000, GID: 5000,
		WatcherOff: !watcher, Timeout: 3 * time.Second, Poll: 5 * time.Millisecond,
	}
	a, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

type watcher struct {
	mu      sync.Mutex
	verdict string // "ok", "error <msg>", or "" to stay silent
	stop    chan struct{}
}

func (w *watcher) set(v string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.verdict = v
}

func startWatcher(t *testing.T, a *Admin) *watcher {
	t.Helper()
	w := &watcher{verdict: "ok", stop: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		last := ""
		for {
			select {
			case <-w.stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
			id, err := os.Readlink(filepath.Join(a.gens, "pending"))
			if err != nil || id == last {
				continue
			}
			w.mu.Lock()
			v := w.verdict
			w.mu.Unlock()
			if v == "" {
				continue
			}
			last = id
			os.WriteFile(filepath.Join(a.gens, "status"), []byte(id+" "+v+"\n"), 0o644)
		}
	}()
	t.Cleanup(func() { close(w.stop); <-done })
	return w
}

type state struct {
	current string
	users   string
	snap    store.Snapshot
	log     int
	dirs    []string
}

func capture(t *testing.T, a *Admin) state {
	t.Helper()
	id, err := os.Readlink(filepath.Join(a.gens, "current"))
	if err != nil {
		t.Fatal(err)
	}
	users, err := os.ReadFile(filepath.Join(a.gens, "current", FileUsers))
	if err != nil {
		t.Fatal(err)
	}
	snap, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	log, err := a.Log()
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(a.gens)
	var dirs []string
	for _, e := range entries {
		if e.Name() != "status" {
			dirs = append(dirs, e.Name())
		}
	}
	return state{id, string(users), snap, len(log), dirs}
}

func TestFailedApplyChangesNothing(t *testing.T) {
	cases := []struct {
		name, verdict, wantErr string
	}{
		{"watcher reports error", "error main.cf: bad map", "postfix rejected generation"},
		{"watcher times out", "", "timed out"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAdmin(t, true)
			a.cfg.Timeout = 300 * time.Millisecond
			w := startWatcher(t, a)
			if _, err := a.AddDomain("test", "example.test"); err != nil {
				t.Fatal(err)
			}
			if _, err := a.AddMailbox("test", "alice@example.test", "", "correct horse battery", false); err != nil {
				t.Fatal(err)
			}
			before := capture(t, a)

			w.set(tc.verdict)
			_, err := a.AddMailbox("test", "bob@example.test", "", "correct horse battery", false)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
			if tc.verdict != "" && !strings.Contains(err.Error(), "bad map") {
				t.Errorf("error %q does not carry the watcher message", err)
			}
			after := capture(t, a)
			if after.current != before.current || after.users != before.users {
				t.Errorf("current moved: %+v -> %+v", before.current, after.current)
			}
			if len(after.snap.Mailboxes) != 1 || after.log != before.log {
				t.Errorf("store changed: %d mailboxes, %d log entries", len(after.snap.Mailboxes), after.log)
			}
			if strings.Join(after.dirs, ",") != strings.Join(before.dirs, ",") {
				t.Errorf("generation dirs changed: %v -> %v", before.dirs, after.dirs)
			}
			if _, err := os.Lstat(filepath.Join(a.gens, "pending")); !os.IsNotExist(err) {
				t.Errorf("pending still exists: %v", err)
			}

			w.set("ok")
			if _, err := a.AddMailbox("test", "bob@example.test", "", "correct horse battery", false); err != nil {
				t.Fatalf("retry after recovery: %v", err)
			}
		})
	}
}

func TestChangeLogHasNoSecrets(t *testing.T) {
	a := newAdmin(t, false)
	const pw = "tr0ub4dor&3-horse"
	steps := []func() (string, error){
		func() (string, error) { return a.AddDomain("cli:alex", "example.test") },
		func() (string, error) { return a.AddMailbox("cli:alex", "alice@example.test", "Alice", pw, false) },
		func() (string, error) { return a.SetPassword("cli:alex", "alice@example.test", pw+"2") },
		func() (string, error) {
			return a.AddAlias("cli:alex", "info@example.test", []string{"alice@example.test"})
		},
	}
	for _, s := range steps {
		if _, err := s(); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := a.Log()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(steps) {
		t.Fatalf("log has %d entries, want %d", len(entries), len(steps))
	}
	for _, e := range entries {
		line := e.Actor + e.Action + e.Subject
		for _, bad := range []string{pw, "$2y$", "$2a$", "BLF-CRYPT"} {
			if strings.Contains(line, bad) {
				t.Errorf("log entry %+v contains %q", e, bad)
			}
		}
	}
}

func TestOperations(t *testing.T) {
	a := newAdmin(t, false)
	const pw = "correct horse battery"
	if err := os.MkdirAll(filepath.Join(a.cfg.MailRoot, "example.test", "old"), 0o755); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name    string
		do      func() (string, error)
		want    string // expected ok text
		wantErr string
	}{
		{"mailbox before domain", func() (string, error) { return a.AddMailbox("t", "alice@example.test", "", pw, false) }, "", "not a hosted domain"},
		{"bad domain", func() (string, error) { return a.AddDomain("t", "localhost") }, "", "invalid domain"},
		{"add domain", func() (string, error) { return a.AddDomain("t", "Example.Test") }, "added example.test; it cannot send or receive until DNS and SES are set up", ""},
		{"duplicate domain", func() (string, error) { return a.AddDomain("t", "example.test") }, "", "already exists"},
		{"short password", func() (string, error) { return a.AddMailbox("t", "alice@example.test", "", "short", false) }, "", "at least 12"},
		{"add mailbox", func() (string, error) { return a.AddMailbox("t", "Alice@example.test", "Alice", pw, false) }, "added mailbox alice@example.test", ""},
		{"duplicate mailbox", func() (string, error) { return a.AddMailbox("t", "alice@example.test", "", pw, false) }, "", "already exists"},
		{"existing mail refused", func() (string, error) { return a.AddMailbox("t", "old@example.test", "", pw, false) }, "", "mail for old@example.test still exists at " + filepath.Join(a.cfg.MailRoot, "example.test", "old")},
		{"existing mail adopted", func() (string, error) { return a.AddMailbox("t", "old@example.test", "", pw, true) }, "added mailbox old@example.test", ""},
		{"alias collides with mailbox", func() (string, error) { return a.AddAlias("t", "alice@example.test", []string{"old@example.test"}) }, "", "already a mailbox"},
		{"alias to unknown local target", func() (string, error) { return a.AddAlias("t", "info@example.test", []string{"ghost@example.test"}) }, "", "not a mailbox or alias"},
		{"catch-all alias", func() (string, error) { return a.AddAlias("t", "@example.test", []string{"alice@example.test"}) }, "", "catch-all"},
		{"add alias", func() (string, error) {
			return a.AddAlias("t", "info@example.test", []string{"alice@example.test", "me@example.org"})
		}, "added alias info@example.test -> alice@example.test,me@example.org", ""},
		{"duplicate alias", func() (string, error) { return a.AddAlias("t", "info@example.test", []string{"old@example.test"}) }, "", "already exists"},
		{"mailbox collides with alias", func() (string, error) { return a.AddMailbox("t", "info@example.test", "", pw, false) }, "", "already an alias"},
		{"alias chain", func() (string, error) { return a.AddAlias("t", "a@example.test", []string{"info@example.test"}) }, "added alias a@example.test -> info@example.test", ""},
		{"alias self loop", func() (string, error) { return a.AddAlias("t", "loop@example.test", []string{"loop@example.test"}) }, "", "alias loop"},
		{"duplicate target", func() (string, error) {
			return a.AddAlias("t", "dup@example.test", []string{"alice@example.test", "alice@example.test"})
		}, "", "twice"},
		{"remove targeted mailbox", func() (string, error) { return a.RemoveMailbox("t", "alice@example.test") }, "", "alias info@example.test still delivers to it"},
		{"remove targeted alias", func() (string, error) { return a.RemoveAlias("t", "info@example.test") }, "", "alias a@example.test still delivers to it"},
		{"disable targeted mailbox", func() (string, error) { return a.SetMailboxState("t", "alice@example.test", store.Disabled) }, "", "disabled"},
		{"receive-only", func() (string, error) { return a.SetMailboxState("t", "alice@example.test", store.ReceiveOnly) }, "set alice@example.test to receive-only", ""},
		{"send-as grant", func() (string, error) { return a.AddSendAs("t", "old@example.test", "sales@example.test") }, "old@example.test may now send as sales@example.test", ""},
		{"duplicate grant", func() (string, error) { return a.AddSendAs("t", "old@example.test", "sales@example.test") }, "", "already send as"},
		{"grant to unknown mailbox", func() (string, error) { return a.AddSendAs("t", "ghost@example.test", "sales@example.test") }, "", "no mailbox"},
		{"remove domain in use", func() (string, error) { return a.RemoveDomain("t", "example.test") }, "", "still has 2 mailboxes, 2 aliases and 1 send-as grants"},
		{"remove mailbox with grant", func() (string, error) { return a.RemoveMailbox("t", "old@example.test") }, "removed old@example.test; mail left in place at " + filepath.Join(a.cfg.MailRoot, "example.test", "old"), ""},
		{"remove alias", func() (string, error) { return a.RemoveAlias("t", "a@example.test") }, "removed alias a@example.test", ""},
	}
	for _, s := range steps {
		got, err := s.do()
		if s.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), s.wantErr) {
				t.Errorf("%s: error = %v, want containing %q", s.name, err, s.wantErr)
			}
			continue
		}
		if err != nil || got != s.want {
			t.Errorf("%s: got %q, %v; want %q", s.name, got, err, s.want)
		}
	}
	snap, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Grants) != 0 || len(snap.Mailboxes) != 1 || len(snap.Aliases) != 1 {
		t.Errorf("unexpected final state: %+v", snap)
	}
	users, _ := os.ReadFile(filepath.Join(a.gens, "current", FileUsers))
	if !strings.Contains(string(users), "alice@example.test:{BLF-CRYPT}$2y$10$") || !strings.HasSuffix(string(users), "::nologin=y\n") {
		t.Errorf("users file = %q", users)
	}
}

func TestResyncAndPrune(t *testing.T) {
	a := newAdmin(t, false)
	if _, err := a.AddDomain("t", "example.test"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := a.Apply("t"); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(a.gens)
	var dirs int
	for _, e := range entries {
		if e.IsDir() {
			dirs++
		}
	}
	if dirs != keepGenerations {
		t.Errorf("%d generations kept, want %d", dirs, keepGenerations)
	}

	if err := os.WriteFile(filepath.Join(a.gens, "current", FileDomains), []byte("tampered.test OK\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Readlink(filepath.Join(a.gens, "current"))
	if _, err := a.AddDomain("t", "example.org"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Readlink(filepath.Join(a.gens, "current"))
	got, _ := os.ReadFile(filepath.Join(a.gens, "current", FileDomains))
	if before == after || string(got) != "example.org OK\nexample.test OK\n" {
		t.Errorf("current not resynced: %s -> %s, domains %q", before, after, got)
	}
}
