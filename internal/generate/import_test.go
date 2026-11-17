package generate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kspears/mailstack/internal/store"
)

func TestImport(t *testing.T) {
	state := t.TempDir()
	a, err := Open(Config{State: state, MailRoot: "/var/vmail", WatcherOff: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	snap := fixture()
	snap.Mailboxes[0].Hash = "{BLF-CRYPT}$2y$10$verbatimhashvalue"
	replaced, err := a.Import("cli:alex", snap, false)
	if err != nil {
		t.Fatal(err)
	}
	if replaced != "" {
		t.Errorf("replaced = %q on an empty store", replaced)
	}
	got, err := a.Snapshot()
	if err != nil || !reflect.DeepEqual(got, snap) {
		t.Errorf("stored snapshot differs: %v\n got %+v\nwant %+v", err, got, snap)
	}
	users, err := os.ReadFile(filepath.Join(state, "generations", "current", "dovecot", "users"))
	if err != nil || !strings.Contains(string(users), "alice@example.test:{BLF-CRYPT}$2y$10$verbatimhashvalue::::::\n") {
		t.Errorf("generated users file: %v\n%s", err, users)
	}

	log, err := a.Log()
	if err != nil {
		t.Fatal(err)
	}
	var imports []store.LogEntry
	for _, e := range log {
		if e.Action == "import" {
			imports = append(imports, e)
		}
	}
	if len(imports) != 1 || imports[0].Actor != "cli:alex" || imports[0].Subject != "2 domains, 4 mailboxes, 2 aliases, 1 send-as grants" {
		t.Errorf("import log entries: %+v", imports)
	}
	for _, e := range log {
		if strings.Contains(e.Subject, "BLF-CRYPT") || strings.Contains(e.Subject, "$2y$") {
			t.Errorf("log entry carries a hash: %+v", e)
		}
	}

	if _, err := a.Import("cli:alex", snap, false); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Errorf("second import: %v", err)
	}
}

func TestImportInvalidChangesNothing(t *testing.T) {
	a, err := Open(Config{State: t.TempDir(), MailRoot: "/var/vmail", WatcherOff: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	snap := store.Snapshot{
		Domains:   []string{"example.test"},
		Mailboxes: []store.Mailbox{{Address: "Bad Name@example.test", Hash: "{BLF-CRYPT}$2y$10$x", State: store.Active}},
	}
	if _, err := a.Import("cli:alex", snap, false); err == nil || !strings.Contains(err.Error(), `"Bad Name@example.test"`) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := a.Snapshot(); len(got.Domains)+len(got.Mailboxes) != 0 {
		t.Errorf("store changed: %+v", got)
	}
	if log, _ := a.Log(); len(log) != 0 {
		t.Errorf("log changed: %+v", log)
	}
}

func populated(t *testing.T) *Admin {
	t.Helper()
	a := newAdmin(t, false)
	for _, step := range []func() (string, error){
		func() (string, error) { return a.AddDomain("t", "old.example.test") },
		func() (string, error) {
			return a.AddMailbox("t", "keep@old.example.test", "", "correct horse battery", false)
		},
	} {
		if _, err := step(); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func TestImportOverwriteFailureKeepsOldAccounts(t *testing.T) {
	a := populated(t)
	before := capture(t, a)
	bad := store.Snapshot{
		Domains:   []string{"example.test"},
		Mailboxes: []store.Mailbox{{Address: "Bad Name@example.test", Hash: "{BLF-CRYPT}$2y$10$x", State: store.Active}},
	}
	if _, err := a.Import("cli:alex", bad, true); err == nil {
		t.Fatal("import of an invalid snapshot succeeded")
	}
	after := capture(t, a)
	if after.current != before.current || after.users != before.users || after.log != before.log ||
		!reflect.DeepEqual(after.snap, before.snap) || strings.Join(after.dirs, ",") != strings.Join(before.dirs, ",") {
		t.Errorf("failed overwrite changed state:\n%+v\n%+v", before, after)
	}
	if left, _ := filepath.Glob(StorePath(a.cfg) + ".replaced-*"); len(left) != 0 {
		t.Errorf("copy left behind after a failed import: %v", left)
	}

	// Also fails after the rows are cleared and loaded: a generation the watcher rejects.
	w := startWatcher(t, a)
	a.cfg.WatcherOff = false
	a.cfg.Timeout = 300 * time.Millisecond
	w.set("error main.cf: bad map")
	if _, err := a.Import("cli:alex", fixture(), true); err == nil || !strings.Contains(err.Error(), "postfix rejected") {
		t.Fatalf("err = %v", err)
	}
	after = capture(t, a)
	if after.current != before.current || !reflect.DeepEqual(after.snap, before.snap) || after.log != before.log {
		t.Errorf("rejected overwrite changed state: %+v", after)
	}
	if left, _ := filepath.Glob(StorePath(a.cfg) + ".replaced-*"); len(left) != 0 {
		t.Errorf("copy left behind after a rejected import: %v", left)
	}
}

func TestImportOverwriteKeepsReadableCopy(t *testing.T) {
	a := populated(t)
	old, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Import("cli:alex", fixture(), false); err == nil {
		t.Fatal("import over existing accounts needs overwrite")
	}
	replaced, err := a.Import("cli:alex", fixture(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(replaced, StorePath(a.cfg)+".replaced-") {
		t.Fatalf("replaced = %q", replaced)
	}
	if st, err := os.Stat(replaced); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("copy: %v %v", st, err)
	}
	copied, err := store.Open(replaced)
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	got, err := copied.Snapshot()
	if err != nil || !reflect.DeepEqual(got, old) {
		t.Errorf("copy holds %+v (%v), want %+v", got, err, old)
	}
	now, _ := a.Snapshot()
	if !reflect.DeepEqual(now, fixture()) {
		t.Errorf("store after overwrite: %+v", now)
	}
	domains, _ := os.ReadFile(filepath.Join(a.gens, "current", FileDomains))
	if string(domains) != "example.org OK\nexample.test OK\n" {
		t.Errorf("current domains: %q", domains)
	}
	log, _ := a.Log()
	if len(log) < 3 || log[len(log)-1].Action != "import" {
		t.Errorf("change log was not kept and extended: %+v", log)
	}
}

func TestImportDoesNotRequireCurrentToMatch(t *testing.T) {
	a := populated(t)
	tamperCurrent(t, a)
	if _, err := a.Import("cli:alex", fixture(), true); err != nil {
		t.Fatalf("import over a stale current: %v", err)
	}
}
