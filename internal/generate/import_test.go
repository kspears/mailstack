package generate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/kspears/mailstack/internal/store"
)

func TestImport(t *testing.T) {
	state := t.TempDir()
	a, err := Open(Config{State: state, MailRoot: "/var/vmail", UID: 5000, GID: 5000, WatcherOff: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	snap := fixture()
	snap.Mailboxes[0].Hash = "{BLF-CRYPT}$2y$10$verbatimhashvalue"
	summary, err := a.Import("cli:kevin", snap)
	if err != nil {
		t.Fatal(err)
	}
	if summary != "imported 2 domains, 4 mailboxes, 2 aliases" {
		t.Errorf("summary = %q", summary)
	}
	got, err := a.Snapshot()
	if err != nil || !reflect.DeepEqual(got, snap) {
		t.Errorf("stored snapshot differs: %v\n got %+v\nwant %+v", err, got, snap)
	}
	users, err := os.ReadFile(filepath.Join(state, "generations", "current", "dovecot", "users"))
	if err != nil || !strings.Contains(string(users), "alice@example.test:{BLF-CRYPT}$2y$10$verbatimhashvalue:") {
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
	if len(imports) != 1 || imports[0].Actor != "cli:kevin" || imports[0].Subject != "2 domains, 4 mailboxes, 2 aliases, 1 send-as grants" {
		t.Errorf("import log entries: %+v", imports)
	}
	for _, e := range log {
		if strings.Contains(e.Subject, "BLF-CRYPT") || strings.Contains(e.Subject, "$2y$") {
			t.Errorf("log entry carries a hash: %+v", e)
		}
	}

	if _, err := a.Import("cli:kevin", snap); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Errorf("second import: %v", err)
	}
}

func TestImportInvalidChangesNothing(t *testing.T) {
	a, err := Open(Config{State: t.TempDir(), MailRoot: "/var/vmail", UID: 5000, GID: 5000, WatcherOff: true})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	snap := store.Snapshot{
		Domains:   []string{"example.test"},
		Mailboxes: []store.Mailbox{{Address: "Bad Name@example.test", Hash: "{BLF-CRYPT}$2y$10$x", State: store.Active}},
	}
	if _, err := a.Import("cli:kevin", snap); err == nil || !strings.Contains(err.Error(), `"Bad Name@example.test"`) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := a.Snapshot(); len(got.Domains)+len(got.Mailboxes) != 0 {
		t.Errorf("store changed: %+v", got)
	}
	if log, _ := a.Log(); len(log) != 0 {
		t.Errorf("log changed: %+v", log)
	}
}
