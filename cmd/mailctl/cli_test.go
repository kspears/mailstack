package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const pw = "correct horse battery\n"

func TestCLI(t *testing.T) {
	state, mail := t.TempDir(), t.TempDir()
	vars := map[string]string{
		"MAILCTL_STATE": state, "MAILCTL_MAIL_ROOT": mail, "MAILCTL_WATCHER": "off", "MAILCTL_DOVECOT_GID": strconv.Itoa(os.Getgid()),
		"SUDO_USER": "alex", "USER": "root", "MAILCTL_ADMIN_HOST": "admin.example.test",
	}
	getenv := func(k string) string { return vars[k] }
	mailPath := filepath.Join(mail, "example.test", "alice")

	steps := []struct {
		name       string
		args       []string
		stdin      string
		code       int
		stdout     string
		stderr     string
		stdoutPart bool
	}{
		{"add domain", []string{"domain", "add", "example.test"}, "", 0, "ok: added example.test; it cannot send or receive until DNS and SES are set up\n", "", false},
		{"add mailbox", []string{"mailbox", "add", "Alice@example.test", "--name", "Alice A"}, pw + pw, 0, "ok: added mailbox alice@example.test\n", "", false},
		{"flags after address", []string{"mailbox", "add", "bob@example.test", "--name=Bob"}, pw + pw, 0, "ok: added mailbox bob@example.test\n", "", false},
		{"password mismatch", []string{"mailbox", "add", "eve@example.test"}, pw + "something else entirely\n", 1, "", "error: passwords do not match\n", false},
		{"short password", []string{"mailbox", "add", "eve@example.test"}, "short\nshort\n", 1, "", "error: password must be at least 12 characters\n", false},
		{"no password on stdin", []string{"mailbox", "add", "eve@example.test"}, "", 1, "", "error: expected the password twice on stdin, one per line\n", false},
		{"unhosted domain", []string{"mailbox", "add", "eve@example.org"}, pw + pw, 1, "", "error: eve@example.org is in example.org, which is not a hosted domain; add it with: mailctl domain add example.org\n", false},
		{"malformed", []string{"mailbox", "add", "not-an-address"}, pw + pw, 1, "", "error: invalid address \"not-an-address\": expected local@domain\n", false},
		{"alias", []string{"alias", "add", "info@example.test", "alice@example.test,bob@example.test"}, "", 0, "ok: added alias info@example.test -> alice@example.test,bob@example.test\n", "", false},
		{"alias loop", []string{"alias", "add", "x@example.test", "x@example.test"}, "", 1, "", "error: alias loop: x@example.test -> x@example.test\n", false},
		{"alias set", []string{"alias", "set", "info@example.test", "bob@example.test,alice@example.test"}, "", 0, "ok: alias info@example.test now delivers to bob@example.test,alice@example.test\n", "", false},
		{"alias set unknown", []string{"alias", "set", "nope@example.test", "bob@example.test"}, "", 1, "", "error: no alias nope@example.test\n", false},
		{"alias set loop", []string{"alias", "set", "info@example.test", "info@example.test"}, "", 1, "", "error: alias loop: info@example.test -> info@example.test\n", false},
		{"sendas", []string{"sendas", "add", "alice@example.test", "sales@example.test"}, "", 0, "ok: alice@example.test may now send as sales@example.test\n", "", false},
		{"state", []string{"mailbox", "state", "bob@example.test", "receive-only"}, "", 0, "ok: set bob@example.test to receive-only\n", "", false},
		{"bad state", []string{"mailbox", "state", "bob@example.test", "asleep"}, "", 1, "", "error: unknown state \"asleep\"; use active, receive-only or disabled\n", false},
		{"passwd", []string{"mailbox", "passwd", "alice@example.test"}, pw + pw, 0, "ok: changed password for alice@example.test\n", "", false},
		{"remove targeted", []string{"mailbox", "remove", "bob@example.test"}, "", 1, "", "error: cannot remove bob@example.test: alias info@example.test still delivers to it; remove or retarget the alias first\n", false},
		{"remove domain in use", []string{"domain", "remove", "example.test"}, "", 1, "", "error: domain example.test still has 2 mailboxes, 1 aliases and 1 send-as grants; remove them first\n", false},
		{"remove mailbox", []string{"alias", "remove", "info@example.test"}, "", 0, "ok: removed alias info@example.test\n", "", false},
		{"remove mailbox keeps mail", []string{"mailbox", "remove", "bob@example.test"}, "", 0, "ok: removed bob@example.test; mail left in place at " + filepath.Join(mail, "example.test", "bob") + "; mailbox purge-removed deletes it after 30 days\n", "", false},
		{"apply", []string{"apply"}, "", 0, "ok: applied current account set\n", "", false},
		{"admin add", []string{"admin", "add", "Sam@Example.test"}, "", 0, "ok: added admin sam@example.test\nEnrolment link, valid for 24 hours and shown only now. Send it by a channel you trust:\nhttps://admin.example.test/enrol?t=", "", true},
		{"admin add twice", []string{"admin", "add", "sam@example.test"}, "", 1, "", "error: admin sam@example.test already exists; use `mailctl admin reset` for a new enrolment link\n", false},
		{"admin add malformed", []string{"admin", "add", "sam"}, "", 1, "", "error: invalid address \"sam\": expected local@domain\n", false},
		{"admin list", []string{"admin", "list"}, "", 0, "sam@example.test  not enrolled  0 passkeys\n", "", false},
		{"admin reset", []string{"admin", "reset", "sam@example.test"}, "", 0, "ok: reset admin sam@example.test; the password, authenticator, passkeys and sessions are gone\nEnrolment link", "", true},
		{"admin reset unknown", []string{"admin", "reset", "nobody@example.test"}, "", 1, "", "error: admin nobody@example.test does not exist\n", false},
		{"admin remove", []string{"admin", "remove", "sam@example.test"}, "", 0, "ok: removed admin sam@example.test\n", "", false},
		{"admin usage", []string{"admin", "add"}, "", 2, "", "error: usage: mailctl admin list|add <address>|reset <address>|remove <address>\n", false},
		{"unknown command", []string{"frobnicate"}, "", 2, "", "error: usage: mailctl ", false},
		{"mailbox list", []string{"mailbox", "list"}, "", 0, "alice@example.test  active  Alice A\n", "", false},
		{"alias list", []string{"alias", "list"}, "", 0, "", "", false},
		{"sendas list", []string{"sendas", "list"}, "", 0, "alice@example.test  sales@example.test\n", "", false},
		{"domain list", []string{"domain", "list"}, "", 0, "example.test\n", "", false},
	}
	for _, s := range steps {
		var out, errOut bytes.Buffer
		code := run(s.args, getenv, strings.NewReader(s.stdin), &out, &errOut)
		stdoutOK := out.String() == s.stdout || s.stdoutPart && strings.HasPrefix(out.String(), s.stdout)
		if code != s.code || !stdoutOK || !strings.HasPrefix(errOut.String(), s.stderr) {
			t.Errorf("%s: code %d stdout %q stderr %q; want code %d stdout %q stderr %q",
				s.name, code, out.String(), errOut.String(), s.code, s.stdout, s.stderr)
		}
	}

	if err := os.MkdirAll(mailPath, 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"mailbox", "remove", "alice@example.test"}, getenv, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("remove alice: %s", errOut.String())
	}
	code := run([]string{"mailbox", "add", "alice@example.test"}, getenv, strings.NewReader(pw+pw), &out, &errOut)
	if want := "error: mail for alice@example.test still exists at " + mailPath + "\n"; code == 0 || errOut.String() != want {
		t.Errorf("re-add: code %d stderr %q, want %q", code, errOut.String(), want)
	}
	out.Reset()
	if code := run([]string{"mailbox", "add", "alice@example.test", "--adopt-existing-mail"}, getenv, strings.NewReader(pw+pw), &out, &errOut); code != 0 || out.String() != "ok: added mailbox alice@example.test\n" {
		t.Errorf("adopt: code %d stdout %q", code, out.String())
	}

	out.Reset()
	run([]string{"log"}, getenv, strings.NewReader(""), &out, &errOut)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) < 5 || !strings.Contains(lines[0], "cli:alex") || !strings.Contains(lines[0], "domain.add") {
		t.Errorf("log output:\n%s", out.String())
	}
	if strings.Contains(out.String(), "correct horse") || strings.Contains(out.String(), "$2y$") {
		t.Errorf("log leaks a secret:\n%s", out.String())
	}
}

func TestActorFallback(t *testing.T) {
	tests := []struct {
		vars map[string]string
		want string
	}{
		{map[string]string{"SUDO_USER": "alex", "USER": "root"}, "cli:alex"},
		{map[string]string{"USER": "alex"}, "cli:alex"},
		{map[string]string{}, "cli:unknown"},
	}
	for _, tc := range tests {
		e := &env{getenv: func(k string) string { return tc.vars[k] }}
		if got := e.actor(); got != tc.want {
			t.Errorf("actor(%v) = %q, want %q", tc.vars, got, tc.want)
		}
	}
}

func TestLostStoreIsNotSilentlyReplaced(t *testing.T) {
	state, mail := t.TempDir(), t.TempDir()
	vars := map[string]string{"MAILCTL_STATE": state, "MAILCTL_MAIL_ROOT": mail, "MAILCTL_WATCHER": "off", "MAILCTL_DOVECOT_GID": strconv.Itoa(os.Getgid()), "USER": "alex"}
	do := func(args ...string) (int, string, string) {
		var out, errOut bytes.Buffer
		code := run(args, func(k string) string { return vars[k] }, strings.NewReader(""), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	if code, _, e := do("domain", "add", "example.test"); code != 0 {
		t.Fatal(e)
	}
	storePath := filepath.Join(state, "store.db")
	if err := os.Remove(storePath); err != nil {
		t.Fatal(err)
	}

	want := "error: account store " + storePath + " is missing but generated files exist; restore it from backup\n"
	for _, args := range [][]string{{"mailbox", "list"}, {"log"}, {"domain", "add", "example.org"}, {"apply"}} {
		if code, _, e := do(args...); code != 1 || e != want {
			t.Errorf("%v: code %d stderr %q", args, code, e)
		}
	}
	if _, err := os.Stat(storePath); err == nil {
		t.Fatal("a refused command created store.db")
	}
	// A refused apply must not have left a store behind for the next command to trust.
	if code, _, e := do("mailbox", "list"); code != 1 || e != want {
		t.Errorf("mailbox list after a refused apply: code %d stderr %q", code, e)
	}

	if code, out, e := do("apply", "--publish-empty"); code != 0 || out != "ok: applied current account set\n" {
		t.Errorf("apply --publish-empty: code %d stdout %q stderr %q", code, out, e)
	}
	if code, _, e := do("mailbox", "list"); code != 0 {
		t.Errorf("mailbox list after --publish-empty: code %d stderr %q", code, e)
	}
	if code, _, _ := do("apply", "--nonsense"); code != 2 {
		t.Errorf("bad apply flag: code %d", code)
	}
}
