package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const pw = "correct horse battery\n"

func TestCLI(t *testing.T) {
	state, mail := t.TempDir(), t.TempDir()
	vars := map[string]string{
		"MAILCTL_STATE": state, "MAILCTL_MAIL_ROOT": mail, "MAILCTL_WATCHER": "off",
		"SUDO_USER": "kevin", "USER": "root",
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
		{"sendas", []string{"sendas", "add", "alice@example.test", "sales@example.test"}, "", 0, "ok: alice@example.test may now send as sales@example.test\n", "", false},
		{"state", []string{"mailbox", "state", "bob@example.test", "receive-only"}, "", 0, "ok: set bob@example.test to receive-only\n", "", false},
		{"bad state", []string{"mailbox", "state", "bob@example.test", "asleep"}, "", 1, "", "error: unknown state \"asleep\"; use active, receive-only or disabled\n", false},
		{"passwd", []string{"mailbox", "passwd", "alice@example.test"}, pw + pw, 0, "ok: changed password for alice@example.test\n", "", false},
		{"remove targeted", []string{"mailbox", "remove", "bob@example.test"}, "", 1, "", "error: cannot remove bob@example.test: alias info@example.test still delivers to it; remove or retarget the alias first\n", false},
		{"remove domain in use", []string{"domain", "remove", "example.test"}, "", 1, "", "error: domain example.test still has 2 mailboxes, 1 aliases and 1 send-as grants; remove them first\n", false},
		{"remove mailbox", []string{"alias", "remove", "info@example.test"}, "", 0, "ok: removed alias info@example.test\n", "", false},
		{"remove mailbox keeps mail", []string{"mailbox", "remove", "bob@example.test"}, "", 0, "ok: removed bob@example.test; mail left in place at " + filepath.Join(mail, "example.test", "bob") + "\n", "", false},
		{"apply", []string{"apply"}, "", 0, "ok: applied current account set\n", "", false},
		{"serve needs access settings", []string{"serve"}, "", 1, "", "error: MAILCTL_ACCESS_TEAM_DOMAIN is not set", false},
		{"unknown command", []string{"frobnicate"}, "", 2, "", "error: usage: mailctl ", false},
		{"mailbox list", []string{"mailbox", "list"}, "", 0, "alice@example.test  active  Alice A\n", "", false},
		{"alias list", []string{"alias", "list"}, "", 0, "", "", false},
		{"sendas list", []string{"sendas", "list"}, "", 0, "alice@example.test  sales@example.test\n", "", false},
		{"domain list", []string{"domain", "list"}, "", 0, "example.test\n", "", false},
	}
	for _, s := range steps {
		var out, errOut bytes.Buffer
		code := run(s.args, getenv, strings.NewReader(s.stdin), &out, &errOut)
		if code != s.code || out.String() != s.stdout || !strings.HasPrefix(errOut.String(), s.stderr) {
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
	if len(lines) < 5 || !strings.Contains(lines[0], "cli:kevin") || !strings.Contains(lines[0], "domain.add") {
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
		{map[string]string{"SUDO_USER": "kevin", "USER": "root"}, "cli:kevin"},
		{map[string]string{"USER": "kevin"}, "cli:kevin"},
		{map[string]string{}, "cli:unknown"},
	}
	for _, tc := range tests {
		e := &env{getenv: func(k string) string { return tc.vars[k] }}
		if got := e.actor(); got != tc.want {
			t.Errorf("actor(%v) = %q, want %q", tc.vars, got, tc.want)
		}
	}
}
