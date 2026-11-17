package mailcow

import (
	"os"
	"path/filepath"
	"testing"
)

func put(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCountSieveScripts(t *testing.T) {
	root := t.TempDir()
	put(t, filepath.Join(root, "sieve", "global_sieve_before.sieve"), "x")
	put(t, filepath.Join(root, "sieve", "global_sieve_after.sieve"), "x")
	if err := os.MkdirAll(filepath.Join(root, "example.test", "alice", "Maildir", "cur"), 0o755); err != nil {
		t.Fatal(err)
	}
	if n, err := CountSieveScripts(root); err != nil || n != 0 {
		t.Fatalf("only the global scripts: %d, %v", n, err)
	}
	if err := os.Mkdir(filepath.Join(root, "example.test", "alice", "sieve"), 0o755); err != nil {
		t.Fatal(err)
	}
	if n, _ := CountSieveScripts(root); n != 0 {
		t.Errorf("an empty sieve directory counted: %d", n)
	}
	put(t, filepath.Join(root, "sieve", "extra.sieve"), "x")
	put(t, filepath.Join(root, "example.test", "alice", "sieve", "mine.sieve"), "x")
	put(t, filepath.Join(root, "example.test", "bob", "active.sieve"), "x")
	put(t, filepath.Join(root, "example.test", "bob", "Maildir", "note.txt"), "x")
	if n, err := CountSieveScripts(root); err != nil || n != 3 {
		t.Errorf("count = %d, %v; want a stray global, a non-empty sieve directory and a home script", n, err)
	}
	if _, err := CountSieveScripts(filepath.Join(root, "missing")); err == nil {
		t.Error("a missing mail root was not an error")
	}
}

func TestCountFolderACLs(t *testing.T) {
	root := t.TempDir()
	box := filepath.Join(root, "example.test", "alice", "Maildir")
	put(t, filepath.Join(box, "cur", "dovecot-acl"), "must not be looked at")
	put(t, filepath.Join(box, ".Shared", "new", "dovecot-acl"), "must not be looked at")
	put(t, filepath.Join(box, ".Empty", "dovecot-acl"), "")
	if n, err := CountFolderACLs(root); err != nil || n != 0 {
		t.Fatalf("no real ACLs: %d, %v", n, err)
	}
	put(t, filepath.Join(box, "dovecot-acl"), "anyone lr")
	put(t, filepath.Join(box, ".Shared", "dovecot-acl"), "user=bob lr")
	put(t, filepath.Join(box, ".Shared", ".Deep", "dovecot-acl"), "user=bob lr")
	put(t, filepath.Join(root, "shared-mailboxes.db"), "x")
	if n, err := CountFolderACLs(root); err != nil || n != 4 {
		t.Errorf("count = %d, %v; want the root, folder, nested folder and shared-mailboxes.db", n, err)
	}
	put(t, filepath.Join(root, "example.test", "carol", "stray"), "no Maildir here")
	if n, _ := CountFolderACLs(root); n != 4 {
		t.Errorf("a home without a Maildir changed the count: %d", n)
	}
}

func TestCountRspamdMapLines(t *testing.T) {
	dir := t.TempDir()
	put(t, filepath.Join(dir, "a.map"), "# comment\n\n  \nfirst\n  # indented comment\nsecond\n")
	put(t, filepath.Join(dir, "b.map"), "third")
	put(t, filepath.Join(dir, "ignored.txt"), "not a map\n")
	if n, err := CountRspamdMapLines(dir); err != nil || n != 3 {
		t.Errorf("count = %d, %v", n, err)
	}
	if _, err := CountRspamdMapLines(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing directory was not an error")
	}
}

func TestLiveReadFiles(t *testing.T) {
	root, maps := t.TempDir(), t.TempDir()
	put(t, filepath.Join(maps, "a.map"), "x\n")
	d := Data{Counts: map[string]int{}}
	Live{MailRoot: root, RspamdCustomDir: maps}.readFiles(&d)
	if len(d.Unchecked) != 0 || d.Counts["global-rspamd-maps"] != 1 {
		t.Errorf("counts %v, unchecked %v", d.Counts, d.Unchecked)
	}
	d = Data{Counts: map[string]int{}}
	Live{}.readFiles(&d)
	if len(d.Unchecked) != 3 {
		t.Errorf("unset directories must leave all three items unchecked: %v", d.Unchecked)
	}
	d = Data{Counts: map[string]int{}}
	Live{MailRoot: filepath.Join(root, "missing"), RspamdCustomDir: maps}.readFiles(&d)
	if d.Unchecked["sieve-scripts"] == "" || d.Unchecked["shared-folder-acls"] == "" || d.Unchecked["global-rspamd-maps"] != "" {
		t.Errorf("unchecked: %v", d.Unchecked)
	}
}
