package mailcow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKeyStageAndInstall(t *testing.T) {
	keys := []KeyFile{{Domain: "example.test", Selector: "dkim", PEM: pemA}}
	root := t.TempDir()
	dir := filepath.Join(root, "dkim")

	staged, err := StageKeys(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("staging touched the destination")
	}
	if _, err := InstallKeys(staged, dir, time.Now()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "example.test.dkim.key")
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", st.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != pemA {
		t.Error("key content changed")
	}
	if err := CheckKeyTargets(dir, keys, false); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("collision: %v", err)
	}
	if err := CheckKeyTargets(dir, keys, true); err != nil {
		t.Error(err)
	}
}

func TestInstallKeysReplacesDirectoryWholesale(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dkim")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"example.org.s1.key": "old", "other.test.s1.key": "unrelated"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	staged, err := StageKeys(dir, []KeyFile{{Domain: "example.org", Selector: "s1", PEM: pemA}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	replaced, err := InstallKeys(staged, dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if replaced != dir+".replaced-20261117T120000Z" {
		t.Errorf("replaced = %q", replaced)
	}
	read := func(path string) string { b, _ := os.ReadFile(path); return string(b) }
	if read(filepath.Join(dir, "example.org.s1.key")) != pemA || read(filepath.Join(dir, "other.test.s1.key")) != "unrelated" {
		t.Error("new directory lacks the new key or the carried-over one")
	}
	if read(filepath.Join(replaced, "example.org.s1.key")) != "old" {
		t.Error("old key was not kept aside")
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o750 {
		t.Errorf("dir mode %v", st.Mode().Perm())
	}
	if _, err := os.Stat(staged); err == nil {
		t.Error("staging directory left behind")
	}
}

func TestInstallKeysFailureKeepsStagedKeys(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dkim")
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := StageKeys(dir, []KeyFile{{Domain: "example.org", Selector: "s1", PEM: pemA}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallKeys(staged, dir, time.Now()); err == nil {
		t.Fatal("install over a plain file succeeded")
	}
	if b, err := os.ReadFile(filepath.Join(staged, "example.org.s1.key")); err != nil || string(b) != pemA {
		t.Errorf("staged key lost: %v", err)
	}
	if b, _ := os.ReadFile(dir); string(b) != "not a directory" {
		t.Error("destination was touched")
	}
}
