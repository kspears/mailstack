package mailcow

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if err := InstallKeys(staged, dir); err != nil {
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

func TestInstallKeysIntoExistingDir(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "dkim")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	staged, err := StageKeys(dir, []KeyFile{{Domain: "example.org", Selector: "s1", PEM: pemA}})
	if err != nil {
		t.Fatal(err)
	}
	if err := InstallKeys(staged, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "example.org.s1.key")); err != nil {
		t.Error(err)
	}
	if _, err := os.Stat(staged); err == nil {
		t.Error("staging directory left behind")
	}
}
