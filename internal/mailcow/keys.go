package mailcow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// StageKeys writes the key files into a fresh private directory next to dir.
// Nothing at dir changes until InstallKeys. The caller removes staged on failure.
func StageKeys(dir string, keys []KeyFile) (staged string, err error) {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", parent, err)
	}
	staged, err = os.MkdirTemp(parent, ".dkim-staging-")
	if err != nil {
		return "", fmt.Errorf("create staging directory for DKIM keys: %w", err)
	}
	for _, k := range keys {
		if err := os.WriteFile(filepath.Join(staged, k.Filename()), []byte(k.PEM), 0o600); err != nil {
			os.RemoveAll(staged)
			return "", fmt.Errorf("write DKIM key for %s: %w", k.Domain, err)
		}
	}
	return staged, nil
}

// CheckKeyTargets fails if a key file already exists at dir and replace is false.
func CheckKeyTargets(dir string, keys []KeyFile, replace bool) error {
	if replace {
		return nil
	}
	for _, k := range keys {
		path := filepath.Join(dir, k.Filename())
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists; pass --overwrite to replace it", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// InstallKeys moves staged into place: the whole directory if dir does not
// exist, otherwise file by file into it.
func InstallKeys(staged, dir string) error {
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return os.Rename(staged, dir)
	}
	entries, err := os.ReadDir(staged)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.Rename(filepath.Join(staged, e.Name()), filepath.Join(dir, e.Name())); err != nil {
			return err
		}
	}
	return os.Remove(staged)
}
