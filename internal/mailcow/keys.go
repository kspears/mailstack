package mailcow

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kspears/mailstack/internal/store"
)

// StageKeys writes the key files into a fresh private directory next to dir.
// Nothing at dir changes until InstallKeys.
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

// InstallKeys makes staged the key directory, all or nothing as far as rename
// allows. If dir does not exist, staged becomes dir. Otherwise the existing
// directory is moved aside whole to <dir>.replaced-<UTC timestamp> (returned as
// replaced), keys in it that staged does not replace are carried into staged, and
// staged becomes dir; if that last rename fails the old directory is moved back.
// Staged lives next to dir, so every rename stays on one filesystem. On failure
// staged is left where it is for the operator.
func InstallKeys(staged, dir string, now time.Time) (replaced string, err error) {
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return "", os.Rename(staged, dir)
	}
	if err != nil {
		return "", err
	}
	old, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read the existing key directory: %w", err)
	}
	for _, e := range old {
		kept := filepath.Join(staged, e.Name())
		if _, err := os.Lstat(kept); err == nil {
			continue
		}
		if e.IsDir() {
			return "", fmt.Errorf("%s holds a directory, %s, that is not a key file", dir, e.Name())
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(kept, b, 0o600); err != nil {
			return "", err
		}
	}
	if err := os.Chmod(staged, info.Mode().Perm()); err != nil {
		return "", err
	}
	replaced = store.ReplacedName(dir, now)
	if err := os.Rename(dir, replaced); err != nil {
		return "", err
	}
	if err := os.Rename(staged, dir); err != nil {
		if back := os.Rename(replaced, dir); back != nil {
			return "", fmt.Errorf("%w; the old keys are at %s and could not be moved back: %v", err, replaced, back)
		}
		return "", err
	}
	return replaced, nil
}
