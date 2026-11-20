package generate

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/kspears/mailstack/internal/validate"
)

// purgeAfterDays is how long the mail of a removed mailbox stays on disk.
const purgeAfterDays = 30

// PurgeRemoved deletes the mail and index directories of every mailbox removed
// more than PurgeAfter ago that has not been added back. Mail that no removal in
// the change log accounts for, such as leftovers from before mailstack, is never
// touched. With dryRun it only reports what it would delete.
func (a *Admin) PurgeRemoved(actor string, dryRun bool) ([]string, error) {
	unlock, err := a.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	snap, err := a.st.Snapshot()
	if err != nil {
		return nil, err
	}
	entries, err := a.st.Log()
	if err != nil {
		return nil, err
	}
	removed := map[string]time.Time{}
	for _, e := range entries {
		if e.Action == "mailbox.remove" {
			removed[e.Subject] = e.Time
		}
	}
	cutoff := a.cfg.Now().AddDate(0, 0, -purgeAfterDays)
	var done []string
	for _, addr := range slices.Sorted(maps.Keys(removed)) {
		if removed[addr].After(cutoff) || hasMailbox(snap, addr) {
			continue
		}
		if _, err := validate.Address(addr); err != nil {
			continue
		}
		paths := []string{a.MailPath(addr), filepath.Join(a.cfg.IndexRoot, addr)}
		present, err := existingDirs(paths)
		if err != nil {
			return done, err
		}
		if len(present) == 0 {
			continue
		}
		what := fmt.Sprintf("mail of %s, removed %s", addr, removed[addr].Format(time.DateOnly))
		if dryRun {
			done = append(done, "would purge "+what)
			continue
		}
		for _, p := range present {
			if err := os.RemoveAll(p); err != nil {
				return done, fmt.Errorf("purge %s: %w; the rest is retried on the next run", addr, err)
			}
		}
		if err := a.logOnly(actor, "mailbox.purge", addr); err != nil {
			return done, err
		}
		done = append(done, "purged "+what)
	}
	return done, nil
}

// existingDirs returns the paths that exist, refusing any that is not a real
// directory so a planted symlink cannot point the delete elsewhere.
func existingDirs(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("%s is not a directory; remove it by hand", p)
		}
		out = append(out, p)
	}
	return out, nil
}

// logOnly records an action that changes no account, so no generation is applied.
func (a *Admin) logOnly(actor, action, subject string) error {
	tx, err := a.st.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.Log(a.cfg.Now(), actor, action, subject); err != nil {
		return err
	}
	return tx.Commit()
}
