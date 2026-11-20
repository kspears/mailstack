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
// more than purgeAfterDays ago that has not been added back since. Only the
// latest removal of an address counts, and only while nothing purged it after
// that, so mail restored by hand is not deleted again. Mail that no removal in
// the change log accounts for, such as leftovers from before mailstack, is never
// touched. One address that cannot be purged does not stop the others; their
// errors are returned together. With dryRun it only reports what it would delete.
func (a *Admin) PurgeRemoved(actor string, dryRun bool) ([]string, error) {
	for _, root := range []string{a.cfg.MailRoot, a.cfg.IndexRoot} {
		if !filepath.IsAbs(root) {
			return nil, fmt.Errorf("mail root %q and index root %q must be absolute paths", a.cfg.MailRoot, a.cfg.IndexRoot)
		}
	}
	unlock, err := a.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	snap, err := a.st.Snapshot()
	if err != nil {
		return nil, err
	}
	// A store that does not match the files in use (replaced or restored) could
	// list as removed a mailbox the daemons still deliver to.
	if err := a.requireCurrentMatches(snap); err != nil {
		return nil, err
	}
	entries, err := a.st.Log()
	if err != nil {
		return nil, err
	}
	removed := map[string]time.Time{}
	for _, e := range entries {
		switch e.Action {
		case "mailbox.remove":
			removed[e.Subject] = e.Time
		case "mailbox.purge":
			delete(removed, e.Subject)
		}
	}
	cutoff := a.cfg.Now().AddDate(0, 0, -purgeAfterDays)
	var done []string
	var errs []error
	for _, addr := range slices.Sorted(maps.Keys(removed)) {
		if removed[addr].After(cutoff) || hasMailbox(snap, addr) {
			continue
		}
		if _, err := validate.Address(addr); err != nil {
			continue
		}
		_, domain := validate.Split(addr)
		present, err := existingDirs(
			[]string{filepath.Join(a.cfg.MailRoot, domain), a.cfg.IndexRoot},
			[]string{a.MailPath(addr), filepath.Join(a.cfg.IndexRoot, addr)},
		)
		if err != nil {
			errs = append(errs, fmt.Errorf("purge %s: %w", addr, err))
			continue
		}
		if len(present) == 0 {
			continue
		}
		what := fmt.Sprintf("mail of %s, removed %s", addr, removed[addr].Format(time.DateOnly))
		if dryRun {
			done = append(done, "would purge "+what)
			continue
		}
		if err := removeAll(present); err != nil {
			errs = append(errs, fmt.Errorf("purge %s: %w; retried on the next run", addr, err))
			continue
		}
		if err := a.logOnly(actor, "mailbox.purge", addr); err != nil {
			return done, err
		}
		done = append(done, "purged "+what)
	}
	return done, errors.Join(errs...)
}

func removeAll(paths []string) error {
	for _, p := range paths {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	return nil
}

// existingDirs returns the targets that exist. Each target and each parent must
// be a real directory, not a symlink, so a planted link cannot point the delete
// elsewhere. A missing parent means its target is missing too.
func existingDirs(parents, targets []string) ([]string, error) {
	var out []string
	for i, t := range targets {
		ok, err := realDir(parents[i])
		if ok {
			ok, err = realDir(t)
		}
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// realDir reports whether p exists as a directory, and fails on anything else at p.
func realDir(p string) (bool, error) {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !fi.IsDir() {
		return false, fmt.Errorf("%s is not a directory; remove it by hand", p)
	}
	return true, nil
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
