package status

import (
	"errors"
	"io/fs"
	"path/filepath"
	"syscall"
	"time"
)

// JunkDir is the Junk folder inside a Maildir.
const JunkDir = ".Junk"

// Mailbox is what a scan found. Last is the newest delivery (zero if none),
// Size the disk space used, and Err the first unexpected read error.
type Mailbox struct {
	Last time.Time
	Size int64
	Err  error
}

// ScanMailbox reports the last delivery to Inbox or Junk and the disk usage of
// the mailbox under dir, in one walk. Missing directories are normal and not errors.
func ScanMailbox(dir string) Mailbox {
	var m Mailbox
	delivered := map[string]bool{}
	for _, folder := range []string{"Maildir", filepath.Join("Maildir", JunkDir)} {
		for _, sub := range []string{"new", "cur"} {
			delivered[filepath.Join(dir, folder, sub)] = true
		}
	}
	fail := func(err error) {
		if m.Err == nil && err != nil && !errors.Is(err, fs.ErrNotExist) {
			m.Err = err
		}
	}
	fail(filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			fail(err)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			fail(err)
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			m.Size += int64(st.Blocks) * 512
		}
		if delivered[filepath.Dir(path)] && info.ModTime().After(m.Last) {
			m.Last = info.ModTime()
		}
		return nil
	}))
	return m
}

// Delivery is the mailbox's last delivery as the Mailboxes list shows it.
func (m Mailbox) Delivery(now time.Time) string {
	switch {
	case m.Err != nil:
		return "Cannot read mail folder"
	case m.Last.IsZero():
		return "No mail yet"
	}
	return Age(now.Sub(m.Last)) + " ago"
}
