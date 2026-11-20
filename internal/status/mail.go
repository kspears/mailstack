package status

import (
	"errors"
	"io/fs"
	"os"
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
// the mailbox under dir. Missing directories are normal and not errors.
func ScanMailbox(dir string) Mailbox {
	var m Mailbox
	fail := func(err error) {
		if m.Err == nil && err != nil && !errors.Is(err, fs.ErrNotExist) {
			m.Err = err
		}
	}
	for _, folder := range []string{"Maildir", filepath.Join("Maildir", JunkDir)} {
		for _, sub := range []string{"new", "cur"} {
			last, err := newestFile(filepath.Join(dir, folder, sub))
			fail(err)
			if last.After(m.Last) {
				m.Last = last
			}
		}
	}
	fail(filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
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
		return nil
	}))
	return m
}

func newestFile(dir string) (time.Time, error) {
	entries, err := os.ReadDir(dir)
	var newest time.Time
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			if err == nil && !errors.Is(ierr, fs.ErrNotExist) {
				err = ierr
			}
			continue
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, err
}
