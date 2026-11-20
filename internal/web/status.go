package web

import (
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kspears/mailstack/internal/status"
	"github.com/kspears/mailstack/internal/store"
)

// mailBoxes returns the cached scan of every mailbox in snap, and when it ran.
func (s *server) mailBoxes(snap store.Snapshot) (map[string]status.Mailbox, string) {
	paths := make(map[string]string, len(snap.Mailboxes))
	for _, m := range snap.Mailboxes {
		paths[m.Address] = s.admin.MailPath(m.Address)
	}
	boxes, at := s.mail.Get(paths)
	return boxes, status.Stamp(at)
}

// statusPage reads only files the ui container already mounts. It never fails as a
// whole: whatever cannot be read shows on its own card.
func (s *server) statusPage(w http.ResponseWriter, r *http.Request) {
	cfg := s.admin.Config()
	now := cfg.Now()
	in := status.Inputs{Now: now, WatcherOff: cfg.WatcherOff, Timeout: cfg.Timeout}
	watcher := filepath.Join(cfg.State, "watcher")
	if fi, err := os.Stat(filepath.Join(watcher, "heartbeat")); err == nil {
		in.Heartbeat = fi.ModTime()
	} else if !errors.Is(err, fs.ErrNotExist) {
		in.HeartbeatErr = err
	}
	in.Files, in.FilesErr = s.admin.CheckFiles()
	pending := filepath.Join(cfg.State, "generations", "pending")
	if target, err := os.Readlink(pending); err == nil {
		in.Pending, in.PendingAt = filepath.Base(target), now
		if fi, err := os.Lstat(pending); err == nil {
			in.PendingAt = fi.ModTime()
		}
	}
	in.WatcherStatus = readWatcherStatus(filepath.Join(watcher, "status"))
	scanned := "never"
	if snap, err := s.admin.Snapshot(); err == nil {
		in.Boxes, scanned = s.mailBoxes(snap)
	}
	in.MailDisk.Disk, in.MailDisk.Err = status.ReadDisk(cfg.MailRoot)
	in.StateDisk.Disk, in.StateDisk.Err = status.ReadDisk(cfg.State)
	s.render(w, r, "status", "status", "Status", struct {
		status.Report
		Checked, Scanned string
	}{status.Evaluate(in), status.Stamp(now), scanned})
}

// readWatcherStatus returns the first few KiB of watcher/status, or "" if it is missing or is
// not a plain file. The internet-facing postfix container writes that directory, so the file
// may be a symlink to a secret, a FIFO or an endless device; none of those is followed or read.
func readWatcherStatus(path string) string {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return ""
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(f, 4<<10))
	return strings.TrimSpace(string(b))
}

type mailboxRow struct {
	store.Mailbox
	Line string
	Err  bool
}

func (s *server) mailboxes(w http.ResponseWriter, r *http.Request) {
	snap, err := s.admin.Snapshot()
	if err != nil {
		s.fail(w, "snapshot", err)
		return
	}
	boxes, _ := s.mailBoxes(snap)
	now := s.admin.Config().Now()
	rows := make([]mailboxRow, len(snap.Mailboxes))
	for i, m := range snap.Mailboxes {
		b := boxes[m.Address]
		rows[i].Mailbox = m
		switch {
		case b.Err != nil:
			rows[i].Line, rows[i].Err = "Cannot read mail folder", true
		case b.Last.IsZero():
			rows[i].Line = "No mail yet · " + status.Size(b.Size)
		default:
			rows[i].Line = "Last delivery " + status.Age(now.Sub(b.Last)) + " ago · " + status.Size(b.Size)
		}
	}
	s.render(w, r, "mailboxes", "mailboxes", "Mailboxes", rows)
}
