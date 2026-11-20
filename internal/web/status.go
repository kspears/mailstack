package web

import (
	"net/http"

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
	in := status.Inputs{Now: now, WatcherOff: cfg.WatcherOff, Timeout: cfg.Timeout, Watcher: s.admin.Watcher()}
	in.Files, in.FilesErr = s.admin.CheckFiles()
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
		rows[i] = mailboxRow{m, b.Line(now), b.Err != nil}
	}
	s.render(w, r, "mailboxes", "mailboxes", "Mailboxes", rows)
}
