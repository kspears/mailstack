package status

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Hour)
)

func put(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestScanMailbox(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]time.Time
		wantLast time.Time
		wantSize bool
	}{
		{"inbox only", map[string]time.Time{"Maildir/new/a": t0, "Maildir/cur/b": t1}, t1, true},
		{"junk only", map[string]time.Time{"Maildir/.Junk/new/a": t1}, t1, true},
		{"junk newer than inbox", map[string]time.Time{"Maildir/cur/a": t0, "Maildir/.Junk/cur/b": t1}, t1, true},
		{"inbox newer than junk", map[string]time.Time{"Maildir/new/a": t1, "Maildir/.Junk/cur/b": t0}, t1, true},
		{"sent only", map[string]time.Time{"Maildir/.Sent/cur/a": t1}, time.Time{}, true},
		{"empty dir", nil, time.Time{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for rel, mt := range tt.files {
				put(t, filepath.Join(dir, rel), mt)
			}
			m := ScanMailbox(dir)
			if m.Err != nil {
				t.Fatalf("Err = %v", m.Err)
			}
			if !m.Last.Equal(tt.wantLast) {
				t.Errorf("Last = %v, want %v", m.Last, tt.wantLast)
			}
			if (m.Size > 0) != tt.wantSize {
				t.Errorf("Size = %d, wantSize %v", m.Size, tt.wantSize)
			}
		})
	}
}

func TestScanMailboxMissingDir(t *testing.T) {
	m := ScanMailbox(filepath.Join(t.TempDir(), "gone"))
	if m.Err != nil || !m.Last.IsZero() || m.Size != 0 {
		t.Fatalf("got %+v", m)
	}
}

func TestScanMailboxUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores permissions")
	}
	dir := t.TempDir()
	cur := filepath.Join(dir, "Maildir", "cur")
	put(t, filepath.Join(cur, "a"), t0)
	if err := os.Chmod(cur, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(cur, 0o755) })
	if m := ScanMailbox(dir); m.Err == nil {
		t.Fatalf("expected an error, got %+v", m)
	}
}
