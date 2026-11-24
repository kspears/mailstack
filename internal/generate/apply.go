package generate

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

const keepGenerations = 10

// defaultDovecotUID is the dovecot user in the dovecot/dovecot image, whose auth process
// reads dovecot/users.
const defaultDovecotUID = 999

// Config is the on-disk layout and apply behaviour. See the README for the env vars.
type Config struct {
	State      string
	MailRoot   string
	IndexRoot  string
	WatcherOff bool
	// DovecotUID owns dovecot/users, which is mode 0400. Dovecot's auth process runs as that
	// user and reads the hashes; its mail processes (uid 5000, though in the dovecot group)
	// and postfix, which also mounts the generations, cannot. ConfigFromEnv always sets it;
	// 0, for a Config built in a test, leaves the owner as written.
	DovecotUID int
	Timeout    time.Duration
	Poll       time.Duration
	Now        func() time.Time
}

// ConfigFromEnv reads MAILCTL_* settings through getenv.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		State:      cmp.Or(getenv("MAILCTL_STATE"), "/data/mailstack"),
		MailRoot:   cmp.Or(getenv("MAILCTL_MAIL_ROOT"), "/var/vmail"),
		IndexRoot:  cmp.Or(getenv("MAILCTL_INDEX_ROOT"), "/var/vmail_index"),
		WatcherOff: getenv("MAILCTL_WATCHER") == "off",
		DovecotUID: defaultDovecotUID,
		Timeout:    30 * time.Second,
		Poll:       100 * time.Millisecond,
		Now:        time.Now,
	}
	if s := getenv("MAILCTL_APPLY_TIMEOUT"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("MAILCTL_APPLY_TIMEOUT=%q is not a positive duration such as 30s", s)
		}
		cfg.Timeout = d
	}
	if s := getenv("MAILCTL_DOVECOT_UID"); s != "" {
		uid, err := strconv.Atoi(s)
		if err != nil || uid <= 0 {
			return cfg, fmt.Errorf("MAILCTL_DOVECOT_UID=%q is not a positive user id such as 999", s)
		}
		cfg.DovecotUID = uid
	}
	if !filepath.IsAbs(cfg.MailRoot) || !filepath.IsAbs(cfg.IndexRoot) {
		return cfg, fmt.Errorf("MAILCTL_MAIL_ROOT=%q and MAILCTL_INDEX_ROOT=%q must be absolute paths", cfg.MailRoot, cfg.IndexRoot)
	}
	return cfg, nil
}

// StorePath is the account store's file.
func StorePath(cfg Config) string { return filepath.Join(cfg.State, "store.db") }

// Admin owns the store and applies every change to it.
type Admin struct {
	cfg  Config
	st   *store.Store
	gens string
}

// Open creates the state directory if needed and opens the store. A missing
// store.db is created only on a fresh install, when generations/current does not
// exist yet. Next to a generation in use it means the store was lost, so Open
// fails unless allowCreate is set: only `apply --publish-empty` and
// `import-mailcow --overwrite` start over on purpose.
func Open(cfg Config, allowCreate bool) (*Admin, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Poll == 0 {
		cfg.Poll = 100 * time.Millisecond
	}
	gens := filepath.Join(cfg.State, "generations")
	if err := os.MkdirAll(gens, 0o755); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := makeDir(watcherDir(cfg)); err != nil {
		return nil, err
	}
	st, err := openStore(StorePath(cfg), gens, allowCreate)
	if err != nil {
		return nil, err
	}
	return &Admin{cfg: cfg, st: st, gens: gens}, nil
}

func openStore(path, gens string, allowCreate bool) (*store.Store, error) {
	if _, err := os.Stat(path); err == nil {
		return store.Open(path)
	}
	if _, err := os.Lstat(filepath.Join(gens, "current")); err == nil && !allowCreate {
		return nil, fmt.Errorf("account store %s is missing but generated files exist; restore it from backup", path)
	}
	return store.Create(path)
}

// watcherDir is the only state directory the internet-facing postfix container may write.
func watcherDir(cfg Config) string { return filepath.Join(cfg.State, "watcher") }

func makeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	return os.Chmod(dir, 0o755)
}

func (a *Admin) Close() error { return a.st.Close() }

func (a *Admin) Snapshot() (store.Snapshot, error) { return a.st.Snapshot() }

func (a *Admin) Log() ([]store.LogEntry, error) { return a.st.Log() }

// Store is for the sign-in tables only, which no generated file depends on.
// Every account change goes through the methods of Admin instead.
func (a *Admin) Store() *store.Store { return a.st }

// MailPath is where a mailbox's mail lives on disk.
func (a *Admin) MailPath(address string) string {
	local, domain := validate.Split(address)
	return filepath.Join(a.cfg.MailRoot, domain, local)
}

// IndexPath is where dovecot keeps a mailbox's indexes.
func (a *Admin) IndexPath(address string) string {
	return filepath.Join(a.cfg.IndexRoot, address)
}

type change struct{ action, subject, summary string }

// change runs fn in a store transaction and applies the result as a new
// generation. Either both the store and the daemons' files move, or neither.
// It refuses to run when the files in use are not what the store renders.
func (a *Admin) change(actor string, fn func(tx *store.Tx, snap store.Snapshot) (change, error)) (string, error) {
	return a.run(actor, a.requireCurrentMatches, fn)
}

// run is the one pipeline every change takes, under the lock and in one store
// transaction: guard looks at the store as it was, fn changes it, then the result
// is validated, applied as one generation and committed.
func (a *Admin) run(actor string, guard func(store.Snapshot) error, fn func(tx *store.Tx, snap store.Snapshot) (change, error)) (string, error) {
	unlock, err := a.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	tx, err := a.st.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	before, err := tx.Snapshot()
	if err != nil {
		return "", err
	}
	if err := guard(before); err != nil {
		return "", err
	}
	c, err := fn(tx, before)
	if err != nil {
		return "", err
	}
	after, err := tx.Snapshot()
	if err != nil {
		return "", err
	}
	if err := validate.Consistency(after); err != nil {
		return "", err
	}
	if err := tx.Log(a.cfg.Now(), actor, c.action, c.subject); err != nil {
		return "", err
	}
	id, err := a.deploy(Render(after))
	if err != nil {
		return "", err
	}
	if err := a.promote(id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("record change (daemons already use generation %s; run mailctl apply to resync): %w", id, err)
	}
	return c.summary, nil
}

// Apply renders the store as it is and applies it, even if nothing changed and
// even if the files in use disagree with it: it is the explicit resync. It
// refuses to publish an empty store over files that list domains unless
// publishEmpty is set, because an empty store usually means store.db was lost.
func (a *Admin) Apply(actor string, publishEmpty bool) (string, error) {
	guard := func(before store.Snapshot) error {
		if publishEmpty || len(before.Domains) > 0 {
			return nil
		}
		have, exists, err := a.currentFiles()
		if !exists {
			return nil
		}
		if err != nil {
			return fmt.Errorf("the account store is empty and the files in use cannot be read, so it is not safe to replace them; pass --publish-empty if this is intended: %w", err)
		}
		if have[FileDomains] == "" {
			return nil
		}
		return errors.New("the account store is empty but the files in use are not; refusing to remove every account. Restore store.db from backup, or pass --publish-empty if this is intended")
	}
	return a.run(actor, guard, func(*store.Tx, store.Snapshot) (change, error) {
		return change{"apply", "-", "applied current account set"}, nil
	})
}

// lockPath is the one lock every change takes.
func (a *Admin) lockPath() string { return filepath.Join(a.cfg.State, "lock") }

func (a *Admin) lock() (func(), error) {
	f, err := os.OpenFile(a.lockPath(), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("take lock: %w", err)
	}
	return func() { f.Close() }, nil
}

// currentFiles reads generations/current. exists is false before the first generation.
func (a *Admin) currentFiles() (files Files, exists bool, err error) {
	link := filepath.Join(a.gens, "current")
	if _, err := os.Lstat(link); errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	files, err = Read(link)
	return files, true, err
}

// requireCurrentMatches refuses a change when generations/current is not what the
// store renders: publishing from a store that was replaced or restored would
// silently remove accounts from the daemons.
func (a *Admin) requireCurrentMatches(snap store.Snapshot) error {
	have, exists, err := a.currentFiles()
	if !exists {
		return nil
	}
	const msg = `the files in use do not match the account store (was the store replaced or restored?); check with "mailctl mailbox list", then run "mailctl apply" to publish the store as it is`
	if err != nil {
		return fmt.Errorf("%s: %w", msg, err)
	}
	if !have.Equal(Render(snap)) {
		return errors.New(msg)
	}
	return nil
}

// FilesState is the outcome of CheckFiles.
type FilesState int

const (
	FilesNone     FilesState = iota // no generation published yet
	FilesMatch                      // generations/current is what the store renders
	FilesMismatch                   // it is not, or it cannot be read
	FilesBusy                       // a change holds the lock right now
	FilesError                      // the lock or the account store could not be read
)

// FilesCheck is what CheckFiles found. Current is the generation id that was compared.
type FilesCheck struct {
	State   FilesState
	Current string
}

// CheckFiles compares generations/current with what the store renders, without
// changing anything. It takes the change lock shared and never waits for it: a
// change in progress reports FilesBusy rather than a false mismatch. The error
// explains FilesError, or a FilesMismatch caused by an unreadable current.
func (a *Admin) CheckFiles() (FilesCheck, error) {
	f, err := os.Open(a.lockPath())
	switch {
	case err == nil:
		defer f.Close()
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
			if errors.Is(err, syscall.EWOULDBLOCK) {
				return FilesCheck{State: FilesBusy}, nil
			}
			return FilesCheck{State: FilesError}, fmt.Errorf("take lock: %w", err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return FilesCheck{State: FilesError}, fmt.Errorf("open lock: %w", err)
	}
	snap, err := a.st.Snapshot()
	if err != nil {
		return FilesCheck{State: FilesError}, fmt.Errorf("read the account store: %w", err)
	}
	id, _ := os.Readlink(filepath.Join(a.gens, "current"))
	have, exists, err := a.currentFiles()
	if !exists {
		return FilesCheck{State: FilesNone}, nil
	}
	check := FilesCheck{State: FilesMismatch, Current: filepath.Base(id)}
	if err != nil {
		return check, err
	}
	if have.Equal(Render(snap)) {
		check.State = FilesMatch
	}
	return check, nil
}

// Config is the configuration the Admin was opened with.
func (a *Admin) Config() Config { return a.cfg }

// WatcherState is what the postfix watcher and pending changes have left in the
// state directory.
type WatcherState struct {
	Heartbeat    time.Time // zero when the watcher has not written one
	HeartbeatErr error     // reading it failed for a reason other than its absence
	Pending      string    // generation id waiting for the watcher; "" when none
	PendingAt    time.Time // when the pending link was made
	Status       string    // watcher/status; "" when missing or not a plain file
}

// Watcher reads the watcher's files and the pending link, changing nothing.
func (a *Admin) Watcher() WatcherState {
	var w WatcherState
	dir := watcherDir(a.cfg)
	if fi, err := os.Stat(filepath.Join(dir, "heartbeat")); err == nil {
		w.Heartbeat = fi.ModTime()
	} else if !errors.Is(err, os.ErrNotExist) {
		w.HeartbeatErr = err
	}
	pending := filepath.Join(a.gens, "pending")
	if target, err := os.Readlink(pending); err == nil {
		w.Pending, w.PendingAt = filepath.Base(target), a.cfg.Now()
		if fi, err := os.Lstat(pending); err == nil {
			w.PendingAt = fi.ModTime()
		}
	}
	w.Status = readWatcherStatus(filepath.Join(dir, "status"))
	return w
}

// Verdict is one watcher/status line: "<id> ok", or "<id> error <message>".
type Verdict struct {
	ID       string
	Rejected bool
	Message  string // why it was rejected
}

// ParseVerdict reads a watcher/status line. ok is false for anything else.
func ParseVerdict(line string) (v Verdict, ok bool) {
	id, rest, _ := strings.Cut(line, " ")
	word, msg, _ := strings.Cut(rest, " ")
	switch {
	case id == "":
		return v, false
	case rest == "ok":
		return Verdict{ID: id}, true
	case word == "error":
		return Verdict{ID: id, Rejected: true, Message: strings.TrimSpace(msg)}, true
	}
	return v, false
}

// readWatcherStatus returns the first few KiB of watcher/status, trimmed, or "" if it
// is missing or not a plain file. The internet-facing postfix container writes that
// directory, so the file may be a symlink to a secret, a FIFO or an endless device;
// none of those is followed or read.
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

// deploy writes and checks a generation, then waits for the watcher to accept it.
// On any failure the generation and pending link are gone and current is untouched.
func (a *Admin) deploy(files Files) (string, error) {
	id := files.ID(a.cfg.Now())
	tmp := filepath.Join(a.gens, ".tmp-"+id)
	if err := writeGeneration(tmp, files, a.cfg.DovecotUID); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	if err := SelfCheck(tmp, files); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	dir := filepath.Join(a.gens, id)
	if err := os.Rename(tmp, dir); err != nil {
		os.RemoveAll(tmp)
		return "", fmt.Errorf("install generation %s: %w", id, err)
	}
	if err := syncPath(a.gens); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if a.cfg.WatcherOff {
		return id, nil
	}
	if err := symlinkReplace(filepath.Join(a.gens, "pending"), id); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	if err := a.wait(id); err != nil {
		os.Remove(filepath.Join(a.gens, "pending"))
		os.RemoveAll(dir)
		return "", err
	}
	return id, nil
}

func (a *Admin) wait(id string) error {
	deadline := time.Now().Add(a.cfg.Timeout)
	for {
		if v, ok := ParseVerdict(readWatcherStatus(filepath.Join(watcherDir(a.cfg), "status"))); ok && v.ID == id {
			if !v.Rejected {
				return nil
			}
			return fmt.Errorf("postfix rejected generation %s: %s", id, v.Message)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s waiting for the postfix watcher to accept generation %s; is it running?", a.cfg.Timeout, id)
		}
		time.Sleep(a.cfg.Poll)
	}
}

func (a *Admin) promote(id string) error {
	if err := symlinkReplace(filepath.Join(a.gens, "current"), id); err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(a.gens, "pending")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove pending: %w", err)
	}
	a.prune()
	return nil
}

func (a *Admin) prune() {
	entries, err := os.ReadDir(a.gens)
	if err != nil {
		return
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// A .tmp- directory is a generation that failed part way; deploy holds the lock, so
		// none is in progress here.
		if strings.HasPrefix(e.Name(), ".tmp-") {
			os.RemoveAll(filepath.Join(a.gens, e.Name()))
			continue
		}
		if !strings.HasPrefix(e.Name(), ".") {
			ids = append(ids, e.Name())
		}
	}
	current, _ := os.Readlink(filepath.Join(a.gens, "current"))
	for len(ids) > keepGenerations {
		if ids[0] != current {
			os.RemoveAll(filepath.Join(a.gens, ids[0]))
		}
		ids = ids[1:]
	}
}

// writeGeneration writes every file and makes the result durable: the files are
// fsynced, then the directories that hold them. dovecot/users holds every password hash,
// so it is 0400 and owned by dovecotUID (see Config); everything else is 0644.
func writeGeneration(dir string, files Files, dovecotUID int) error {
	for _, name := range fileNames {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		mode, uid := os.FileMode(0o644), -1
		if name == FileUsers {
			mode = 0o400
			if dovecotUID > 0 {
				uid = dovecotUID
			}
		}
		if err := writeSynced(path, files[name], mode, uid); err != nil {
			return err
		}
	}
	for _, d := range []string{filepath.Join(dir, "dovecot"), filepath.Join(dir, "postfix"), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
		if err := syncPath(d); err != nil {
			return err
		}
	}
	return nil
}

// writeSynced writes content with mode and, unless uid is -1, that owner. The owner and
// mode are set before the content is written, so the file is never readable more widely.
func writeSynced(path, content string, mode os.FileMode, uid int) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	// Mode first: once the file is given away, changing its mode would need FOWNER too.
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if uid != -1 {
		if err := f.Chown(uid, -1); err != nil {
			f.Close()
			return fmt.Errorf("give %s to uid %d (the container needs the CHOWN capability): %w", path, uid, err)
		}
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// syncPath fsyncs a file or directory.
func syncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("fsync %s: %w", path, err)
	}
	return nil
}

func symlinkReplace(link, target string) error {
	tmp := link + ".tmp"
	os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, link); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncPath(filepath.Dir(link))
}
