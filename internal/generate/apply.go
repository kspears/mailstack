package generate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

const keepGenerations = 10

// Config is the on-disk layout and apply behaviour. See the README for the env vars.
type Config struct {
	State      string
	MailRoot   string
	UID, GID   int
	WatcherOff bool
	Timeout    time.Duration
	Poll       time.Duration
	Now        func() time.Time
}

// ConfigFromEnv reads MAILCTL_* settings through getenv.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	cfg := Config{
		State:      orDefault(getenv("MAILCTL_STATE"), "/data/mailstack"),
		MailRoot:   orDefault(getenv("MAILCTL_MAIL_ROOT"), "/var/vmail"),
		UID:        5000,
		GID:        5000,
		WatcherOff: getenv("MAILCTL_WATCHER") == "off",
		Timeout:    30 * time.Second,
		Poll:       100 * time.Millisecond,
		Now:        time.Now,
	}
	for _, v := range []struct {
		name string
		dst  *int
	}{{"MAILCTL_MAIL_UID", &cfg.UID}, {"MAILCTL_MAIL_GID", &cfg.GID}} {
		if s := getenv(v.name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < 0 {
				return cfg, fmt.Errorf("%s=%q is not a valid id", v.name, s)
			}
			*v.dst = n
		}
	}
	if s := getenv("MAILCTL_APPLY_TIMEOUT"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			return cfg, fmt.Errorf("MAILCTL_APPLY_TIMEOUT=%q is not a positive duration such as 30s", s)
		}
		cfg.Timeout = d
	}
	return cfg, nil
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Admin owns the store and applies every change to it.
type Admin struct {
	cfg  Config
	st   *store.Store
	gens string
}

// Open creates the state directory if needed and opens the store.
func Open(cfg Config) (*Admin, error) {
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
	st, err := store.Open(filepath.Join(cfg.State, "store.db"))
	if err != nil {
		return nil, err
	}
	return &Admin{cfg: cfg, st: st, gens: gens}, nil
}

func (a *Admin) Close() error { return a.st.Close() }

func (a *Admin) Snapshot() (store.Snapshot, error) { return a.st.Snapshot() }

func (a *Admin) Log() ([]store.LogEntry, error) { return a.st.Log() }

// MailPath is where a mailbox's mail lives on disk.
func (a *Admin) MailPath(address string) string {
	local, domain := validate.Split(address)
	return filepath.Join(a.cfg.MailRoot, domain, local)
}

type change struct{ action, subject, summary string }

// change runs fn in a store transaction and applies the result as a new
// generation. Either both the store and the daemons' files move, or neither.
func (a *Admin) change(actor string, fn func(tx *store.Tx, snap store.Snapshot) (change, error)) (string, error) {
	unlock, err := a.lock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := a.ensureCurrent(); err != nil {
		return "", err
	}
	tx, err := a.st.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	before, err := tx.Snapshot()
	if err != nil {
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
	id, err := a.deploy(Render(after, a.cfg))
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

// Apply re-renders from the store and applies even if nothing changed.
func (a *Admin) Apply(actor string) (string, error) {
	return a.change(actor, func(*store.Tx, store.Snapshot) (change, error) {
		return change{"apply", "-", "applied current account set"}, nil
	})
}

func (a *Admin) lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(a.cfg.State, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("take lock: %w", err)
	}
	return func() { f.Close() }, nil
}

// ensureCurrent re-renders when current is missing or no longer matches the store.
func (a *Admin) ensureCurrent() error {
	snap, err := a.st.Snapshot()
	if err != nil {
		return err
	}
	want := Render(snap, a.cfg)
	if have, err := Read(filepath.Join(a.gens, "current")); err == nil && have.Equal(want) {
		return nil
	}
	id, err := a.deploy(want)
	if err != nil {
		return fmt.Errorf("resync generated files with the store: %w", err)
	}
	return a.promote(id)
}

// deploy writes and checks a generation, then waits for the watcher to accept it.
// On any failure the generation and pending link are gone and current is untouched.
func (a *Admin) deploy(files Files) (string, error) {
	id := files.ID(a.cfg.Now())
	tmp := filepath.Join(a.gens, ".tmp-"+id)
	if err := writeGeneration(tmp, files); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	if err := SelfCheck(tmp); err != nil {
		os.RemoveAll(tmp)
		return "", err
	}
	dir := filepath.Join(a.gens, id)
	if err := os.Rename(tmp, dir); err != nil {
		os.RemoveAll(tmp)
		return "", fmt.Errorf("install generation %s: %w", id, err)
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
		if b, err := os.ReadFile(filepath.Join(a.gens, "status")); err == nil {
			got, rest, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
			if got == id {
				if rest == "ok" {
					return nil
				}
				if msg, isErr := strings.CutPrefix(rest, "error"); isErr {
					return fmt.Errorf("postfix rejected generation %s: %s", id, strings.TrimSpace(msg))
				}
			}
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
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	current, _ := os.Readlink(filepath.Join(a.gens, "current"))
	for len(ids) > keepGenerations {
		if ids[0] != current {
			os.RemoveAll(filepath.Join(a.gens, ids[0]))
		}
		ids = ids[1:]
	}
}

func writeGeneration(dir string, files Files) error {
	for _, name := range fileNames {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(files[name]), 0o644); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o644); err != nil {
			return err
		}
	}
	for _, d := range []string{dir, filepath.Join(dir, "dovecot"), filepath.Join(dir, "postfix")} {
		if err := os.Chmod(d, 0o755); err != nil {
			return err
		}
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
	return nil
}
