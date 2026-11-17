package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/mailcow"
	"github.com/kspears/mailstack/internal/store"
)

const importUsage = "import-mailcow [--dry-run] [--overwrite] [--skip-mailbox <address>]... [--acknowledge <item>[,<item>...]] [--bayes [--bayes-pattern <glob>]...]"

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

type importFlags struct {
	dryRun, overwrite, bayes bool
	skip, acknowledge        listFlag
	bayesPatterns            listFlag
}

func parseImportFlags(args []string) (importFlags, error) {
	var f importFlags
	fs := flag.NewFlagSet("import-mailcow", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&f.dryRun, "dry-run", false, "")
	fs.BoolVar(&f.overwrite, "overwrite", false, "")
	fs.BoolVar(&f.bayes, "bayes", false, "")
	fs.Var(&f.skip, "skip-mailbox", "")
	fs.Var(&f.acknowledge, "acknowledge", "")
	fs.Var(&f.bayesPatterns, "bayes-pattern", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return f, usageError(importUsage)
	}
	var names []string
	for _, a := range f.acknowledge {
		names = append(names, strings.Split(a, ",")...)
	}
	f.acknowledge = names
	if len(f.bayesPatterns) > 0 && !f.bayes {
		return f, usageError(importUsage)
	}
	if len(f.bayesPatterns) == 0 {
		f.bayesPatterns = mailcow.DefaultBayesPatterns
	}
	if _, err := mailcow.ParseAcknowledge(f.acknowledge); err != nil {
		return f, usageError("import-mailcow: " + err.Error())
	}
	return f, nil
}

func (e *env) importMailcow(args []string) error {
	f, err := parseImportFlags(args)
	if err != nil {
		return err
	}
	cfg, err := generate.ConfigFromEnv(e.getenv)
	if err != nil {
		return err
	}
	storePath := filepath.Join(cfg.State, "store.db")
	occupied, err := storeHoldsAccounts(storePath)
	if err != nil {
		return err
	}
	if occupied && !f.overwrite {
		return fmt.Errorf("a store already exists at %s; pass --overwrite to replace it", storePath)
	}
	dkimDir := e.getenv("MAILCTL_DKIM_DIR")
	if dkimDir == "" {
		dkimDir = filepath.Join(cfg.State, "dkim")
	}

	src, closeSrc, err := e.openMailcow()
	if err != nil {
		return err
	}
	defer closeSrc()
	ctx := context.Background()
	data, err := src.Read(ctx)
	if err != nil {
		return err
	}
	snap, rep, err := mailcow.Plan(data, mailcow.Options{
		SkipMailboxes: f.skip,
		Acknowledge:   f.acknowledge,
		RelayHost:     e.getenv("MAILSTACK_RELAY_HOST"),
	})
	rep.Write(e.stdout)
	if err != nil {
		return err
	}
	if err := mailcow.CheckKeyTargets(dkimDir, rep.DKIM, f.overwrite); err != nil {
		return err
	}
	counts := fmt.Sprintf("%d domains, %d mailboxes, %d aliases", rep.Domains, rep.Mailboxes, rep.Aliases)

	bayes, err := e.copyBayes(f, src)
	if err != nil {
		return err
	}
	verb := "copied"
	if f.dryRun {
		verb = "would copy"
	}
	for _, c := range bayes {
		fmt.Fprintf(e.stdout, "bayes keys %s: %s %d\n", c.Pattern, verb, c.Keys)
	}
	if f.dryRun {
		fmt.Fprintln(e.stdout, "ok: dry run; nothing written")
		return nil
	}
	return e.writeImport(cfg, storePath, dkimDir, snap, rep, occupied, counts)
}

func (e *env) writeImport(cfg generate.Config, storePath, dkimDir string, snap store.Snapshot, rep mailcow.Report, occupied bool, counts string) error {
	staged, err := mailcow.StageKeys(dkimDir, rep.DKIM)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)

	var replaced string
	if occupied {
		replaced = fmt.Sprintf("%s.replaced-%s", storePath, cfg.Now().UTC().Format("20060102T150405Z"))
		if err := os.Rename(storePath, replaced); err != nil {
			return fmt.Errorf("move the old store aside: %w", err)
		}
	}
	if err := e.importStore(cfg, snap); err != nil {
		if replaced != "" {
			if rerr := restoreStore(replaced, storePath); rerr != nil {
				return fmt.Errorf("%w; the old store is at %s and could not be moved back: %v", err, replaced, rerr)
			}
		}
		return err
	}
	if err := mailcow.InstallKeys(staged, dkimDir); err != nil {
		return fmt.Errorf("the store was imported but the DKIM key files could not be moved from %s to %s: %w; move them by hand", staged, dkimDir, err)
	}
	if replaced != "" {
		fmt.Fprintf(e.stdout, "old store kept at %s\n", replaced)
	}
	fmt.Fprintf(e.stdout, "ok: imported %s\n", counts)
	return nil
}

func (e *env) importStore(cfg generate.Config, snap store.Snapshot) error {
	admin, err := generate.Open(cfg)
	if err != nil {
		return err
	}
	defer admin.Close()
	_, err = admin.Import(e.actor(), snap)
	return err
}

// restoreStore puts the old store back after a failed import, discarding the half-made one.
func restoreStore(replaced, storePath string) error {
	if err := os.Remove(storePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(replaced, storePath)
}

func storeHoldsAccounts(path string) (bool, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	st, err := store.Open(path)
	if err != nil {
		return false, err
	}
	defer st.Close()
	snap, err := st.Snapshot()
	if err != nil {
		return false, err
	}
	return len(snap.Domains)+len(snap.Mailboxes)+len(snap.Aliases) > 0, nil
}

func (e *env) required(name string) (string, error) {
	v := e.getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	return v, nil
}

// openMailcow connects to mailcow's MySQL and Redis. The connection settings
// come from the environment and are never printed.
func (e *env) openMailcow() (mailcow.Live, func(), error) {
	var live mailcow.Live
	dsn, err := e.required("MAILCOW_MYSQL_DSN")
	if err != nil {
		return live, nil, err
	}
	addr, err := e.required("MAILCOW_REDIS_ADDR")
	if err != nil {
		return live, nil, err
	}
	if live.DB, err = sql.Open("mysql", dsn); err != nil {
		return live, nil, errors.New("MAILCOW_MYSQL_DSN is not a valid go-sql-driver DSN")
	}
	if live.Redis, err = mailcow.DialRedis(addr, e.getenv("MAILCOW_REDIS_PASSWORD"), true); err != nil {
		live.DB.Close()
		return live, nil, err
	}
	return live, func() { live.DB.Close(); live.Redis.Close() }, nil
}

// copyBayes copies rspamd statistics when asked; on a dry run it only counts.
func (e *env) copyBayes(f importFlags, src mailcow.Live) ([]mailcow.PatternCount, error) {
	if !f.bayes {
		return nil, nil
	}
	var dst *mailcow.Redis
	if !f.dryRun {
		addr, err := e.required("MAILSTACK_REDIS_ADDR")
		if err != nil {
			return nil, err
		}
		if dst, err = mailcow.DialRedis(addr, e.getenv("MAILSTACK_REDIS_PASSWORD"), false); err != nil {
			return nil, err
		}
		defer dst.Close()
	}
	return mailcow.CopyKeys(src.Redis, dst, f.bayesPatterns)
}
