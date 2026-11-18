package main

import (
	"cmp"
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
	"github.com/kspears/mailstack/internal/validate"
)

const importUsage = "import-mailcow [--dry-run] [--overwrite] [--skip-mailbox <address>]... [--acknowledge <item>[,<item>...]] [--bayes [--bayes-pattern <glob>]...] | import-mailcow --bayes-only [--dry-run] [--bayes-pattern <glob>]..."

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(v string) error {
	*l = append(*l, v)
	return nil
}

type importFlags struct {
	dryRun, overwrite, bayes, bayesOnly bool
	skip, acknowledge                   listFlag
	bayesPatterns                       listFlag
}

func parseImportFlags(args []string) (importFlags, error) {
	var f importFlags
	fs := flag.NewFlagSet("import-mailcow", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&f.dryRun, "dry-run", false, "")
	fs.BoolVar(&f.overwrite, "overwrite", false, "")
	fs.BoolVar(&f.bayes, "bayes", false, "")
	fs.BoolVar(&f.bayesOnly, "bayes-only", false, "")
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
	if f.bayesOnly {
		f.bayes = true
		if f.overwrite || len(f.skip) > 0 || len(f.acknowledge) > 0 {
			return f, usageError("import-mailcow: --bayes-only changes no accounts, so it takes no --overwrite, --skip-mailbox or --acknowledge")
		}
	}
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

// importMailcow reads, plans and validates everything before it writes anything,
// then writes in this order: the account store (one transaction, one generation),
// the DKIM keys, and last the Bayes statistics, which can be repeated on their own.
func (e *env) importMailcow(args []string) error {
	f, err := parseImportFlags(args)
	if err != nil {
		return err
	}
	src, closeSrc, err := e.openMailcow(f.bayesOnly)
	if err != nil {
		return err
	}
	defer closeSrc()
	if f.bayesOnly {
		return e.copyBayes(f, src)
	}
	cfg, err := generate.ConfigFromEnv(e.getenv)
	if err != nil {
		return err
	}
	dkimDir := cmp.Or(e.getenv("MAILCTL_DKIM_DIR"), filepath.Join(cfg.State, "dkim"))

	data, err := src.Read(context.Background())
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
	if err := validate.Consistency(snap); err != nil {
		return err
	}
	if err := mailcow.CheckKeyTargets(dkimDir, rep.DKIM, f.overwrite); err != nil {
		return err
	}
	if f.dryRun {
		if err := e.copyBayes(f, src); err != nil {
			return err
		}
		fmt.Fprintln(e.stdout, "ok: dry run; nothing written")
		return nil
	}

	staged, err := mailcow.StageKeys(dkimDir, rep.DKIM)
	if err != nil {
		return err
	}
	admin, err := generate.Open(cfg, f.overwrite)
	if err != nil {
		os.RemoveAll(staged)
		return err
	}
	replaced, err := admin.Import(e.actor(), snap, f.overwrite)
	admin.Close()
	if err != nil {
		os.RemoveAll(staged)
		return err
	}
	if replaced != "" {
		fmt.Fprintf(e.stdout, "old store kept at %s\n", replaced)
	}
	oldKeys, err := mailcow.InstallKeys(staged, dkimDir, cfg.Now())
	if err != nil {
		return fmt.Errorf("the account store was imported but the DKIM key files could not be installed: %w; the staged keys are kept in %s, move them to %s by hand", err, staged, dkimDir)
	}
	if oldKeys != "" {
		fmt.Fprintf(e.stdout, "old DKIM keys kept at %s\n", oldKeys)
	}
	fmt.Fprintf(e.stdout, "ok: imported %d domains, %d mailboxes, %d aliases\n", rep.Domains, rep.Mailboxes, rep.Aliases)
	if err := e.copyBayes(f, src); err != nil {
		return fmt.Errorf("the accounts and DKIM keys are imported; only the Bayes statistics failed: %w; re-run with --bayes-only", err)
	}
	return nil
}

func (e *env) required(name string) (string, error) {
	v := e.getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s is not set", name)
	}
	return v, nil
}

// openMailcow connects to mailcow's MySQL (unless redisOnly) and Redis. The
// connection settings come from the environment and are never printed. The two
// directory settings tell the import where mailcow's files are; the mail root
// defaults to MAILCTL_MAIL_ROOT, which is right when mailcow's mail volume is
// mounted at the same path.
func (e *env) openMailcow(redisOnly bool) (mailcow.Live, func(), error) {
	live := mailcow.Live{
		MailRoot:        cmp.Or(e.getenv("MAILCOW_VMAIL_ROOT"), e.getenv("MAILCTL_MAIL_ROOT")),
		RspamdCustomDir: e.getenv("MAILCOW_RSPAMD_CUSTOM_DIR"),
	}
	addr, err := e.required("MAILCOW_REDIS_ADDR")
	if err != nil {
		return live, nil, err
	}
	if !redisOnly {
		dsn, err := e.required("MAILCOW_MYSQL_DSN")
		if err != nil {
			return live, nil, err
		}
		if live.DB, err = sql.Open("mysql", dsn); err != nil {
			return live, nil, errors.New("MAILCOW_MYSQL_DSN is not a valid go-sql-driver DSN")
		}
	}
	if live.Redis, err = mailcow.DialRedis(addr, e.getenv("MAILCOW_REDIS_PASSWORD"), true); err != nil {
		if live.DB != nil {
			live.DB.Close()
		}
		return live, nil, err
	}
	return live, func() {
		if live.DB != nil {
			live.DB.Close()
		}
		live.Redis.Close()
	}, nil
}

// copyBayes copies rspamd statistics when asked; on a dry run it only counts.
func (e *env) copyBayes(f importFlags, src mailcow.Live) error {
	if !f.bayes {
		return nil
	}
	var dst *mailcow.Redis
	if !f.dryRun {
		addr, err := e.required("MAILSTACK_REDIS_ADDR")
		if err != nil {
			return err
		}
		if dst, err = mailcow.DialRedis(addr, e.getenv("MAILSTACK_REDIS_PASSWORD"), false); err != nil {
			return err
		}
		defer dst.Close()
	}
	counts, err := mailcow.CopyKeys(src.Redis, dst, f.bayesPatterns)
	if err != nil {
		return err
	}
	verb := "copied"
	if f.dryRun {
		verb = "would copy"
	}
	for _, c := range counts {
		fmt.Fprintf(e.stdout, "bayes keys %s: %s %d\n", c.Pattern, verb, c.Keys)
	}
	return nil
}
