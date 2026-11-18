package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

type env struct {
	getenv func(string) string
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

type usageError string

func (u usageError) Error() string { return "usage: mailctl " + string(u) }

const usage = `mailctl mailbox list|add|passwd|state|remove ...
       mailctl alias list|add|set|remove ...
       mailctl sendas list|add|remove ...
       mailctl domain list|add|remove ...
       mailctl admin list|add|reset|remove ...
       mailctl log | apply [--publish-empty] | serve | import-mailcow | learn --controller <url> --password-file <path> spam|ham | install-self <directory>`

func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{getenv, stdin, stdout, stderr}
	if err := e.dispatch(args); err != nil {
		fmt.Fprintln(stderr, "error: "+err.Error())
		var u usageError
		if errors.As(err, &u) {
			return 2
		}
		return 1
	}
	return 0
}

func (e *env) actor() string {
	for _, v := range []string{"SUDO_USER", "USER"} {
		if u := e.getenv(v); u != "" {
			return "cli:" + u
		}
	}
	return "cli:unknown"
}

func (e *env) dispatch(args []string) error {
	if len(args) == 0 {
		return usageError(usage)
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "serve":
		return e.serve(rest)
	case "import-mailcow":
		return e.importMailcow(rest)
	case "learn":
		return e.learn(rest)
	case "install-self":
		return e.installSelf(rest)
	case "apply":
		return e.apply(rest)
	}
	if !slices.Contains([]string{"mailbox", "alias", "sendas", "domain", "admin", "log"}, cmd) {
		return usageError(usage)
	}
	cfg, err := generate.ConfigFromEnv(e.getenv)
	if err != nil {
		return err
	}
	admin, err := generate.Open(cfg, false)
	if err != nil {
		return err
	}
	defer admin.Close()
	switch cmd {
	case "mailbox":
		return e.mailbox(admin, rest)
	case "alias":
		return e.alias(admin, rest)
	case "sendas":
		return e.sendas(admin, rest)
	case "domain":
		return e.domain(admin, rest)
	case "admin":
		return e.adminAccounts(admin, rest)
	default:
		return e.log(admin, rest)
	}
}

// apply is the one command besides the mailcow import that may start from a lost
// store, and only with --publish-empty.
func (e *env) apply(args []string) error {
	var publishEmpty bool
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&publishEmpty, "publish-empty", false, "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return usageError("apply [--publish-empty]")
	}
	cfg, err := generate.ConfigFromEnv(e.getenv)
	if err != nil {
		return err
	}
	admin, err := generate.Open(cfg, publishEmpty)
	if err != nil {
		return err
	}
	defer admin.Close()
	return e.ok(admin.Apply(e.actor(), publishEmpty))
}

func (e *env) ok(summary string, err error) error {
	if err != nil {
		return err
	}
	fmt.Fprintln(e.stdout, "ok: "+summary)
	return nil
}

func (e *env) mailbox(a *generate.Admin, args []string) error {
	const u = "mailbox list|add <address> [--name <display name>] [--adopt-existing-mail]|passwd <address>|state <address> active|receive-only|disabled|remove <address>"
	if len(args) == 0 {
		return usageError(u)
	}
	var name string
	var adopt bool
	fs := flag.NewFlagSet("mailbox", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if args[0] == "add" {
		fs.StringVar(&name, "name", "", "")
		fs.BoolVar(&adopt, "adopt-existing-mail", false, "")
	}
	pos, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return usageError(u)
	}
	actor := e.actor()
	switch {
	case args[0] == "list" && len(pos) == 0:
		return e.list(a, func(w io.Writer, snap store.Snapshot) {
			for _, m := range snap.Mailboxes {
				fmt.Fprintf(w, "%s\t%s\t%s\n", m.Address, m.State, m.Name)
			}
		})
	case args[0] == "add" && len(pos) == 1:
		pw, err := e.newPassword()
		if err != nil {
			return err
		}
		return e.ok(a.AddMailbox(actor, pos[0], name, pw, adopt))
	case args[0] == "passwd" && len(pos) == 1:
		pw, err := e.newPassword()
		if err != nil {
			return err
		}
		return e.ok(a.SetPassword(actor, pos[0], pw))
	case args[0] == "state" && len(pos) == 2:
		state, err := store.ParseState(pos[1])
		if err != nil {
			return err
		}
		return e.ok(a.SetMailboxState(actor, pos[0], state))
	case args[0] == "remove" && len(pos) == 1:
		return e.ok(a.RemoveMailbox(actor, pos[0]))
	}
	return usageError(u)
}

func (e *env) alias(a *generate.Admin, args []string) error {
	const u = "alias list|add <address> <target>[,<target>...]|set <address> <target>[,<target>...]|remove <address>"
	if len(args) == 0 {
		return usageError(u)
	}
	actor, rest := e.actor(), args[1:]
	switch {
	case args[0] == "list" && len(rest) == 0:
		return e.list(a, func(w io.Writer, snap store.Snapshot) {
			for _, al := range snap.Aliases {
				fmt.Fprintf(w, "%s -> %s\n", al.Address, strings.Join(al.Targets, ","))
			}
		})
	case args[0] == "add" && len(rest) == 2:
		return e.ok(a.AddAlias(actor, rest[0], strings.Split(rest[1], ",")))
	case args[0] == "set" && len(rest) == 2:
		return e.ok(a.SetAliasTargets(actor, rest[0], strings.Split(rest[1], ",")))
	case args[0] == "remove" && len(rest) == 1:
		return e.ok(a.RemoveAlias(actor, rest[0]))
	}
	return usageError(u)
}

func (e *env) sendas(a *generate.Admin, args []string) error {
	const u = "sendas list|add <mailbox> <address>|remove <mailbox> <address>"
	if len(args) == 0 {
		return usageError(u)
	}
	actor, rest := e.actor(), args[1:]
	switch {
	case args[0] == "list" && len(rest) == 0:
		return e.list(a, func(w io.Writer, snap store.Snapshot) {
			for _, g := range snap.Grants {
				fmt.Fprintf(w, "%s\t%s\n", g.Mailbox, g.Address)
			}
		})
	case args[0] == "add" && len(rest) == 2:
		return e.ok(a.AddSendAs(actor, rest[0], rest[1]))
	case args[0] == "remove" && len(rest) == 2:
		return e.ok(a.RemoveSendAs(actor, rest[0], rest[1]))
	}
	return usageError(u)
}

func (e *env) domain(a *generate.Admin, args []string) error {
	const u = "domain list|add <domain>|remove <domain>"
	if len(args) == 0 {
		return usageError(u)
	}
	actor, rest := e.actor(), args[1:]
	switch {
	case args[0] == "list" && len(rest) == 0:
		return e.list(a, func(w io.Writer, snap store.Snapshot) {
			for _, d := range snap.Domains {
				fmt.Fprintln(w, d)
			}
		})
	case args[0] == "add" && len(rest) == 1:
		return e.ok(a.AddDomain(actor, rest[0]))
	case args[0] == "remove" && len(rest) == 1:
		return e.ok(a.RemoveDomain(actor, rest[0]))
	}
	return usageError(u)
}

// list prints the rows that rows writes from the current account set; cells are
// tab-separated and aligned.
func (e *env) list(a *generate.Admin, rows func(w io.Writer, snap store.Snapshot)) error {
	snap, err := a.Snapshot()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
	rows(w, snap)
	return w.Flush()
}

func (e *env) log(a *generate.Admin, args []string) error {
	if len(args) != 0 {
		return usageError("log")
	}
	entries, err := a.Log()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
	for _, l := range entries {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", l.Time.Format(time.RFC3339), l.Actor, l.Action, l.Subject)
	}
	return w.Flush()
}

// parseInterspersed parses flags that may appear before, between or after positional arguments.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// newPassword prompts twice without echo on a terminal, or reads two lines from stdin otherwise.
func (e *env) newPassword() (string, error) {
	read := e.passwordReader()
	first, err := read("Password: ")
	if err != nil {
		return "", err
	}
	second, err := read("Repeat password: ")
	if err != nil {
		return "", err
	}
	return validate.SamePassword(first, second)
}

// passwordReader returns a reader of one password: a prompt on a terminal, the
// next stdin line otherwise.
func (e *env) passwordReader() func(label string) (string, error) {
	if f, ok := e.stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return func(label string) (string, error) {
			fmt.Fprint(e.stderr, label)
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(e.stderr)
			if err != nil {
				return "", fmt.Errorf("read password: %w", err)
			}
			return string(b), nil
		}
	}
	r := bufio.NewReader(e.stdin)
	return func(string) (string, error) { return readLine(r) }
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && (!errors.Is(err, io.EOF) || line == "") {
		return "", errors.New("expected the password twice on stdin, one per line")
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// adminAccounts manages who may sign in to the UI. It is deliberately not in
// the UI: making or resetting an admin needs a shell on the server.
func (e *env) adminAccounts(a *generate.Admin, args []string) error {
	const u = "admin list|add <address>|reset <address>|remove <address>"
	if len(args) == 0 {
		return usageError(u)
	}
	rest := args[1:]
	if args[0] == "list" && len(rest) == 0 {
		admins, err := a.Store().Admins()
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(e.stdout, 0, 4, 2, ' ', 0)
		for _, adm := range admins {
			state := "not enrolled"
			if adm.Enrolled {
				state = "enrolled"
			}
			fmt.Fprintf(w, "%s\t%s\t%d passkeys\n", adm.Address, state, adm.Passkeys)
		}
		return w.Flush()
	}
	if len(rest) != 1 || !slices.Contains([]string{"add", "reset", "remove"}, args[0]) {
		return usageError(u)
	}
	site, err := e.site()
	if err != nil {
		return err
	}
	service, err := site.service(a, nil)
	if err != nil {
		return err
	}
	address := strings.ToLower(strings.TrimSpace(rest[0]))
	var token, done string
	switch args[0] {
	case "add":
		token, err = service.AddAdmin(e.actor(), address)
		done = "added admin " + address
	case "reset":
		token, err = service.ResetAdmin(e.actor(), address)
		done = "reset admin " + address + "; the password, authenticator, passkeys and sessions are gone"
	default:
		return e.ok("removed admin "+address, service.RemoveAdmin(e.actor(), address))
	}
	if err != nil {
		return err
	}
	// The link is the only copy: the store keeps a hash of it.
	fmt.Fprintf(e.stdout, "ok: %s\nEnrolment link, valid for 24 hours and shown only now. Send it by a channel you trust:\n%s/enrol?t=%s\n", done, site.origin(), token)
	return nil
}
