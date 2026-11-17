// Package generate renders the lookup files postfix and dovecot read, and
// applies them all-or-nothing.
package generate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

const (
	FileUsers       = "dovecot/users"
	FileDomains     = "postfix/domains"
	FileMailboxes   = "postfix/mailboxes"
	FileAliases     = "postfix/aliases"
	FileSenderLogin = "postfix/sender_login"
)

var fileNames = []string{FileUsers, FileDomains, FileMailboxes, FileAliases, FileSenderLogin}

// Files maps a path relative to a generation directory to its content.
type Files map[string]string

// Render produces every generated file for snap. snap must be consistent.
func Render(snap store.Snapshot, cfg Config) Files {
	var users, domains, mailboxes, aliases []string
	for _, d := range snap.Domains {
		domains = append(domains, d+" OK")
	}
	for _, m := range snap.Mailboxes {
		if m.State == store.Disabled {
			continue
		}
		local, domain := validate.Split(m.Address)
		line := fmt.Sprintf("%s:%s:%d:%d::%s::", m.Address, m.Hash, cfg.UID, cfg.GID, filepath.Join(cfg.MailRoot, domain, local))
		if m.State == store.ReceiveOnly {
			line += "nologin=y"
		}
		users = append(users, line)
		mailboxes = append(mailboxes, m.Address+" OK")
	}
	for _, a := range snap.Aliases {
		aliases = append(aliases, a.Address+" "+strings.Join(a.Targets, ","))
	}
	return Files{
		FileUsers:       join(users),
		FileDomains:     join(domains),
		FileMailboxes:   join(mailboxes),
		FileAliases:     join(aliases),
		FileSenderLogin: join(senderLogin(snap)),
	}
}

func senderLogin(snap store.Snapshot) []string {
	active := map[string]bool{}
	for _, m := range snap.Mailboxes {
		if m.State == store.Active {
			active[m.Address] = true
		}
	}
	targets := map[string][]string{}
	for _, a := range snap.Aliases {
		targets[a.Address] = a.Targets
	}
	logins := map[string]map[string]bool{}
	allow := func(sender, login string) {
		if !active[login] {
			return
		}
		if logins[sender] == nil {
			logins[sender] = map[string]bool{}
		}
		logins[sender][login] = true
	}
	for m := range active {
		allow(m, m)
	}
	for _, g := range snap.Grants {
		allow(g.Address, g.Mailbox)
	}
	for _, a := range snap.Aliases {
		for _, m := range deliversTo(a.Address, targets, active, map[string]bool{}) {
			allow(a.Address, m)
		}
	}
	senders := make([]string, 0, len(logins))
	for s := range logins {
		senders = append(senders, s)
	}
	sort.Strings(senders)
	lines := make([]string, 0, len(senders))
	for _, s := range senders {
		l := make([]string, 0, len(logins[s]))
		for login := range logins[s] {
			l = append(l, login)
		}
		sort.Strings(l)
		lines = append(lines, s+" "+strings.Join(l, ","))
	}
	return lines
}

// deliversTo returns the active mailboxes reachable from alias through chains of aliases.
func deliversTo(alias string, targets map[string][]string, active, seen map[string]bool) []string {
	if seen[alias] {
		return nil
	}
	seen[alias] = true
	var out []string
	for _, t := range targets[alias] {
		if active[t] {
			out = append(out, t)
			continue
		}
		out = append(out, deliversTo(t, targets, active, seen)...)
	}
	return out
}

func join(lines []string) string {
	sort.Strings(lines)
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// ID names a generation: a sortable UTC timestamp plus a short content hash.
func (f Files) ID(at time.Time) string {
	h := sha256.New()
	for _, name := range fileNames {
		fmt.Fprintf(h, "%s\x00%s\x00", name, f[name])
	}
	return at.UTC().Format("20060102T150405.000000Z") + "-" + hex.EncodeToString(h.Sum(nil))[:8]
}

// Equal reports whether two file sets have identical content.
func (f Files) Equal(g Files) bool {
	return len(f) == len(g) && !slices.ContainsFunc(fileNames, func(n string) bool { return f[n] != g[n] })
}
