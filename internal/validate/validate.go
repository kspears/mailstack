// Package validate holds the account rules: address syntax, collisions,
// alias resolution and loops.
package validate

import (
	"fmt"
	"slices"
	"strings"

	"github.com/kspears/mailstack/internal/store"
)

const (
	MinPasswordLen = 12
	maxPasswordLen = 72 // bcrypt ignores or rejects anything longer
)

const localChars = "abcdefghijklmnopqrstuvwxyz0123456789._+=-"

// Password checks length only; there are no composition rules.
func Password(pw string) error {
	if len(pw) < MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLen)
	}
	if len(pw) > maxPasswordLen {
		return fmt.Errorf("password must be at most %d bytes", maxPasswordLen)
	}
	return nil
}

// Domain lower-cases and validates a hostname with at least two labels.
func Domain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(s))
	if len(d) == 0 || len(d) > 253 {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("invalid domain %q: need at least two labels", s)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", fmt.Errorf("invalid domain %q", s)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid domain %q: use ASCII letters, digits and hyphens (punycode for IDNs)", s)
			}
		}
	}
	return d, nil
}

// Address lower-cases and validates local@domain. Catch-alls are refused.
func Address(s string) (string, error) {
	a := strings.ToLower(strings.TrimSpace(s))
	local, domain, ok := strings.Cut(a, "@")
	if !ok || strings.Contains(domain, "@") {
		return "", fmt.Errorf("invalid address %q: expected local@domain", s)
	}
	if local == "" || local == "*" {
		return "", fmt.Errorf("invalid address %q: catch-all addresses are not supported", s)
	}
	if len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", fmt.Errorf("invalid address %q: bad local part", s)
	}
	for _, c := range local {
		if !strings.ContainsRune(localChars, c) {
			return "", fmt.Errorf("invalid address %q: local part may only use a-z, 0-9 and . _ + = -", s)
		}
	}
	if _, err := Domain(domain); err != nil {
		return "", fmt.Errorf("invalid address %q: bad domain", s)
	}
	return a, nil
}

// Split returns the local part and domain of a validated address.
func Split(address string) (local, domain string) {
	local, domain, _ = strings.Cut(address, "@")
	return
}

// Consistency checks a whole snapshot and returns the first problem found.
func Consistency(s store.Snapshot) error {
	hosted := map[string]bool{}
	for _, d := range s.Domains {
		hosted[d] = true
	}
	mailboxes := map[string]store.Mailbox{}
	for _, m := range s.Mailboxes {
		if err := inHostedDomain(m.Address, hosted); err != nil {
			return err
		}
		mailboxes[m.Address] = m
	}
	aliases := map[string][]string{}
	for _, a := range s.Aliases {
		if err := inHostedDomain(a.Address, hosted); err != nil {
			return err
		}
		if _, dup := mailboxes[a.Address]; dup {
			return fmt.Errorf("%s is a mailbox, so an alias cannot use that address", a.Address)
		}
		if len(a.Targets) == 0 {
			return fmt.Errorf("alias %s has no targets", a.Address)
		}
		aliases[a.Address] = a.Targets
	}
	for _, a := range s.Aliases {
		seen := map[string]bool{}
		for _, t := range a.Targets {
			if _, err := Address(t); err != nil {
				return fmt.Errorf("alias %s: %w", a.Address, err)
			}
			if seen[t] {
				return fmt.Errorf("alias %s lists target %s twice", a.Address, t)
			}
			seen[t] = true
			if err := resolves(a.Address, t, hosted, mailboxes, aliases); err != nil {
				return err
			}
		}
	}
	if err := findLoop(s.Aliases, aliases); err != nil {
		return err
	}
	for _, g := range s.Grants {
		if _, ok := mailboxes[g.Mailbox]; !ok {
			return fmt.Errorf("send-as grant for %s: no such mailbox", g.Mailbox)
		}
		if err := inHostedDomain(g.Address, hosted); err != nil {
			return err
		}
	}
	return nil
}

func inHostedDomain(address string, hosted map[string]bool) error {
	if _, err := Address(address); err != nil {
		return err
	}
	_, domain := Split(address)
	if !hosted[domain] {
		return fmt.Errorf("%s is in %s, which is not a hosted domain; add it with: mailctl domain add %s", address, domain, domain)
	}
	return nil
}

func resolves(alias, target string, hosted map[string]bool, mailboxes map[string]store.Mailbox, aliases map[string][]string) error {
	_, domain := Split(target)
	if !hosted[domain] {
		return nil
	}
	if m, ok := mailboxes[target]; ok {
		if m.State == store.Disabled {
			return fmt.Errorf("alias %s targets %s, which is disabled and cannot receive mail", alias, target)
		}
		return nil
	}
	if _, ok := aliases[target]; ok {
		return nil
	}
	return fmt.Errorf("alias %s targets %s, which is in a hosted domain but is not a mailbox or alias", alias, target)
}

func findLoop(list []store.Alias, aliases map[string][]string) error {
	const visiting, done = 1, 2
	state := map[string]int{}
	var path []string
	var visit func(a string) error
	visit = func(a string) error {
		switch state[a] {
		case done:
			return nil
		case visiting:
			start := slices.Index(path, a)
			return fmt.Errorf("alias loop: %s", strings.Join(append(path[start:], a), " -> "))
		}
		state[a] = visiting
		path = append(path, a)
		for _, t := range aliases[a] {
			if _, isAlias := aliases[t]; !isAlias {
				continue
			}
			if err := visit(t); err != nil {
				return err
			}
		}
		path = path[:len(path)-1]
		state[a] = done
		return nil
	}
	for _, a := range list {
		if err := visit(a.Address); err != nil {
			return err
		}
	}
	return nil
}

// AliasesTargeting lists aliases that deliver directly to address.
func AliasesTargeting(s store.Snapshot, address string) []string {
	var out []string
	for _, a := range s.Aliases {
		for _, t := range a.Targets {
			if t == address {
				out = append(out, a.Address)
				break
			}
		}
	}
	return out
}
