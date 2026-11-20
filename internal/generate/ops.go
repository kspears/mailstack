package generate

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

// Every operation below takes an actor for the change log (for example
// "cli:alex" or an email), validates, applies atomically, and returns the
// text that follows "ok: ". On error nothing has changed.

func (a *Admin) AddDomain(actor, domain string) (string, error) {
	d, err := validate.Domain(domain)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if slices.Contains(snap.Domains, d) {
			return change{}, fmt.Errorf("domain %s already exists", d)
		}
		if err := tx.AddDomain(d); err != nil {
			return change{}, err
		}
		return change{"domain.add", d, "added " + d + "; it cannot send or receive until DNS and SES are set up"}, nil
	})
}

func (a *Admin) RemoveDomain(actor, domain string) (string, error) {
	d, err := validate.Domain(domain)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !slices.Contains(snap.Domains, d) {
			return change{}, fmt.Errorf("domain %s does not exist", d)
		}
		inDomain := func(address string) bool { _, dom := validate.Split(address); return dom == d }
		var mailboxes, aliases, grants int
		for _, m := range snap.Mailboxes {
			if inDomain(m.Address) {
				mailboxes++
			}
		}
		for _, al := range snap.Aliases {
			if inDomain(al.Address) {
				aliases++
			}
		}
		for _, g := range snap.Grants {
			if inDomain(g.Address) {
				grants++
			}
		}
		if mailboxes+aliases+grants > 0 {
			return change{}, fmt.Errorf("domain %s still has %d mailboxes, %d aliases and %d send-as grants; remove them first", d, mailboxes, aliases, grants)
		}
		if err := tx.RemoveDomain(d); err != nil {
			return change{}, err
		}
		return change{"domain.remove", d, "removed domain " + d}, nil
	})
}

// AddMailbox creates an active mailbox with a bcrypt-hashed password. It refuses
// an address whose mail directory already exists unless adoptExisting is set.
func (a *Admin) AddMailbox(actor, address, name, password string, adoptExisting bool) (string, error) {
	addr, err := validate.HostedName(address)
	if err != nil {
		return "", err
	}
	hash, err := hashChecked(password)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if hasMailbox(snap, addr) {
			return change{}, fmt.Errorf("mailbox %s already exists", addr)
		}
		if hasAlias(snap, addr) {
			return change{}, fmt.Errorf("%s is already an alias, so a mailbox cannot use that address", addr)
		}
		path := a.MailPath(addr)
		if _, err := os.Stat(path); err == nil && !adoptExisting {
			return change{}, fmt.Errorf("mail for %s still exists at %s", addr, path)
		}
		if err := tx.AddMailbox(store.Mailbox{Address: addr, Hash: hash, State: store.Active, Name: name}); err != nil {
			return change{}, err
		}
		return change{"mailbox.add", addr, "added mailbox " + addr}, nil
	})
}

func (a *Admin) SetPassword(actor, address, password string) (string, error) {
	addr, err := validate.Address(address)
	if err != nil {
		return "", err
	}
	hash, err := hashChecked(password)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !hasMailbox(snap, addr) {
			return change{}, fmt.Errorf("no mailbox %s", addr)
		}
		if err := tx.SetHash(addr, hash); err != nil {
			return change{}, err
		}
		return change{"mailbox.passwd", addr, "changed password for " + addr}, nil
	})
}

func (a *Admin) SetMailboxState(actor, address string, state store.State) (string, error) {
	addr, err := validate.Address(address)
	if err != nil {
		return "", err
	}
	if _, err := store.ParseState(string(state)); err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !hasMailbox(snap, addr) {
			return change{}, fmt.Errorf("no mailbox %s", addr)
		}
		if err := tx.SetState(addr, state); err != nil {
			return change{}, err
		}
		return change{"mailbox.state", addr + " " + string(state), fmt.Sprintf("set %s to %s", addr, state)}, nil
	})
}

// RemoveMailbox removes the account and its send-as grants. Mail on disk is left alone.
func (a *Admin) RemoveMailbox(actor, address string) (string, error) {
	addr, err := validate.Address(address)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !hasMailbox(snap, addr) {
			return change{}, fmt.Errorf("no mailbox %s", addr)
		}
		if err := refuseIfTargeted(snap, addr); err != nil {
			return change{}, err
		}
		if err := tx.RemoveMailbox(addr); err != nil {
			return change{}, err
		}
		return change{"mailbox.remove", addr, fmt.Sprintf("removed %s; mail left in place at %s; mailbox purge-removed deletes it after %d days", addr, a.MailPath(addr), purgeAfterDays)}, nil
	})
}

func (a *Admin) AddAlias(actor, address string, targets []string) (string, error) {
	addr, err := validate.HostedName(address)
	if err != nil {
		return "", err
	}
	norm, err := aliasTargets(addr, targets)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if hasMailbox(snap, addr) {
			return change{}, fmt.Errorf("%s is already a mailbox, so an alias cannot use that address", addr)
		}
		if hasAlias(snap, addr) {
			return change{}, fmt.Errorf("alias %s already exists", addr)
		}
		if err := tx.AddAlias(store.Alias{Address: addr, Targets: norm}); err != nil {
			return change{}, err
		}
		list := strings.Join(norm, ",")
		return change{"alias.add", addr + " -> " + list, fmt.Sprintf("added alias %s -> %s", addr, list)}, nil
	})
}

// SetAliasTargets replaces an alias's targets in one change, so the address
// never stops existing the way it would across a remove and an add.
func (a *Admin) SetAliasTargets(actor, address string, targets []string) (string, error) {
	addr, err := validate.Address(address)
	if err != nil {
		return "", err
	}
	norm, err := aliasTargets(addr, targets)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !hasAlias(snap, addr) {
			return change{}, fmt.Errorf("no alias %s", addr)
		}
		if err := tx.RemoveAlias(addr); err != nil {
			return change{}, err
		}
		if err := tx.AddAlias(store.Alias{Address: addr, Targets: norm}); err != nil {
			return change{}, err
		}
		list := strings.Join(norm, ",")
		return change{"alias.set", addr + " -> " + list, fmt.Sprintf("alias %s now delivers to %s", addr, list)}, nil
	})
}

func aliasTargets(alias string, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("alias %s needs at least one target", alias)
	}
	norm := make([]string, len(targets))
	var err error
	for i, t := range targets {
		if norm[i], err = validate.Address(t); err != nil {
			return nil, err
		}
	}
	return norm, nil
}

func (a *Admin) RemoveAlias(actor, address string) (string, error) {
	addr, err := validate.Address(address)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !hasAlias(snap, addr) {
			return change{}, fmt.Errorf("no alias %s", addr)
		}
		if err := refuseIfTargeted(snap, addr); err != nil {
			return change{}, err
		}
		if err := tx.RemoveAlias(addr); err != nil {
			return change{}, err
		}
		return change{"alias.remove", addr, "removed alias " + addr}, nil
	})
}

func (a *Admin) AddSendAs(actor, mailbox, address string) (string, error) {
	g, err := grant(mailbox, address)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !hasMailbox(snap, g.Mailbox) {
			return change{}, fmt.Errorf("no mailbox %s", g.Mailbox)
		}
		if slices.Contains(snap.Grants, g) {
			return change{}, fmt.Errorf("%s may already send as %s", g.Mailbox, g.Address)
		}
		if err := tx.AddGrant(g); err != nil {
			return change{}, err
		}
		return change{"sendas.add", g.Mailbox + " -> " + g.Address, fmt.Sprintf("%s may now send as %s", g.Mailbox, g.Address)}, nil
	})
}

func (a *Admin) RemoveSendAs(actor, mailbox, address string) (string, error) {
	g, err := grant(mailbox, address)
	if err != nil {
		return "", err
	}
	return a.change(actor, func(tx *store.Tx, snap store.Snapshot) (change, error) {
		if !slices.Contains(snap.Grants, g) {
			return change{}, fmt.Errorf("%s has no send-as grant for %s", g.Mailbox, g.Address)
		}
		if err := tx.RemoveGrant(g); err != nil {
			return change{}, err
		}
		return change{"sendas.remove", g.Mailbox + " -> " + g.Address, fmt.Sprintf("%s may no longer send as %s", g.Mailbox, g.Address)}, nil
	})
}

func grant(mailbox, address string) (store.Grant, error) {
	m, err := validate.Address(mailbox)
	if err != nil {
		return store.Grant{}, err
	}
	addr, err := validate.Address(address)
	if err != nil {
		return store.Grant{}, err
	}
	return store.Grant{Mailbox: m, Address: addr}, nil
}

func hashChecked(password string) (string, error) {
	if err := validate.Password(password); err != nil {
		return "", err
	}
	return store.HashPassword(password)
}

func refuseIfTargeted(snap store.Snapshot, address string) error {
	if by := validate.AliasesTargeting(snap, address); len(by) > 0 {
		return fmt.Errorf("cannot remove %s: alias %s still delivers to it; remove or retarget the alias first", address, strings.Join(by, ", "))
	}
	return nil
}

func hasMailbox(snap store.Snapshot, address string) bool {
	return slices.ContainsFunc(snap.Mailboxes, func(m store.Mailbox) bool { return m.Address == address })
}

func hasAlias(snap store.Snapshot, address string) bool {
	return slices.ContainsFunc(snap.Aliases, func(al store.Alias) bool { return al.Address == address })
}
