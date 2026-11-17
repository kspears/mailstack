package generate

import (
	"errors"
	"fmt"
	"os"

	"github.com/kspears/mailstack/internal/store"
)

// Import loads a whole account set, password hashes verbatim, as one change under
// the lock. It does not require the files in use to match the store: that is the
// state it exists to replace.
//
// Without overwrite the store must hold no domains, mailboxes or aliases. With
// overwrite, a consistent copy of the database is first written next to it as
// store.db.replaced-<UTC timestamp> (returned as replaced), then every account row
// is deleted inside the same transaction that loads snap and applies one
// generation. On any failure the transaction rolls back, current has not moved,
// and a copy made by this call is removed. The change log records counts only.
func (a *Admin) Import(actor string, snap store.Snapshot, overwrite bool) (summary, replaced string, err error) {
	unlock, err := a.lock()
	if err != nil {
		return "", "", err
	}
	defer unlock()

	existing, err := a.st.Snapshot()
	if err != nil {
		return "", "", err
	}
	holdsAccounts := len(existing.Domains)+len(existing.Mailboxes)+len(existing.Aliases) > 0
	if holdsAccounts && !overwrite {
		return "", "", errors.New("cannot import into a store that already holds domains, mailboxes or aliases")
	}
	if holdsAccounts {
		replaced = fmt.Sprintf("%s.replaced-%s", a.storePath, a.cfg.Now().UTC().Format("20060102T150405Z"))
		if err := a.st.CopyTo(replaced); err != nil {
			return "", "", err
		}
		defer func() {
			if err != nil {
				os.Remove(replaced)
				replaced = ""
			}
		}()
	}

	tx, err := a.st.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	if err := tx.Clear(); err != nil {
		return "", "", err
	}
	if err := load(tx, snap); err != nil {
		return "", "", err
	}
	counts := fmt.Sprintf("%d domains, %d mailboxes, %d aliases", len(snap.Domains), len(snap.Mailboxes), len(snap.Aliases))
	summary, err = a.finish(tx, actor, change{"import", fmt.Sprintf("%s, %d send-as grants", counts, len(snap.Grants)), "imported " + counts})
	return summary, replaced, err
}

func load(tx *store.Tx, snap store.Snapshot) error {
	for _, d := range snap.Domains {
		if err := tx.AddDomain(d); err != nil {
			return fmt.Errorf("import domain %s: %w", d, err)
		}
	}
	for _, m := range snap.Mailboxes {
		if err := tx.AddMailbox(m); err != nil {
			return fmt.Errorf("import mailbox %s: %w", m.Address, err)
		}
	}
	for _, al := range snap.Aliases {
		if err := tx.AddAlias(al); err != nil {
			return fmt.Errorf("import alias %s: %w", al.Address, err)
		}
	}
	for _, g := range snap.Grants {
		if err := tx.AddGrant(g); err != nil {
			return fmt.Errorf("import send-as grant %s for %s: %w", g.Address, g.Mailbox, err)
		}
	}
	return nil
}
