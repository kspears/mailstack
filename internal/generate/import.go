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
func (a *Admin) Import(actor string, snap store.Snapshot, overwrite bool) (replaced string, err error) {
	guard := func(before store.Snapshot) error {
		if !before.HoldsAccounts() {
			return nil
		}
		if !overwrite {
			return errors.New("cannot import into a store that already holds domains, mailboxes or aliases; pass --overwrite to replace it")
		}
		copied := store.ReplacedName(StorePath(a.cfg), a.cfg.Now())
		if err := a.st.CopyTo(copied); err != nil {
			return err
		}
		replaced = copied
		return nil
	}
	defer func() {
		if err != nil && replaced != "" {
			os.Remove(replaced)
			replaced = ""
		}
	}()
	_, err = a.run(actor, guard, func(tx *store.Tx, _ store.Snapshot) (change, error) {
		if err := tx.Clear(); err != nil {
			return change{}, err
		}
		if err := load(tx, snap); err != nil {
			return change{}, err
		}
		counts := fmt.Sprintf("%d domains, %d mailboxes, %d aliases", len(snap.Domains), len(snap.Mailboxes), len(snap.Aliases))
		return change{"import", fmt.Sprintf("%s, %d send-as grants", counts, len(snap.Grants)), "imported " + counts}, nil
	})
	return replaced, err
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
