package generate

import (
	"errors"
	"fmt"

	"github.com/kspears/mailstack/internal/store"
)

// Import loads a whole account set into an empty store, password hashes
// verbatim, as one change. The change log records counts only.
func (a *Admin) Import(actor string, snap store.Snapshot) (string, error) {
	return a.change(actor, func(tx *store.Tx, before store.Snapshot) (change, error) {
		if len(before.Domains)+len(before.Mailboxes)+len(before.Aliases) > 0 {
			return change{}, errors.New("cannot import into a store that already holds domains, mailboxes or aliases")
		}
		for _, d := range snap.Domains {
			if err := tx.AddDomain(d); err != nil {
				return change{}, fmt.Errorf("import domain %s: %w", d, err)
			}
		}
		for _, m := range snap.Mailboxes {
			if err := tx.AddMailbox(m); err != nil {
				return change{}, fmt.Errorf("import mailbox %s: %w", m.Address, err)
			}
		}
		for _, al := range snap.Aliases {
			if err := tx.AddAlias(al); err != nil {
				return change{}, fmt.Errorf("import alias %s: %w", al.Address, err)
			}
		}
		for _, g := range snap.Grants {
			if err := tx.AddGrant(g); err != nil {
				return change{}, fmt.Errorf("import send-as grant %s for %s: %w", g.Address, g.Mailbox, err)
			}
		}
		counts := fmt.Sprintf("%d domains, %d mailboxes, %d aliases", len(snap.Domains), len(snap.Mailboxes), len(snap.Aliases))
		return change{"import", fmt.Sprintf("%s, %d send-as grants", counts, len(snap.Grants)), "imported " + counts}, nil
	})
}
