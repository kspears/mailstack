package mailcow

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Unchecked are the items this tool cannot see because they live in files on disk.
var Unchecked = []string{
	"not checked: global rspamd maps (files on disk; check data/conf/rspamd/custom/ by hand)",
	"not checked: user Sieve script files (files on disk; look for a sieve directory in each mailbox by hand)",
	"not checked: shared-folder ACL files (files on disk; look for non-empty dovecot-acl files by hand)",
}

// Write prints the summary table, the stop-item counts and the unchecked lines.
// DKIM key material is never printed.
func (r Report) Write(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "domains\t%d\n", r.Domains)
	fmt.Fprintf(tw, "mailboxes carried\t%d\n", r.Mailboxes)
	fmt.Fprintf(tw, "mailboxes skipped\t%d\n", len(r.Skipped))
	for _, s := range r.Skipped {
		fmt.Fprintf(tw, "  skipped\t%s\n", s)
	}
	fmt.Fprintf(tw, "aliases\t%d\n", r.Aliases)
	fmt.Fprintf(tw, "send-as grants\t%d\n", r.Grants)
	if r.GrantsDropped > 0 {
		fmt.Fprintf(tw, "send-as grants of skipped mailboxes dropped\t%d\n", r.GrantsDropped)
	}
	fmt.Fprintf(tw, "dkim keys\t%d\n", len(r.DKIM))
	fmt.Fprintf(tw, "dkim keys for other domains, not copied\t%d\n", r.UnusedDKIMKeys)
	fmt.Fprintf(tw, "mailboxes with a quota (information only)\t%d\n", r.QuotaMailboxes)
	fmt.Fprintf(tw, "relayhosts matching the new relay, redundant, dropped\t%d\n", r.RedundantRelayhosts)
	for _, f := range r.Findings {
		fmt.Fprintf(tw, "%s\t%d\n", f.Item, f.Rows)
	}
	tw.Flush()
	for _, f := range r.Findings {
		if f.Acknowledged {
			fmt.Fprintf(w, "acknowledged: %s (%d rows left behind)\n", f.Item, f.Rows)
		}
	}
	fmt.Fprintln(w, strings.Join(Unchecked, "\n"))
}
