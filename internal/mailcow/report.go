package mailcow

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// Write prints the summary table and the stop-item counts.
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
		if f.Unchecked != "" {
			fmt.Fprintf(tw, "%s\tnot checked: %s\n", f.Item, f.Unchecked)
			continue
		}
		fmt.Fprintf(tw, "%s\t%d\n", f.Item, f.Rows)
	}
	tw.Flush()
	for _, f := range r.Findings {
		switch {
		case f.Acknowledged && f.Unchecked != "":
			fmt.Fprintf(w, "acknowledged: %s (not checked)\n", f.Item)
		case f.Acknowledged:
			fmt.Fprintf(w, "acknowledged: %s (%d rows left behind)\n", f.Item, f.Rows)
		}
	}
}
