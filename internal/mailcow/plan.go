package mailcow

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/kspears/mailstack/internal/store"
	"github.com/kspears/mailstack/internal/validate"
)

const hashPrefix = "{BLF-CRYPT}"

// Options are the choices the owner makes on the command line.
type Options struct {
	SkipMailboxes []string
	Acknowledge   []string
	// RelayHost is the relay the new stack uses, as mailcow stores it, e.g.
	// "[smtp.example.test]:2587".
	RelayHost string
}

type stopItem struct {
	name    string
	ackable bool
}

// stopItems lists, in reporting order, everything in mailcow that can change
// mail behaviour and has no destination in the new stack.
var stopItems = []stopItem{
	{"alias-domains", false},
	{"catch-all-aliases", false},
	{"special-alias-targets", false},
	{"bcc-maps", true},
	{"recipient-maps", true},
	{"transport-maps", true},
	{"relayhosts-in-use", false},
	{"relayhosts-unused", true},
	{"temporary-aliases", true},
	{"sync-jobs", true},
	{"forwarding-hosts", true},
	{"domain-footers", true},
	{"sieve-filters", true},
	{"sieve-scripts", true},
	{"mailbox-protocol-restrictions", true},
	{"spam-settings", true},
	{"rate-limits", true},
	{"app-passwords", true},
	{"tfa", true},
	{"inactive-aliases", true},
	{"external-send-as", true},
	{"shared-folder-acls", true},
	{"global-rspamd-maps", true},
}

// ParseAcknowledge validates item names given to --acknowledge.
func ParseAcknowledge(names []string) (map[string]bool, error) {
	ack := map[string]bool{}
	for _, n := range names {
		i := slices.IndexFunc(stopItems, func(s stopItem) bool { return s.name == n })
		switch {
		case i < 0:
			return nil, fmt.Errorf("unknown item %q to acknowledge; known items: %s", n, strings.Join(itemNames(), ", "))
		case !stopItems[i].ackable:
			return nil, fmt.Errorf("%s cannot be acknowledged: it changes where mail goes", n)
		}
		ack[n] = true
	}
	return ack, nil
}

func itemNames() []string {
	var out []string
	for _, s := range stopItems {
		if s.ackable {
			out = append(out, s.name)
		}
	}
	return out
}

// Finding is the count for one stop item. Unchecked is the reason the item could
// not be counted at all; Rows is then 0 and means nothing.
type Finding struct {
	Item         string
	Rows         int
	Unchecked    string
	Acknowledged bool
}

// KeyFile is one DKIM private key to write as <Domain>.<Selector>.key.
// The PEM is never printed.
type KeyFile struct {
	Domain, Selector string
	PEM              string
}

func (k KeyFile) Filename() string { return k.Domain + "." + k.Selector + ".key" }

// Report is everything the owner needs to see before anything is written.
type Report struct {
	Domains             int
	Mailboxes           int
	Skipped             []string
	Aliases             int
	Grants              int
	GrantsDropped       int
	QuotaMailboxes      int
	RedundantRelayhosts int
	DKIM                []KeyFile
	UnusedDKIMKeys      int
	Findings            []Finding
}

// Plan decides what is carried, skipped or blocking. The report is filled in
// as far as it got even when err is non-nil.
func Plan(d Data, o Options) (store.Snapshot, Report, error) {
	var snap store.Snapshot
	var rep Report
	ack, err := ParseAcknowledge(o.Acknowledge)
	if err != nil {
		return snap, rep, err
	}
	p := &planner{d: d, o: o, rep: &rep, snap: &snap, hosted: map[string]bool{}, counts: map[string]int{}}
	p.domains()
	p.mailboxes()
	p.relayhosts()
	p.aliases()
	p.grants()
	p.dkim()
	for _, item := range stopItems {
		n, ok := p.counts[item.name]
		if !ok {
			n = d.Counts[item.name]
		}
		why := d.Unchecked[item.name]
		rep.Findings = append(rep.Findings, Finding{item.name, n, why, (n > 0 || why != "") && ack[item.name]})
	}
	if p.err != nil {
		return store.Snapshot{}, rep, p.err
	}
	for _, f := range rep.Findings {
		if f.Unchecked != "" && !f.Acknowledged {
			return store.Snapshot{}, rep, fmt.Errorf("cannot check %s: %s", f.Item, f.Unchecked)
		}
		if f.Rows > 0 && !f.Acknowledged {
			return store.Snapshot{}, rep, fmt.Errorf("%s has %d rows and no destination", f.Item, f.Rows)
		}
	}
	sortSnapshot(&snap)
	slices.Sort(rep.Skipped)
	return snap, rep, nil
}

type planner struct {
	d      Data
	o      Options
	rep    *Report
	snap   *store.Snapshot
	err    error
	hosted map[string]bool
	counts map[string]int

	mailboxSet map[string]bool
	aliasSet   map[string]bool
	relays     map[string]string
}

func (p *planner) fail(format string, args ...any) {
	if p.err == nil {
		p.err = fmt.Errorf(format, args...)
	}
}

func (p *planner) failErr(err error) {
	if p.err == nil {
		p.err = err
	}
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func (p *planner) domains() {
	for _, d := range p.d.Domains {
		name, err := validate.Domain(d.Name)
		if err != nil {
			p.failErr(err)
			continue
		}
		switch {
		case !d.Active:
			p.fail("domain %s is inactive; activate it in mailcow or remove it before importing", name)
		case d.BackupMX:
			p.fail("domain %s is a backup MX, which the new stack does not support", name)
		case d.RelayAll || d.RelayUnknown:
			p.fail("domain %s is a relay domain, which the new stack does not support", name)
		}
		p.hosted[name] = true
		p.snap.Domains = append(p.snap.Domains, name)
	}
	p.rep.Domains = len(p.snap.Domains)
}

func (p *planner) mailboxes() {
	p.mailboxSet = map[string]bool{}
	skip := map[string]bool{}
	for _, s := range p.o.SkipMailboxes {
		skip[norm(s)] = true
	}
	var protocolRows int
	for _, m := range p.d.Mailboxes {
		addr := norm(m.Address)
		if m.Active == 0 {
			if !skip[addr] {
				p.fail("mailbox %s is disabled; pass --skip-mailbox %s to leave it behind", addr, addr)
				continue
			}
			delete(skip, addr)
			p.rep.Skipped = append(p.rep.Skipped, addr)
			continue
		}
		if m.Active != 1 && m.Active != 2 {
			p.fail("mailbox %s has unknown active value %d", addr, m.Active)
			continue
		}
		if _, err := validate.Address(addr); err != nil {
			p.failErr(err)
			continue
		}
		if _, domain := validate.Split(addr); !p.hosted[domain] {
			p.fail("mailbox %s is in %s, which is not a carried domain", addr, domain)
			continue
		}
		if !strings.HasPrefix(m.Hash, hashPrefix) {
			p.fail("%s uses %s", addr, scheme(m.Hash))
			continue
		}
		state := store.Active
		if m.Active == 2 {
			state = store.ReceiveOnly
		}
		p.mailboxSet[addr] = true
		p.snap.Mailboxes = append(p.snap.Mailboxes, store.Mailbox{Address: addr, Hash: m.Hash, State: state, Name: m.Name})
		if m.Quota > 0 {
			p.rep.QuotaMailboxes++
		}
		if restricted(m.Attributes) {
			protocolRows++
		}
	}
	for s := range skip {
		p.fail("--skip-mailbox %s: not a disabled mailbox; only disabled mailboxes can be skipped", s)
	}
	p.rep.Mailboxes = len(p.snap.Mailboxes)
	p.counts["mailbox-protocol-restrictions"] = protocolRows
}

func scheme(hash string) string {
	if rest, ok := strings.CutPrefix(hash, "{"); ok {
		if name, _, found := strings.Cut(rest, "}"); found && name != "" {
			return name
		}
	}
	return "no recognisable scheme prefix"
}

// attributes reads the JSON mailcow keeps per mailbox; values are strings or numbers.
func attributes(raw string) map[string]string {
	var m map[string]any
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range m {
		out[k] = strings.TrimSuffix(fmt.Sprint(v), ".0")
	}
	return out
}

// restricted reports a mailbox that mailcow bars from IMAP or SMTP, or routes
// through its own relay. POP3 and ManageSieve are not offered here at all, so
// mailcow switching them off for a mailbox restricts nothing that carries over.
func restricted(raw string) bool {
	attrs := attributes(raw)
	for _, k := range []string{"imap_access", "smtp_access"} {
		if v, ok := attrs[k]; ok && v == "0" {
			return true
		}
	}
	return hasRelayhost(attrs["relayhost"])
}

func hasRelayhost(id string) bool { return id != "" && id != "0" }

// relayhosts redundant-drops rows equal to the new relay and counts the rest. A
// differing row that no domain and no carried mailbox uses is only left behind
// (relayhosts-unused). A domain or carried mailbox assigned to a differing active
// row would silently start relaying differently, so that is relayhosts-in-use and
// can never be acknowledged. mailcow does not use an inactive row, so an
// assignment to one is not in use, but the row is still not unused.
func (p *planner) relayhosts() {
	p.relays = map[string]string{}
	differs := map[string]bool{}
	for _, r := range p.d.Relayhosts {
		p.relays[r.ID] = r.Hostname
		if sameRelay(r.Hostname, p.o.RelayHost) {
			p.rep.RedundantRelayhosts++
			continue
		}
		differs[r.ID] = true
	}
	active := map[string]bool{}
	for _, r := range p.d.Relayhosts {
		active[r.ID] = r.Active
	}
	var inUse int
	assigned := map[string]bool{}
	assign := func(id string) {
		if !hasRelayhost(id) || sameRelay(p.relays[id], p.o.RelayHost) {
			return
		}
		assigned[id] = true
		if _, known := p.relays[id]; !known || active[id] {
			inUse++
		}
	}
	for _, d := range p.d.Domains {
		assign(d.RelayhostID)
	}
	for _, m := range p.d.Mailboxes {
		if m.Active != 0 {
			assign(attributes(m.Attributes)["relayhost"])
		}
	}
	var unused int
	for id := range differs {
		if !assigned[id] {
			unused++
		}
	}
	p.counts["relayhosts-in-use"] = inUse
	p.counts["relayhosts-unused"] = unused
}

func sameRelay(a, b string) bool { return b != "" && norm(a) == norm(b) }

type pendingAlias struct {
	address string
	targets []string
}

func (p *planner) aliases() {
	p.aliasSet = map[string]bool{}
	var pending []pendingAlias
	var catchAll, inactive int
	for _, a := range p.d.Aliases {
		addr := norm(a.Address)
		targets := splitTargets(a.Goto)
		switch {
		case len(targets) == 1 && targets[0] == addr:
			continue
		case strings.HasPrefix(addr, "@"):
			catchAll++
		case !a.Active:
			inactive++
		default:
			p.aliasSet[addr] = true
			pending = append(pending, pendingAlias{addr, targets})
		}
	}
	p.counts["catch-all-aliases"] = catchAll
	p.counts["inactive-aliases"] = inactive

	var special int
	for _, a := range pending {
		if _, err := validate.Address(a.address); err != nil {
			p.failErr(err)
			continue
		}
		if _, domain := validate.Split(a.address); !p.hosted[domain] {
			p.fail("alias %s is in %s, which is not a carried domain", a.address, domain)
			continue
		}
		if p.hasSpecialTarget(a.targets) {
			special++
			continue
		}
		p.snap.Aliases = append(p.snap.Aliases, store.Alias{Address: a.address, Targets: a.targets})
	}
	p.counts["special-alias-targets"] = special
	p.rep.Aliases = len(p.snap.Aliases)
}

func splitTargets(goTo string) []string {
	var out []string
	for _, t := range strings.Split(goTo, ",") {
		if t = norm(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// hasSpecialTarget reports whether a target is neither a carried mailbox or
// alias nor a syntactically valid address outside the hosted domains.
func (p *planner) hasSpecialTarget(targets []string) bool {
	for _, t := range targets {
		if p.mailboxSet[t] || p.aliasSet[t] {
			continue
		}
		if _, err := validate.Address(t); err != nil {
			return true
		}
		if _, domain := validate.Split(t); p.hosted[domain] {
			return true
		}
	}
	return false
}

func (p *planner) grants() {
	var external int
	seen := map[store.Grant]bool{}
	for _, g := range p.d.SenderACLs {
		if g.External {
			external++
			continue
		}
		grant := store.Grant{Mailbox: norm(g.LoggedInAs), Address: norm(g.SendAs)}
		if slices.Contains(p.rep.Skipped, grant.Mailbox) {
			p.rep.GrantsDropped++
			continue
		}
		if _, err := validate.Address(grant.Address); err != nil {
			p.fail("send-as grant for %s: %v", grant.Mailbox, err)
			continue
		}
		if !seen[grant] {
			seen[grant] = true
			p.snap.Grants = append(p.snap.Grants, grant)
		}
	}
	p.counts["external-send-as"] = external
	p.rep.Grants = len(p.snap.Grants)
}

func (p *planner) dkim() {
	used := map[string]bool{}
	for _, domain := range p.snap.Domains {
		selector := p.d.DKIMSelectors[domain]
		if selector == "" {
			p.fail("domain %s has no DKIM selector in DKIM_SELECTORS", domain)
			continue
		}
		if !validSelector(selector) {
			p.fail("domain %s has a DKIM selector %q that is not safe to use in a file name", domain, selector)
			continue
		}
		field := selector + "." + domain
		pem, ok := p.d.DKIMKeys[field]
		if !ok {
			p.fail("domain %s has no DKIM key %s in DKIM_PRIV_KEYS", domain, field)
			continue
		}
		if !strings.Contains(pem, "-----BEGIN") {
			p.fail("the DKIM key for %s is not a PEM private key", domain)
			continue
		}
		used[field] = true
		p.rep.DKIM = append(p.rep.DKIM, KeyFile{Domain: domain, Selector: selector, PEM: pem})
	}
	p.rep.UnusedDKIMKeys = len(p.d.DKIMKeys) - len(used)
}

func validSelector(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return s != ""
}

func sortSnapshot(s *store.Snapshot) {
	slices.Sort(s.Domains)
	slices.SortFunc(s.Mailboxes, func(a, b store.Mailbox) int { return strings.Compare(a.Address, b.Address) })
	slices.SortFunc(s.Aliases, func(a, b store.Alias) int { return strings.Compare(a.Address, b.Address) })
	slices.SortFunc(s.Grants, func(a, b store.Grant) int {
		return strings.Compare(a.Mailbox+" "+a.Address, b.Mailbox+" "+b.Address)
	})
}
