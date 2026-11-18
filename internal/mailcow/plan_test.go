package mailcow

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/kspears/mailstack/internal/store"
)

const (
	hashA = "{BLF-CRYPT}$2y$10$aaaaaaaaaaaaaaaaaaaaaa"
	pemA  = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	relay = "[smtp.example.test]:2587"
)

func good() Data {
	return Data{
		Domains: []Domain{
			{Name: "example.test", Active: true, RelayhostID: "0"},
			{Name: "example.org", Active: true, RelayhostID: "0"},
		},
		Mailboxes: []Mailbox{
			{Address: "alice@example.test", Name: "Alice A", Hash: hashA, Active: 1, Quota: 100, Attributes: `{"imap_access":"1","smtp_access":"1","relayhost":"0"}`},
			{Address: "bob@example.test", Hash: hashA, Active: 2},
			{Address: "carol@example.org", Hash: hashA, Active: 0},
		},
		Aliases: []Alias{
			{Address: "alice@example.test", Goto: "alice@example.test", Active: true},
			{Address: "bob@example.test", Goto: "bob@example.test", Active: true},
			{Address: "carol@example.org", Goto: "carol@example.org", Active: true},
			{Address: "info@example.test", Goto: "alice@example.test", Active: true},
			{Address: "team@example.test", Goto: "info@example.test,bob@example.test,away@example.net", Active: true},
		},
		SenderACLs:    []SenderACL{{LoggedInAs: "alice@example.test", SendAs: "sales@example.test"}},
		Relayhosts:    []Relayhost{{ID: "1", Hostname: relay, Active: true}},
		Counts:        map[string]int{},
		DKIMSelectors: map[string]string{"example.test": "dkim", "example.org": "s1"},
		DKIMKeys: map[string]string{
			"dkim.example.test": pemA,
			"s1.example.org":    pemA,
		},
	}
}

func opts() Options {
	return Options{SkipMailboxes: []string{"carol@example.org"}, RelayHost: relay}
}

func TestPlanHappyPath(t *testing.T) {
	snap, rep, err := Plan(good(), opts())
	if err != nil {
		t.Fatal(err)
	}
	want := store.Snapshot{
		Domains: []string{"example.org", "example.test"},
		Mailboxes: []store.Mailbox{
			{Address: "alice@example.test", Hash: hashA, State: store.Active, Name: "Alice A"},
			{Address: "bob@example.test", Hash: hashA, State: store.ReceiveOnly},
		},
		Aliases: []store.Alias{
			{Address: "info@example.test", Targets: []string{"alice@example.test"}},
			{Address: "team@example.test", Targets: []string{"info@example.test", "bob@example.test", "away@example.net"}},
		},
		Grants: []store.Grant{{Mailbox: "alice@example.test", Address: "sales@example.test"}},
	}
	if !reflect.DeepEqual(snap, want) {
		t.Errorf("snapshot:\n got %+v\nwant %+v", snap, want)
	}
	if rep.Domains != 2 || rep.Mailboxes != 2 || rep.Aliases != 2 || rep.Grants != 1 || rep.QuotaMailboxes != 1 ||
		rep.RedundantRelayhosts != 1 || rep.UnusedDKIMKeys != 0 || !reflect.DeepEqual(rep.Skipped, []string{"carol@example.org"}) {
		t.Errorf("report: %+v", rep)
	}
	if len(rep.DKIM) != 2 || rep.DKIM[0].Filename() != "example.test.dkim.key" || rep.DKIM[1].Filename() != "example.org.s1.key" {
		t.Errorf("dkim: %+v", rep.DKIM)
	}
	if len(rep.Findings) != len(stopItems) {
		t.Errorf("findings: %d, want %d", len(rep.Findings), len(stopItems))
	}
}

func TestPlanNormalisesCase(t *testing.T) {
	d := good()
	d.Mailboxes[0].Address = "Alice@Example.Test"
	d.Aliases[3].Address = "Info@Example.test"
	snap, _, err := Plan(d, opts())
	if err != nil {
		t.Fatal(err)
	}
	if snap.Mailboxes[0].Address != "alice@example.test" || snap.Aliases[0].Address != "info@example.test" {
		t.Errorf("not lower-cased: %+v", snap)
	}
}

func TestPlanStopItems(t *testing.T) {
	tests := []struct {
		item   string
		mutate func(*Data)
	}{
		{"alias-domains", func(d *Data) { d.Counts["alias-domains"] = 2 }},
		{"catch-all-aliases", func(d *Data) {
			d.Aliases = append(d.Aliases, Alias{Address: "@example.test", Goto: "alice@example.test", Active: true})
		}},
		{"special-alias-targets", func(d *Data) {
			d.Aliases = append(d.Aliases, Alias{Address: "junk@example.test", Goto: "null@localhost", Active: true})
		}},
		{"bcc-maps", func(d *Data) { d.Counts["bcc-maps"] = 2 }},
		{"recipient-maps", func(d *Data) { d.Counts["recipient-maps"] = 2 }},
		{"transport-maps", func(d *Data) { d.Counts["transport-maps"] = 2 }},
		{"relayhosts-unused", func(d *Data) {
			d.Relayhosts = append(d.Relayhosts, Relayhost{ID: "2", Hostname: "[other.example.test]:25", Active: true})
		}},
		{"relayhosts-in-use", func(d *Data) {
			d.Relayhosts = append(d.Relayhosts, Relayhost{ID: "2", Hostname: "[other.example.test]:25", Active: true})
			d.Domains[0].RelayhostID = "2"
		}},
		{"temporary-aliases", func(d *Data) { d.Counts["temporary-aliases"] = 2 }},
		{"sync-jobs", func(d *Data) { d.Counts["sync-jobs"] = 2 }},
		{"forwarding-hosts", func(d *Data) { d.Counts["forwarding-hosts"] = 2 }},
		{"domain-footers", func(d *Data) { d.Counts["domain-footers"] = 2 }},
		{"sieve-filters", func(d *Data) { d.Counts["sieve-filters"] = 2 }},
		{"mailbox-protocol-restrictions", func(d *Data) { d.Mailboxes[0].Attributes = `{"imap_access":"0"}` }},
		{"spam-settings", func(d *Data) { d.Counts["spam-settings"] = 2 }},
		{"rate-limits", func(d *Data) { d.Counts["rate-limits"] = 2 }},
		{"app-passwords", func(d *Data) { d.Counts["app-passwords"] = 2 }},
		{"tfa", func(d *Data) { d.Counts["tfa"] = 2 }},
		{"inactive-aliases", func(d *Data) {
			d.Aliases = append(d.Aliases, Alias{Address: "old@example.test", Goto: "alice@example.test"})
		}},
		{"external-send-as", func(d *Data) {
			d.SenderACLs = append(d.SenderACLs, SenderACL{LoggedInAs: "alice@example.test", SendAs: "x@example.net", External: true})
		}},
		{"sieve-scripts", func(d *Data) { d.Counts["sieve-scripts"] = 2 }},
		{"shared-folder-acls", func(d *Data) { d.Counts["shared-folder-acls"] = 2 }},
		{"global-rspamd-maps", func(d *Data) { d.Counts["global-rspamd-maps"] = 2 }},
	}
	covered := map[string]bool{}
	for _, tc := range tests {
		covered[tc.item] = true
		t.Run(tc.item, func(t *testing.T) {
			d := good()
			tc.mutate(&d)
			_, rep, err := Plan(d, opts())
			if err == nil || !strings.HasPrefix(err.Error(), tc.item+" has ") || !strings.HasSuffix(err.Error(), " rows and no destination") {
				t.Fatalf("err = %v", err)
			}
			if len(rep.Findings) != len(stopItems) {
				t.Errorf("report lacks the full table: %d findings", len(rep.Findings))
			}
			ackable := map[string]bool{}
			for _, s := range stopItems {
				ackable[s.name] = s.ackable
			}
			o := opts()
			o.Acknowledge = []string{tc.item}
			snap, rep, err := Plan(d, o)
			if !ackable[tc.item] {
				if err == nil || !strings.Contains(err.Error(), "cannot be acknowledged") {
					t.Fatalf("acknowledging %s: err = %v", tc.item, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("acknowledged: %v", err)
			}
			if len(snap.Mailboxes) == 0 {
				t.Error("acknowledged plan carried nothing")
			}
			for _, f := range rep.Findings {
				if f.Item == tc.item && (!f.Acknowledged || f.Rows == 0) {
					t.Errorf("finding %+v", f)
				}
			}
		})
	}
	for _, s := range stopItems {
		if !covered[s.name] {
			t.Errorf("stop item %s has no test", s.name)
		}
	}
}

func TestPlanExactMessage(t *testing.T) {
	d := good()
	d.Counts["bcc-maps"] = 3
	_, _, err := Plan(d, opts())
	if err == nil || err.Error() != "bcc-maps has 3 rows and no destination" {
		t.Errorf("err = %v", err)
	}
}

func TestPlanFirstStopItemWins(t *testing.T) {
	d := good()
	d.Counts["tfa"] = 1
	d.Counts["bcc-maps"] = 1
	_, _, err := Plan(d, opts())
	if err == nil || !strings.HasPrefix(err.Error(), "bcc-maps ") {
		t.Errorf("err = %v", err)
	}
}

func TestParseAcknowledge(t *testing.T) {
	for _, bad := range []string{"nonsense", "alias-domains", "catch-all-aliases", "special-alias-targets"} {
		if _, err := ParseAcknowledge([]string{"tfa", bad}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if _, err := ParseAcknowledge([]string{"tfa", "spam-settings"}); err != nil {
		t.Error(err)
	}
}

func TestPlanDisabledMailbox(t *testing.T) {
	_, _, err := Plan(good(), Options{RelayHost: relay})
	if err == nil || err.Error() != "mailbox carol@example.org is disabled; pass --skip-mailbox carol@example.org to leave it behind" {
		t.Errorf("err = %v", err)
	}
	o := opts()
	o.SkipMailboxes = append(o.SkipMailboxes, "alice@example.test")
	if _, _, err := Plan(good(), o); err == nil || !strings.Contains(err.Error(), "only disabled mailboxes can be skipped") {
		t.Errorf("skipping an active mailbox: %v", err)
	}
}

func TestPlanHash(t *testing.T) {
	for hash, want := range map[string]string{
		"{SSHA512}abc":      "alice@example.test uses SSHA512",
		"plainhashnoprefix": "alice@example.test uses no recognisable scheme prefix",
	} {
		d := good()
		d.Mailboxes[0].Hash = hash
		if _, _, err := Plan(d, opts()); err == nil || err.Error() != want {
			t.Errorf("%q: err = %v, want %q", hash, err, want)
		}
	}
}

func TestPlanSelfAliasesExcluded(t *testing.T) {
	snap, _, err := Plan(good(), opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range snap.Aliases {
		if a.Address == "alice@example.test" || a.Address == "bob@example.test" {
			t.Errorf("self alias carried: %+v", a)
		}
	}
}

func TestPlanAliasToSkippedMailbox(t *testing.T) {
	d := good()
	d.Aliases = append(d.Aliases, Alias{Address: "old@example.test", Goto: "carol@example.org", Active: true})
	_, _, err := Plan(d, opts())
	if err == nil || !strings.HasPrefix(err.Error(), "special-alias-targets has 1 rows") {
		t.Errorf("err = %v", err)
	}
}

func TestPlanRelayhosts(t *testing.T) {
	t.Run("matching is redundant", func(t *testing.T) {
		d := good()
		d.Domains[0].RelayhostID = "1"
		_, rep, err := Plan(d, opts())
		if err != nil || rep.RedundantRelayhosts != 1 {
			t.Errorf("err = %v, redundant = %d", err, rep.RedundantRelayhosts)
		}
	})
	t.Run("case and spacing ignored", func(t *testing.T) {
		d := good()
		d.Relayhosts[0].Hostname = " [SMTP.example.test]:2587 "
		if _, _, err := Plan(d, opts()); err != nil {
			t.Error(err)
		}
	})
	t.Run("differing row assigned to a domain is in use and cannot be acknowledged", func(t *testing.T) {
		d := good()
		d.Relayhosts = append(d.Relayhosts, Relayhost{ID: "2", Hostname: "[other.example.test]:25", Active: true})
		d.Domains[0].RelayhostID = "2"
		_, rep, err := Plan(d, opts())
		if err == nil || err.Error() != "relayhosts-in-use has 1 rows and no destination" {
			t.Fatalf("err = %v", err)
		}
		if got := findingRows(rep, "relayhosts-unused"); got != 0 {
			t.Errorf("an assigned row also counted as unused: %d", got)
		}
		o := opts()
		o.Acknowledge = []string{"relayhosts-in-use"}
		if _, _, err := Plan(d, o); err == nil || !strings.Contains(err.Error(), "cannot be acknowledged") {
			t.Errorf("acknowledging in-use: %v", err)
		}
	})
	t.Run("differing row assigned to a carried mailbox is in use", func(t *testing.T) {
		d := good()
		d.Relayhosts = append(d.Relayhosts, Relayhost{ID: "2", Hostname: "[other.example.test]:25", Active: true})
		d.Mailboxes[0].Attributes = `{"relayhost":"2"}`
		_, _, err := Plan(d, Options{SkipMailboxes: []string{"carol@example.org"}, RelayHost: relay, Acknowledge: []string{"mailbox-protocol-restrictions"}})
		if err == nil || !strings.HasPrefix(err.Error(), "relayhosts-in-use has 1 rows") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("assignment from a skipped mailbox does not count", func(t *testing.T) {
		d := good()
		d.Relayhosts = append(d.Relayhosts, Relayhost{ID: "2", Hostname: "[other.example.test]:25", Active: true})
		d.Mailboxes[2].Attributes = `{"relayhost":"2"}`
		_, rep, err := Plan(d, Options{SkipMailboxes: []string{"carol@example.org"}, RelayHost: relay, Acknowledge: []string{"relayhosts-unused"}})
		if err != nil {
			t.Fatal(err)
		}
		if findingRows(rep, "relayhosts-in-use") != 0 || findingRows(rep, "relayhosts-unused") != 1 {
			t.Errorf("findings: %+v", rep.Findings)
		}
	})
	t.Run("unused differing row can be acknowledged", func(t *testing.T) {
		d := good()
		d.Relayhosts = append(d.Relayhosts, Relayhost{ID: "2", Hostname: "[other.example.test]:25", Active: true})
		if _, _, err := Plan(d, opts()); err == nil || !strings.HasPrefix(err.Error(), "relayhosts-unused has 1 rows") {
			t.Fatalf("err = %v", err)
		}
		o := opts()
		o.Acknowledge = []string{"relayhosts-unused"}
		if _, _, err := Plan(d, o); err != nil {
			t.Errorf("acknowledged: %v", err)
		}
	})
	t.Run("inactive differing row assigned to a domain is not in use", func(t *testing.T) {
		d := good()
		d.Relayhosts = append(d.Relayhosts, Relayhost{ID: "2", Hostname: "[other.example.test]:25", Active: false})
		d.Domains[0].RelayhostID = "2"
		_, rep, err := Plan(d, opts())
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if findingRows(rep, "relayhosts-in-use") != 0 || findingRows(rep, "relayhosts-unused") != 0 {
			t.Errorf("findings: %+v", rep.Findings)
		}
	})
	t.Run("no expected relay means every row differs", func(t *testing.T) {
		o := opts()
		o.RelayHost = ""
		if _, _, err := Plan(good(), o); err == nil || !strings.HasPrefix(err.Error(), "relayhosts-unused") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("per-mailbox relayhost restricts", func(t *testing.T) {
		d := good()
		d.Mailboxes[0].Attributes = `{"relayhost":"1"}`
		if _, _, err := Plan(d, opts()); err == nil || !strings.HasPrefix(err.Error(), "mailbox-protocol-restrictions") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("numeric attributes", func(t *testing.T) {
		d := good()
		d.Mailboxes[0].Attributes = `{"smtp_access":0}`
		if _, _, err := Plan(d, opts()); err == nil || !strings.HasPrefix(err.Error(), "mailbox-protocol-restrictions") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestPlanDKIM(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Data)
		wantErr string
		unused  int
	}{
		{"missing key", func(d *Data) { delete(d.DKIMKeys, "s1.example.org") }, "domain example.org has no DKIM key s1.example.org", 0},
		{"missing selector", func(d *Data) { delete(d.DKIMSelectors, "example.test") }, "domain example.test has no DKIM selector", 0},
		{"selector with a slash", func(d *Data) { d.DKIMSelectors["example.test"] = "../x" }, "not safe to use in a file name", 0},
		{"not pem", func(d *Data) { d.DKIMKeys["s1.example.org"] = "garbage" }, "is not a PEM private key", 0},
		{"extra key for another domain", func(d *Data) { d.DKIMKeys["dkim.example.net"] = pemA }, "", 1},
		{"extra key, other selector", func(d *Data) { d.DKIMKeys["old.example.test"] = pemA }, "", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := good()
			tc.mutate(&d)
			_, rep, err := Plan(d, opts())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || rep.UnusedDKIMKeys != tc.unused || len(rep.DKIM) != 2 {
				t.Errorf("err = %v, unused = %d, keys = %d", err, rep.UnusedDKIMKeys, len(rep.DKIM))
			}
		})
	}
}

func TestPlanDomains(t *testing.T) {
	tests := map[string]func(*Domain){
		"inactive":     func(d *Domain) { d.Active = false },
		"backup MX":    func(d *Domain) { d.BackupMX = true },
		"relay domain": func(d *Domain) { d.RelayAll = true },
	}
	for name, mutate := range tests {
		d := good()
		mutate(&d.Domains[0])
		if _, _, err := Plan(d, opts()); err == nil || !strings.Contains(err.Error(), "domain example.test is ") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestPlanRejectsInvalidAddress(t *testing.T) {
	d := good()
	d.Mailboxes[0].Address = "Al!ce@example.test"
	_, _, err := Plan(d, opts())
	if err == nil || !strings.Contains(err.Error(), `"al!ce@example.test"`) || !strings.Contains(err.Error(), "local part may only use") {
		t.Errorf("err = %v", err)
	}
}

func TestPlanGrants(t *testing.T) {
	d := good()
	d.SenderACLs = append(d.SenderACLs,
		SenderACL{LoggedInAs: "alice@example.test", SendAs: "sales@example.test"},
		SenderACL{LoggedInAs: "carol@example.org", SendAs: "x@example.org"})
	snap, rep, err := Plan(d, opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Grants) != 1 || rep.GrantsDropped != 1 {
		t.Errorf("grants %v, dropped %d", snap.Grants, rep.GrantsDropped)
	}
	d.SenderACLs = []SenderACL{{LoggedInAs: "alice@example.test", SendAs: "@example.test"}}
	if _, _, err := Plan(d, opts()); err == nil || !strings.Contains(err.Error(), "send-as grant for alice@example.test") {
		t.Errorf("domain-wide grant: %v", err)
	}
}

func TestReportNeverPrintsKeys(t *testing.T) {
	_, rep, err := Plan(good(), opts())
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	rep.Write(&b)
	out := b.String()
	if strings.Contains(out, "BEGIN") || strings.Contains(out, "AAAA") {
		t.Error("report leaks key material")
	}
}

func findingRows(rep Report, item string) int {
	for _, f := range rep.Findings {
		if f.Item == item {
			return f.Rows
		}
	}
	return -1
}

func TestUncheckedFileItems(t *testing.T) {
	for _, item := range []string{"sieve-scripts", "shared-folder-acls", "global-rspamd-maps"} {
		t.Run(item, func(t *testing.T) {
			d := good()
			d.Unchecked = map[string]string{item: "MAILCOW_RSPAMD_CUSTOM_DIR is not set"}
			_, rep, err := Plan(d, opts())
			if want := "cannot check " + item + ": MAILCOW_RSPAMD_CUSTOM_DIR is not set"; err == nil || err.Error() != want {
				t.Fatalf("err = %v, want %q", err, want)
			}
			var out strings.Builder
			rep.Write(&out)
			if !regexp.MustCompile(item + ` +not checked: MAILCOW_RSPAMD_CUSTOM_DIR is not set`).MatchString(out.String()) {
				t.Errorf("report:\n%s", out.String())
			}
			o := opts()
			o.Acknowledge = []string{item}
			if _, rep, err := Plan(d, o); err != nil {
				t.Errorf("acknowledged: %v", err)
			} else {
				out.Reset()
				rep.Write(&out)
				if !strings.Contains(out.String(), "acknowledged: "+item+" (not checked)") {
					t.Errorf("report:\n%s", out.String())
				}
			}
		})
	}
}
