package status

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/kspears/mailstack/internal/generate"
)

var testNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func okDisk(used, avail, dev uint64) DiskInput {
	return DiskInput{Disk: Disk{Used: used, Avail: avail, Total: used + avail, Dev: dev}}
}

// healthy returns inputs where every card is green.
func healthy() Inputs {
	return Inputs{
		Now:       testNow,
		Heartbeat: testNow.Add(-time.Minute),
		Files:     generate.FilesCheck{State: generate.FilesMatch, Current: "g1"},
		Timeout:   time.Minute,
		Boxes:     map[string]Mailbox{"a@x": {Last: testNow.Add(-time.Hour)}},
		MailDisk:  okDisk(50, 50, 1),
		StateDisk: okDisk(50, 50, 1),
	}
}

func card(t *testing.T, r Report, title string) Card {
	t.Helper()
	for _, c := range r.Cards {
		if c.Title == title {
			return c
		}
	}
	t.Fatalf("no card %q in %+v", title, r.Cards)
	return Card{}
}

func TestEvaluateHealthy(t *testing.T) {
	r := Evaluate(healthy())
	if r.Verdict != Green || r.Headline != "No problems found" || len(r.Reasons) != 0 {
		t.Fatalf("got %+v", r)
	}
	var titles []string
	for _, c := range r.Cards {
		titles = append(titles, c.Title)
	}
	want := []string{"Postfix watcher", "Account files", "Pending change", "Last watcher verdict", "Last mail in", "Mail and state disk"}
	if !slices.Equal(titles, want) {
		t.Fatalf("cards = %v, want %v", titles, want)
	}
	if v := card(t, r, "Postfix watcher").Value; v != "Last seen 1 min ago" {
		t.Errorf("watcher value = %q", v)
	}
	if v := card(t, r, "Account files").Value; v != "In use: g1 · Matches the account store" {
		t.Errorf("files value = %q", v)
	}
	if v := card(t, r, "Last mail in").Value; v != "2026-11-20 03:00 PST (1 h ago)" {
		t.Errorf("mail value = %q", v)
	}
	if v := card(t, r, "Mail and state disk").Value; v != "50 B of 100 B used (50%)" {
		t.Errorf("disk value = %q", v)
	}
}

func TestCards(t *testing.T) {
	tests := []struct {
		name   string
		title  string
		mod    func(*Inputs)
		mark   Mark
		value  string
		reason string
	}{
		{"heartbeat at 5m", "Postfix watcher", func(in *Inputs) { in.Heartbeat = testNow.Add(-5 * time.Minute) }, Green, "Last seen 5 min ago", ""},
		{"heartbeat over 5m", "Postfix watcher", func(in *Inputs) { in.Heartbeat = testNow.Add(-5*time.Minute - time.Second) }, Red,
			"Postfix watcher last seen 5 min ago", "Postfix watcher last seen 5 min ago"},
		{"heartbeat missing", "Postfix watcher", func(in *Inputs) { in.Heartbeat = time.Time{} }, Yellow,
			"Postfix watcher has not reported yet", "Postfix watcher has not reported yet"},
		{"watcher off", "Postfix watcher", func(in *Inputs) { in.WatcherOff = true; in.Heartbeat = time.Time{} }, Neutral, "Watcher is off", ""},

		{"files none", "Account files", func(in *Inputs) { in.Files = generate.FilesCheck{State: generate.FilesNone} }, Neutral, "No account files yet", ""},
		{"files busy", "Account files", func(in *Inputs) { in.Files = generate.FilesCheck{State: generate.FilesBusy} }, Neutral, "A change is being applied", ""},
		{"files mismatch", "Account files", func(in *Inputs) { in.Files.State = generate.FilesMismatch }, Red,
			`The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list"`,
			`The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list"`},
		{"files mismatch with error", "Account files", func(in *Inputs) {
			in.Files.State = generate.FilesMismatch
			in.FilesErr = errors.New("boom")
		}, Red,
			`The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list": boom`,
			`The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list"`},
		{"store error", "Account files", func(in *Inputs) {
			in.Files = generate.FilesCheck{}
			in.FilesErr = errors.New("bad db")
			in.StoreErr = true
		}, Red, "Cannot read the account store: bad db", "Cannot read the account store: bad db"},

		{"no pending", "Pending change", func(in *Inputs) {}, Green, "None", ""},
		{"pending at timeout", "Pending change", func(in *Inputs) {
			in.Pending, in.PendingAt = "g2", testNow.Add(-time.Minute)
		}, Neutral, "g2, waiting 1 min", ""},
		{"pending over timeout", "Pending change", func(in *Inputs) {
			in.Pending, in.PendingAt = "g2", testNow.Add(-time.Minute-time.Second)
		}, Yellow, "g2, waiting 1 min", "A change has been pending for 1 min"},
		{"pending, watcher off", "Pending change", func(in *Inputs) {
			in.Pending, in.PendingAt, in.WatcherOff = "g2", testNow.Add(-time.Hour), true
		}, Neutral, "Watcher is off", ""},

		{"no verdict", "Last watcher verdict", func(in *Inputs) {}, Neutral, "No verdict yet", ""},
		{"verdict", "Last watcher verdict", func(in *Inputs) { in.WatcherStatus = "applied g1" }, Neutral, "applied g1", ""},

		{"mail at 2h-1s", "Last mail in", func(in *Inputs) {
			in.Boxes = map[string]Mailbox{"a": {Last: testNow.Add(-2*time.Hour + time.Second)}}
		}, Green, "2026-11-20 02:00 PST (1 h ago)", ""},
		{"mail at 2h", "Last mail in", func(in *Inputs) {
			in.Boxes = map[string]Mailbox{"a": {Last: testNow.Add(-2 * time.Hour)}}
		}, Yellow, "2026-11-20 02:00 PST (2 h ago)", "No mail received for 2 h"},
		{"newest across boxes", "Last mail in", func(in *Inputs) {
			in.Boxes = map[string]Mailbox{"a": {Last: testNow.Add(-5 * time.Hour)}, "b": {Last: testNow.Add(-time.Minute)}}
		}, Green, "2026-11-20 03:59 PST (1 min ago)", ""},
		{"no mail", "Last mail in", func(in *Inputs) { in.Boxes = map[string]Mailbox{"a": {Size: 5}} }, Neutral, "No mail yet", ""},
		{"no boxes", "Last mail in", func(in *Inputs) { in.Boxes = nil }, Neutral, "No mail yet", ""},
		{"no mail, one unreadable", "Last mail in", func(in *Inputs) {
			in.Boxes = map[string]Mailbox{"a": {Err: errors.New("x")}}
		}, Yellow, "No mail yet · 1 mailbox could not be read", "1 mailbox could not be read"},
		{"fresh mail, two unreadable", "Last mail in", func(in *Inputs) {
			in.Boxes = map[string]Mailbox{
				"a": {Last: testNow.Add(-time.Minute)},
				"b": {Err: errors.New("x")}, "c": {Err: errors.New("y")},
			}
		}, Yellow, "2026-11-20 03:59 PST (1 min ago) · 2 mailboxes could not be read", "2 mailboxes could not be read"},

		{"disk 79.9", "Mail and state disk", func(in *Inputs) { in.MailDisk, in.StateDisk = okDisk(799, 201, 1), okDisk(799, 201, 1) },
			Green, "799 B of 1000 B used (79%)", ""},
		{"disk 80.0", "Mail and state disk", func(in *Inputs) { in.MailDisk, in.StateDisk = okDisk(800, 200, 1), okDisk(800, 200, 1) },
			Yellow, "800 B of 1000 B used (80%)", "Mail and state disk is 80% full"},
		{"disk 89.9", "Mail and state disk", func(in *Inputs) { in.MailDisk, in.StateDisk = okDisk(899, 101, 1), okDisk(899, 101, 1) },
			Yellow, "899 B of 1000 B used (89%)", "Mail and state disk is 89% full"},
		{"disk 90.0", "Mail and state disk", func(in *Inputs) { in.MailDisk, in.StateDisk = okDisk(900, 100, 1), okDisk(900, 100, 1) },
			Red, "900 B of 1000 B used (90%)", "Mail and state disk is 90% full"},
		{"mail disk error", "Mail storage disk", func(in *Inputs) { in.MailDisk.Err = errors.New("nope") },
			Red, "Cannot read Mail storage disk: nope", "Cannot read Mail storage disk: nope"},
		{"state disk fine beside error", "State disk", func(in *Inputs) { in.MailDisk.Err = errors.New("nope") },
			Green, "50 B of 100 B used (50%)", ""},
		{"different devices", "State disk", func(in *Inputs) { in.StateDisk = okDisk(850, 150, 2) },
			Yellow, "850 B of 1000 B used (85%)", "State disk is 85% full"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := healthy()
			tt.mod(&in)
			r := Evaluate(in)
			c := card(t, r, tt.title)
			if c.Mark != tt.mark || c.Value != tt.value {
				t.Errorf("card = {%v %q}, want {%v %q}", c.Mark, c.Value, tt.mark, tt.value)
			}
			if tt.reason == "" {
				return
			}
			if !slices.Contains(r.Reasons, tt.reason) {
				t.Errorf("reasons %q lack %q", r.Reasons, tt.reason)
			}
		})
	}
}

func TestNeutralCardsNeverRaiseVerdict(t *testing.T) {
	in := healthy()
	in.WatcherOff = true
	in.Pending, in.PendingAt = "g2", testNow.Add(-time.Hour)
	in.Files = generate.FilesCheck{State: generate.FilesBusy}
	in.Boxes = nil
	r := Evaluate(in)
	if r.Verdict != Green || len(r.Reasons) != 0 {
		t.Fatalf("got %+v", r)
	}
}

func TestDiskGrouping(t *testing.T) {
	titles := func(in Inputs) []string {
		var out []string
		for _, c := range Evaluate(in).Cards {
			if c.Title == "Mail and state disk" || c.Title == "Mail storage disk" || c.Title == "State disk" {
				out = append(out, c.Title)
			}
		}
		return out
	}
	in := healthy()
	if got := titles(in); !slices.Equal(got, []string{"Mail and state disk"}) {
		t.Errorf("same dev: %v", got)
	}
	in.StateDisk = okDisk(50, 50, 2)
	if got := titles(in); !slices.Equal(got, []string{"Mail storage disk", "State disk"}) {
		t.Errorf("different dev: %v", got)
	}
	in = healthy()
	in.StateDisk.Err = errors.New("x")
	if got := titles(in); !slices.Equal(got, []string{"Mail storage disk", "State disk"}) {
		t.Errorf("error: %v", got)
	}
}

func TestVerdictAndReasonOrder(t *testing.T) {
	in := healthy()
	in.Heartbeat = time.Time{}                                                                    // yellow, card 1
	in.Files.State = generate.FilesMismatch                                                       // red, card 2
	in.Boxes = map[string]Mailbox{"a": {Last: testNow.Add(-3 * time.Hour), Err: errors.New("x")}} // two yellows
	in.MailDisk, in.StateDisk = okDisk(950, 50, 1), okDisk(950, 50, 1)                            // red, last
	r := Evaluate(in)
	if r.Verdict != Red || r.Headline != "Something is wrong" {
		t.Fatalf("verdict = %v %q", r.Verdict, r.Headline)
	}
	want := []string{
		`The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list"`,
		"Mail and state disk is 95% full",
		"Postfix watcher has not reported yet",
		"No mail received for 3 h",
		"1 mailbox could not be read",
	}
	if !slices.Equal(r.Reasons, want) {
		t.Fatalf("reasons = %q\nwant %q", r.Reasons, want)
	}
}

func TestHeadlines(t *testing.T) {
	in := healthy()
	in.Heartbeat = time.Time{}
	if r := Evaluate(in); r.Verdict != Yellow || r.Headline != "Needs attention" {
		t.Fatalf("got %v %q", r.Verdict, r.Headline)
	}
}

func TestMarkClass(t *testing.T) {
	for m, want := range map[Mark]string{Green: "green", Neutral: "neutral", Yellow: "yellow", Red: "red"} {
		if m.Class() != want {
			t.Errorf("%d: %q", m, m.Class())
		}
	}
}
