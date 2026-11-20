package status

import (
	"fmt"
	"math"
	"time"

	"github.com/kspears/mailstack/internal/generate"
)

// Mark is the outcome of a check.
type Mark int

const (
	Green Mark = iota
	Neutral
	Yellow
	Red
)

// Class is the CSS class for the mark.
func (m Mark) Class() string {
	return [...]string{"green", "neutral", "yellow", "red"}[m]
}

type Card struct {
	Title string
	Mark  Mark
	Value string
}

type Report struct {
	Verdict  Mark
	Headline string
	Reasons  []string
	Cards    []Card
}

type DiskInput struct {
	Disk Disk
	Err  error
}

type Inputs struct {
	Now           time.Time
	WatcherOff    bool
	Heartbeat     time.Time // zero when missing
	HeartbeatErr  error     // reading it failed for a reason other than its absence
	Files         generate.FilesCheck
	FilesErr      error
	Pending       string
	PendingAt     time.Time
	Timeout       time.Duration
	WatcherStatus string
	Boxes         map[string]Mailbox
	MailDisk      DiskInput
	StateDisk     DiskInput
}

const (
	heartbeatMax = 5 * time.Minute
	staleMail    = 2 * time.Hour
)

// check is a card plus the reasons it adds to the report.
type check struct {
	Card
	reasons []string
}

// Evaluate turns the gathered inputs into the cards, verdict and reasons.
func Evaluate(in Inputs) Report {
	checks := []check{
		watcherCheck(in),
		filesCheck(in),
		pendingCheck(in),
		{Card: Card{"Last watcher verdict", Neutral, orDefault(in.WatcherStatus, "No verdict yet")}},
		mailCheck(in),
	}
	checks = append(checks, diskChecks(in)...)

	r := Report{Verdict: Green}
	for _, c := range checks {
		r.Cards = append(r.Cards, c.Card)
		if c.Mark == Yellow || c.Mark == Red {
			r.Verdict = max(r.Verdict, c.Mark)
		}
	}
	for _, want := range []Mark{Red, Yellow} {
		for _, c := range checks {
			if c.Mark == want {
				r.Reasons = append(r.Reasons, c.reasons...)
			}
		}
	}
	r.Headline = map[Mark]string{
		Green:  "No problems found",
		Yellow: "Needs attention",
		Red:    "Something is wrong",
	}[r.Verdict]
	return r
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func problem(title string, m Mark, value string) check {
	return check{Card{title, m, value}, []string{value}}
}

func watcherCheck(in Inputs) check {
	const title = "Postfix watcher"
	switch {
	case in.WatcherOff:
		return check{Card: Card{title, Neutral, "Watcher is off"}}
	case in.HeartbeatErr != nil:
		return problem(title, Red, fmt.Sprintf("Cannot read the watcher heartbeat: %v", in.HeartbeatErr))
	case in.Heartbeat.IsZero():
		return problem(title, Yellow, "Postfix watcher has not reported yet")
	}
	age := in.Now.Sub(in.Heartbeat)
	if age > heartbeatMax {
		return problem(title, Red, "Postfix watcher last seen "+Age(age)+" ago")
	}
	return check{Card: Card{title, Green, "Last seen " + Age(age) + " ago"}}
}

func filesCheck(in Inputs) check {
	const title = "Account files"
	switch {
	case in.FilesErr != nil && in.Files.State != generate.FilesMismatch:
		return problem(title, Red, fmt.Sprintf("Cannot check the account files: %v", in.FilesErr))
	case in.Files.State == generate.FilesNone:
		return check{Card: Card{title, Neutral, "No account files yet"}}
	case in.Files.State == generate.FilesBusy:
		return check{Card: Card{title, Neutral, "A change is being applied"}}
	case in.Files.State == generate.FilesMismatch:
		reason := `The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list"`
		value := reason
		if in.FilesErr != nil {
			value += fmt.Sprintf(": %v", in.FilesErr)
		}
		return check{Card{title, Red, value}, []string{reason}}
	}
	return check{Card: Card{title, Green, "In use: " + in.Files.Current + " · Matches the account store"}}
}

func pendingCheck(in Inputs) check {
	const title = "Pending change"
	switch {
	case in.WatcherOff:
		return check{Card: Card{title, Neutral, "Watcher is off"}}
	case in.Pending == "":
		return check{Card: Card{title, Green, "None"}}
	}
	age := in.Now.Sub(in.PendingAt)
	value := fmt.Sprintf("%s, waiting %s", in.Pending, Age(age))
	if age > in.Timeout {
		return check{Card{title, Yellow, value}, []string{"A change has been pending for " + Age(age)}}
	}
	return check{Card: Card{title, Neutral, value}}
}

func mailCheck(in Inputs) check {
	const title = "Last mail in"
	var newest time.Time
	unreadable := 0
	for _, b := range in.Boxes {
		if b.Err != nil {
			unreadable++
			continue
		}
		if b.Last.After(newest) {
			newest = b.Last
		}
	}

	c := check{Card: Card{title, Green, ""}}
	age := in.Now.Sub(newest)
	if newest.IsZero() {
		c.Mark, c.Value = Neutral, "No mail yet"
	} else {
		c.Value = fmt.Sprintf("%s (%s ago)", Stamp(newest), Age(age))
	}
	if !newest.IsZero() && age >= staleMail {
		c.Mark = Yellow
		c.reasons = append(c.reasons, "No mail received for "+Age(age))
	}
	if unreadable > 0 {
		msg := fmt.Sprintf("%d mailboxes could not be read", unreadable)
		if unreadable == 1 {
			msg = "1 mailbox could not be read"
		}
		c.Mark = max(c.Mark, Yellow)
		c.Value += " · " + msg
		c.reasons = append(c.reasons, msg)
	}
	return c
}

func diskChecks(in Inputs) []check {
	if in.MailDisk.Err == nil && in.StateDisk.Err == nil && in.MailDisk.Disk.Dev == in.StateDisk.Disk.Dev {
		return []check{diskCheck("Mail and state disk", in.MailDisk)}
	}
	return []check{diskCheck("Mail storage disk", in.MailDisk), diskCheck("State disk", in.StateDisk)}
}

func diskCheck(title string, in DiskInput) check {
	if in.Err != nil {
		return problem(title, Red, fmt.Sprintf("Cannot read %s: %v", title, in.Err))
	}
	p := in.Disk.Percent()
	shown := int(math.Floor(p))
	c := check{Card: Card{title, Green, fmt.Sprintf("%s of %s used (%d%%)", Size(int64(in.Disk.Used)), Size(int64(in.Disk.Total)), shown)}}
	switch {
	case p >= 90:
		c.Mark = Red
	case p >= 80:
		c.Mark = Yellow
	default:
		return c
	}
	c.reasons = []string{fmt.Sprintf("%s is %d%% full", title, shown)}
	return c
}
