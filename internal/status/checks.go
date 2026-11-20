package status

import (
	"cmp"
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
	Note  string // a second, quieter line; empty for most cards
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
	Now        time.Time
	WatcherOff bool
	Watcher    generate.WatcherState
	Files      generate.FilesCheck
	FilesErr   error // explains FilesError, or a FilesMismatch caused by an unreadable current
	Timeout    time.Duration
	Boxes      map[string]Mailbox
	MailDisk   DiskInput
	StateDisk  DiskInput
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

func problem(title string, m Mark, value string) check {
	return check{Card{title, m, value, ""}, []string{value}}
}

func watcherCheck(in Inputs) check {
	const title = "Postfix watcher"
	switch {
	case in.WatcherOff:
		return check{Card: Card{title, Neutral, "Watcher is off", ""}}
	case in.Watcher.HeartbeatErr != nil:
		return problem(title, Red, fmt.Sprintf("Cannot read the watcher heartbeat: %v", in.Watcher.HeartbeatErr))
	case in.Watcher.Heartbeat.IsZero():
		return problem(title, Yellow, "Postfix watcher has not reported yet")
	}
	age := in.Now.Sub(in.Watcher.Heartbeat)
	if age > heartbeatMax {
		return problem(title, Red, "Postfix watcher last seen "+Age(age)+" ago")
	}
	return check{Card: Card{title, Green, "Last seen " + Age(age) + " ago", ""}}
}

// filesCheck also carries the watcher's last verdict when it rejected a change. That
// is history, since mailctl rolled the change back and reported it then, so it adds a
// line without changing the mark.
func filesCheck(in Inputs) check {
	c := filesState(in)
	if in.WatcherOff {
		return c // a verdict left from before the watcher was turned off is stale
	}
	if msg := rejected(in.Watcher.Status, in.Files.Current); msg != "" {
		c.Note = "Last change was rejected: " + msg
	}
	return c
}

// rejected returns the watcher's message when its last verdict was an error about a
// generation other than the one in use.
func rejected(status, current string) string {
	v, ok := generate.ParseVerdict(status)
	if !ok || !v.Rejected || v.ID == current {
		return ""
	}
	return cmp.Or(v.Message, "no reason given")
}

func filesState(in Inputs) check {
	const title = "Account files"
	switch in.Files.State {
	case generate.FilesError:
		return problem(title, Red, fmt.Sprintf("Cannot check the account files: %v", in.FilesErr))
	case generate.FilesNone:
		return check{Card: Card{title, Neutral, "No account files yet", ""}}
	case generate.FilesBusy:
		return check{Card: Card{title, Neutral, "A change is being applied", ""}}
	case generate.FilesMismatch:
		reason := `The files in use do not match the account store; run "mailctl apply" after checking "mailctl mailbox list"`
		value := reason
		if in.FilesErr != nil {
			value += fmt.Sprintf(": %v", in.FilesErr)
		}
		return check{Card{title, Red, value, ""}, []string{reason}}
	}
	return check{Card: Card{title, Green, "In use: " + in.Files.Current + " · Matches the account store", ""}}
}

func pendingCheck(in Inputs) check {
	const title = "Pending change"
	switch {
	case in.WatcherOff:
		return check{Card: Card{title, Neutral, "Watcher is off", ""}}
	case in.Watcher.Pending == "":
		return check{Card: Card{title, Green, "None", ""}}
	}
	age := in.Now.Sub(in.Watcher.PendingAt)
	value := fmt.Sprintf("%s, waiting %s", in.Watcher.Pending, Age(age))
	if age > in.Timeout {
		return check{Card{title, Yellow, value, ""}, []string{"A change has been pending for " + Age(age)}}
	}
	return check{Card: Card{title, Neutral, value, ""}}
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

	c := check{Card: Card{title, Neutral, "No mail yet", ""}}
	if !newest.IsZero() {
		age := in.Now.Sub(newest)
		c.Mark, c.Value = Green, fmt.Sprintf("%s (%s ago)", Stamp(newest), Age(age))
		if age >= staleMail {
			c.Mark = Yellow
			c.reasons = append(c.reasons, "No mail received for "+Age(age))
		}
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
	c := check{Card: Card{title, Green, fmt.Sprintf("%s of %s used (%d%%)", Size(int64(in.Disk.Used)), Size(int64(in.Disk.Total)), shown), ""}}
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
