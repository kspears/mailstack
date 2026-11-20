package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The SHA-1 vectors of RFC 6238, appendix B, cut to six digits.
func TestTOTPMatchesTheRFC(t *testing.T) {
	secret := []byte("12345678901234567890")
	for at, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 20000000000: "353130"} {
		if got := totpCode(secret, totpStep(time.Unix(at, 0))); got != want {
			t.Errorf("at %d: %s, want %s", at, got, want)
		}
	}
}

func TestTOTPMatchAllowsOneStepOfDrift(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111109, 0)
	for offset, want := range map[time.Duration]bool{-60 * time.Second: false, -30 * time.Second: true, 0: true, 30 * time.Second: true, 60 * time.Second: false} {
		code := totpCode(secret, totpStep(now.Add(offset)))
		step, ok := totpMatch(secret, code, now)
		if ok != want || ok && step != totpStep(now.Add(offset)) {
			t.Errorf("a code from %v away: accepted %v at step %d, want %v", offset, ok, step, want)
		}
	}
	for _, typed := range []string{"", "08180", "0818044", "abcdef", "081 804"} {
		_, ok := totpMatch(secret, typed, now)
		if want := typed == "081 804"; ok != want {
			t.Errorf("typed %q: accepted %v, want %v", typed, ok, want)
		}
	}
	if _, ok := totpMatch(nil, "081804", now); ok {
		t.Error("an account with no authenticator accepted a code")
	}
}

func TestSingleLineKeepsOneCallToOneLine(t *testing.T) {
	var lines []string
	logf := SingleLine(func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	logf("passkey: %v", "bad origin\n2026/11/18 09:00:00 sign-in failed from=198.51.100.9 x\r y")
	logf("100%% literal %s", "%d")
	want := []string{"passkey: bad origin 2026/11/18 09:00:00 sign-in failed from=198.51.100.9 x  y", "100% literal %d"}
	if len(lines) != 2 || lines[0] != want[0] || lines[1] != want[1] {
		t.Errorf("got %q, want %q", lines, want)
	}
}

func TestSingleLineCapsTheLength(t *testing.T) {
	var lines []string
	logf := SingleLine(func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) })
	// A long path then a forged line, as a visitor would send it to land the forgery at
	// the start of the entry Docker splits off; é makes the cut fall inside a rune.
	logf("GET %q 404", "/"+strings.Repeat("é", 20<<10)+"2026/11/18 09:00:00 sign-in failed from=198.51.100.9 x")
	if len(lines) != 1 || len(lines[0]) > maxLogLine || !utf8.ValidString(lines[0]) || !strings.HasSuffix(lines[0], " [truncated]") {
		t.Errorf("got %d lines, first %d bytes, valid UTF-8 %v", len(lines), len(lines[0]), utf8.ValidString(lines[0]))
	}
	if strings.Contains(lines[0], "sign-in failed") {
		t.Error("the forged text survived the cut")
	}
}

func TestPasswordChecksWaitForASlot(t *testing.T) {
	s := &Service{checking: make(chan struct{}, 1), checkWait: 20 * time.Millisecond}
	if !s.acquire() {
		t.Fatal("a free slot was refused")
	}
	if s.acquire() {
		t.Fatal("a second check got a slot while the only one was taken")
	}
	go func() { time.Sleep(5 * time.Millisecond); <-s.checking }()
	if !s.acquire() {
		t.Error("a check did not get the slot freed while it waited")
	}
}
