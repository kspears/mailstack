package auth

import (
	"fmt"
	"testing"
	"time"
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
