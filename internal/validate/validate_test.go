package validate

import (
	"strings"
	"testing"

	"github.com/kspears/mailstack/internal/store"
)

func TestAddress(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  string
	}{
		{in: "Alice@Example.TEST", want: "alice@example.test"},
		{in: "  a.b+tag@example.org ", want: "a.b+tag@example.org"},
		{in: "a_b-c=d@sub.example.test", want: "a_b-c=d@sub.example.test"},
		{in: "", wantErr: "expected local@domain"},
		{in: "alice", wantErr: "expected local@domain"},
		{in: "a@b@example.test", wantErr: "expected local@domain"},
		{in: "@example.test", wantErr: "catch-all"},
		{in: "*@example.test", wantErr: "catch-all"},
		{in: ".a@example.test", wantErr: "bad local part"},
		{in: "a.@example.test", wantErr: "bad local part"},
		{in: "a..b@example.test", wantErr: "bad local part"},
		{in: "a/b@example.test", wantErr: "local part may only use"},
		{in: "a b@example.test", wantErr: "local part may only use"},
		{in: "a:b@example.test", wantErr: "local part may only use"},
		{in: "a,b@example.test", wantErr: "local part may only use"},
		{in: strings.Repeat("a", 65) + "@example.test", wantErr: "bad local part"},
		{in: "a@localhost", wantErr: "bad domain"},
		{in: "a@-example.test", wantErr: "bad domain"},
		{in: "a@example..test", wantErr: "bad domain"},
		{in: "a@exa_mple.test", wantErr: "bad domain"},
		{in: "a@example.test.", wantErr: "bad domain"},
	}
	for _, tc := range tests {
		got, err := Address(tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Address(%q) error = %v, want containing %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("Address(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestPassword(t *testing.T) {
	tests := []struct {
		pw      string
		wantErr bool
	}{
		{"short", true},
		{"elevenchars", true},
		{"twelve chars", false},
		{strings.Repeat("x", 72), false},
		{strings.Repeat("x", 73), true},
	}
	for _, tc := range tests {
		if err := Password(tc.pw); (err != nil) != tc.wantErr {
			t.Errorf("Password(len %d) error = %v, wantErr %v", len(tc.pw), err, tc.wantErr)
		}
	}
}

func mb(addr string, st store.State) store.Mailbox {
	return store.Mailbox{Address: addr, Hash: "{BLF-CRYPT}x", State: st}
}

func TestConsistency(t *testing.T) {
	base := func() store.Snapshot {
		return store.Snapshot{
			Domains:   []string{"example.org", "example.test"},
			Mailboxes: []store.Mailbox{mb("alice@example.test", store.Active), mb("off@example.test", store.Disabled)},
		}
	}
	tests := []struct {
		name    string
		mutate  func(*store.Snapshot)
		wantErr string
	}{
		{"valid", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "info@example.test", Targets: []string{"alice@example.test", "me@example.net"}}}
		}, ""},
		{"mailbox in unhosted domain", func(s *store.Snapshot) {
			s.Mailboxes = append(s.Mailboxes, mb("x@example.net", store.Active))
		}, "not a hosted domain"},
		{"alias in unhosted domain", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "x@example.net", Targets: []string{"alice@example.test"}}}
		}, "not a hosted domain"},
		{"alias collides with mailbox", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "alice@example.test", Targets: []string{"me@example.net"}}}
		}, "is a mailbox"},
		{"unresolved local target", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "info@example.test", Targets: []string{"ghost@example.test"}}}
		}, "not a mailbox or alias"},
		{"disabled target", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "info@example.test", Targets: []string{"off@example.test"}}}
		}, "disabled"},
		{"duplicate target", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "info@example.test", Targets: []string{"alice@example.test", "alice@example.test"}}}
		}, "twice"},
		{"self loop", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "a@example.test", Targets: []string{"a@example.test"}}}
		}, "alias loop: a@example.test -> a@example.test"},
		{"two hop loop", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{
				{Address: "a@example.test", Targets: []string{"b@example.test"}},
				{Address: "b@example.test", Targets: []string{"a@example.test"}},
			}
		}, "alias loop: a@example.test -> b@example.test -> a@example.test"},
		{"multi hop loop behind a tail", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{
				{Address: "a@example.test", Targets: []string{"b@example.test"}},
				{Address: "b@example.test", Targets: []string{"alice@example.test", "c@example.org"}},
				{Address: "c@example.org", Targets: []string{"d@example.test"}},
				{Address: "d@example.test", Targets: []string{"b@example.test"}},
			}
		}, "alias loop: b@example.test -> c@example.org -> d@example.test -> b@example.test"},
		{"diamond is not a loop", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{
				{Address: "a@example.test", Targets: []string{"b@example.test", "c@example.test"}},
				{Address: "b@example.test", Targets: []string{"d@example.test"}},
				{Address: "c@example.test", Targets: []string{"d@example.test"}},
				{Address: "d@example.test", Targets: []string{"alice@example.test"}},
			}
		}, ""},
		{"mailbox name with plus", func(s *store.Snapshot) {
			s.Mailboxes = append(s.Mailboxes, mb("a+b@example.test", store.Active))
		}, `a+b@example.test: "+" is reserved for plus-addressing and cannot be part of a mailbox or alias name`},
		{"alias name with plus", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "in+fo@example.test", Targets: []string{"alice@example.test"}}}
		}, `in+fo@example.test: "+" is reserved for plus-addressing`},
		{"hosted target with plus", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "info@example.test", Targets: []string{"alice+news@example.test"}}}
		}, "target the base address alice@example.test"},
		{"external target with plus", func(s *store.Snapshot) {
			s.Aliases = []store.Alias{{Address: "info@example.test", Targets: []string{"me+news@example.net"}}}
		}, ""},
		{"grant for missing mailbox", func(s *store.Snapshot) {
			s.Grants = []store.Grant{{Mailbox: "ghost@example.test", Address: "x@example.test"}}
		}, "no such mailbox"},
		{"grant in unhosted domain", func(s *store.Snapshot) {
			s.Grants = []store.Grant{{Mailbox: "alice@example.test", Address: "x@example.net"}}
		}, "not a hosted domain"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutate(&s)
			err := Consistency(s)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestHostedName(t *testing.T) {
	if got, err := HostedName("Alice@Example.Test"); err != nil || got != "alice@example.test" {
		t.Errorf("HostedName = %q, %v", got, err)
	}
	for _, bad := range []string{"a+b@example.test", "+@example.test", "@example.test"} {
		if _, err := HostedName(bad); err == nil {
			t.Errorf("HostedName(%q) accepted", bad)
		}
	}
}
