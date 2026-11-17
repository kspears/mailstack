package main

import (
	"strings"
	"testing"
)

func TestServeIdentifierConfig(t *testing.T) {
	full := map[string]string{"MAILCTL_ACCESS_TEAM_DOMAIN": "example.cloudflareaccess.com", "MAILCTL_ACCESS_AUD": "tag", "MAILCTL_ADMINS": "a@example.test"}
	without := func(k string) map[string]string {
		m := map[string]string{}
		for key, v := range full {
			if key != k {
				m[key] = v
			}
		}
		return m
	}
	cases := []struct {
		name, listen, wantErr string
		env                   map[string]string
	}{
		{"complete", ":8080", "", full},
		{"no team domain", ":8080", "MAILCTL_ACCESS_TEAM_DOMAIN is not set", without("MAILCTL_ACCESS_TEAM_DOMAIN")},
		{"no aud", ":8080", "MAILCTL_ACCESS_AUD is not set", without("MAILCTL_ACCESS_AUD")},
		{"no admins", ":8080", "MAILCTL_ADMINS is not set", without("MAILCTL_ADMINS")},
		{"dev on loopback", "127.0.0.1:8080", "", map[string]string{"MAILCTL_DEV_IDENTITY": "dev@example.test"}},
		{"dev on localhost", "localhost:8080", "", map[string]string{"MAILCTL_DEV_IDENTITY": "dev@example.test"}},
		{"dev on ipv6 loopback", "[::1]:8080", "", map[string]string{"MAILCTL_DEV_IDENTITY": "dev@example.test"}},
		{"dev on all interfaces", ":8080", "only allowed when MAILCTL_LISTEN is a loopback", map[string]string{"MAILCTL_DEV_IDENTITY": "dev@example.test"}},
		{"dev on public address", "0.0.0.0:8080", "only allowed when MAILCTL_LISTEN is a loopback", map[string]string{"MAILCTL_DEV_IDENTITY": "dev@example.test"}},
	}
	for _, tc := range cases {
		e := &env{getenv: func(k string) string { return tc.env[k] }}
		_, err := e.identifier(tc.listen)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: error %v, want it to contain %q", tc.name, err, tc.wantErr)
		}
	}
}
