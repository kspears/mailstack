package main

import (
	"strings"
	"testing"
)

func TestSiteConfig(t *testing.T) {
	for _, tc := range []struct {
		name, wantErr string
		env           map[string]string
		wantOrigin    string
	}{
		{"complete", "", map[string]string{"MAILCTL_ADMIN_HOST": "Admin.Example.Test", "MAILCTL_TRUSTED_PROXY": "10.0.0.2"}, "https://admin.example.test"},
		{"dev", "", map[string]string{"MAILCTL_ADMIN_HOST": "localhost:8080", "MAILCTL_DEV": "1"}, "http://localhost:8080"},
		{"no host", "MAILCTL_ADMIN_HOST is not set", map[string]string{}, ""},
		{"proxy as a network", "is not one IP address", map[string]string{"MAILCTL_ADMIN_HOST": "admin.example.test", "MAILCTL_TRUSTED_PROXY": "10.0.0.0/24"}, ""},
	} {
		e := &env{getenv: func(k string) string { return tc.env[k] }}
		s, err := e.site()
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: error %v, want it to contain %q", tc.name, err, tc.wantErr)
		case tc.wantErr == "" && s.origin() != tc.wantOrigin:
			t.Errorf("%s: origin %q, want %q", tc.name, s.origin(), tc.wantOrigin)
		}
	}
}

func TestDevModeNeedsLoopback(t *testing.T) {
	for listen, refused := range map[string]bool{"127.0.0.1:8080": false, "localhost:8080": false, "[::1]:8080": false, ":8080": true, "0.0.0.0:8080": true} {
		vars := map[string]string{"MAILCTL_ADMIN_HOST": "localhost:8080", "MAILCTL_DEV": "1", "MAILCTL_LISTEN": listen, "MAILCTL_STATE": t.TempDir()}
		if !refused {
			// A loopback listen would go on to serve; binding an unusable port ends it.
			vars["MAILCTL_LISTEN"] = strings.Replace(listen, "8080", "notaport", 1)
		}
		e := &env{getenv: func(k string) string { return vars[k] }, stdout: new(strings.Builder)}
		err := e.serve(nil)
		if got := err != nil && strings.Contains(err.Error(), "only allowed when MAILCTL_LISTEN is a loopback"); got != refused {
			t.Errorf("listen %s: error %v, want refused=%v", listen, err, refused)
		}
	}
}
