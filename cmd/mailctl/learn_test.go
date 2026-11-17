package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type recorded struct {
	path, password, body string
}

func learnRun(t *testing.T, handler http.HandlerFunc, args []string, stdin string, mod func(map[string]string)) (code int, stdout, stderr string, got *recorded) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = &recorded{r.URL.Path, r.Header.Get("Password"), string(b)}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("s3cret-controller-pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"MAILCTL_RSPAMD_URL": srv.URL, "MAILCTL_RSPAMD_PASSWORD_FILE": pwFile}
	if mod != nil {
		mod(vars)
	}
	var out, errOut bytes.Buffer
	code = run(args, func(k string) string { return vars[k] }, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String(), got
}

func TestLearnPostsTheMessageWithThePasswordHeader(t *testing.T) {
	for _, kind := range []string{"spam", "ham"} {
		code, out, errOut, got := learnRun(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"success":true}`)) },
			[]string{"learn", kind}, "Subject: hi\r\n\r\nbody", nil)
		if code != 0 || got == nil || got.path != "/learn"+kind || got.password != "s3cret-controller-pw" || got.body != "Subject: hi\r\n\r\nbody" {
			t.Errorf("%s: code %d stderr %q got %+v", kind, code, errOut, got)
		}
		if strings.Contains(out+errOut, "s3cret") {
			t.Errorf("%s: the password was printed", kind)
		}
	}
}

func TestLearnOutcomes(t *testing.T) {
	reply := func(code int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			w.Write([]byte(body))
		}
	}
	cases := []struct {
		name    string
		h       http.HandlerFunc
		wantErr string
	}{
		{"learned", reply(200, `{"success":true}`), ""},
		{"already learned, 208", reply(208, `{"error":"<abc> has been already learned as spam, ignore it"}`), ""},
		{"already learned, 4xx", reply(404, `{"error":"message has been already learned as ham"}`), ""},
		{"too few tokens", reply(404, `{"error":"message has too few tokens"}`), ""},
		{"wrong password", reply(403, `{"error":"Unauthorized"}`), "403"},
		{"server error", reply(500, `{"error":"redis is down"}`), "redis is down"},
		{"not json", reply(502, `bad gateway`), "bad gateway"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, errOut, _ := learnRun(t, tc.h, []string{"learn", "spam"}, "msg", nil)
			if tc.wantErr == "" && code != 0 {
				t.Errorf("code %d: %s", code, errOut)
			}
			if tc.wantErr != "" && (code != 1 || !strings.HasPrefix(errOut, "error: ") || !strings.Contains(errOut, tc.wantErr)) {
				t.Errorf("code %d stderr %q, want it to contain %q", code, errOut, tc.wantErr)
			}
			if strings.Contains(errOut, "s3cret") {
				t.Error("the password was printed")
			}
		})
	}
}

func TestLearnArgumentsAndSettings(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {}
	if code, _, errOut, got := learnRun(t, ok, []string{"learn"}, "msg", nil); code != 2 || got != nil || !strings.Contains(errOut, "usage: mailctl learn") {
		t.Errorf("no kind: code %d %q", code, errOut)
	}
	if code, _, _, _ := learnRun(t, ok, []string{"learn", "junk"}, "msg", nil); code != 2 {
		t.Errorf("bad kind: code %d", code)
	}
	if code, _, errOut, got := learnRun(t, ok, []string{"learn", "spam"}, "", nil); code != 1 || got != nil || !strings.Contains(errOut, "stdin") {
		t.Errorf("empty message: code %d %q", code, errOut)
	}
	if code, _, errOut, _ := learnRun(t, ok, []string{"learn", "spam"}, "msg", func(v map[string]string) { delete(v, "MAILCTL_RSPAMD_PASSWORD_FILE") }); code != 1 || !strings.Contains(errOut, "password file (MAILCTL_RSPAMD_PASSWORD_FILE, default /run/secrets/rspamd-controller-password)") {
		t.Errorf("no password file: code %d %q", code, errOut)
	}
	if code, _, errOut, _ := learnRun(t, ok, []string{"learn", "spam"}, "msg", func(v map[string]string) { v["MAILCTL_RSPAMD_PASSWORD_FILE"] = "/nonexistent/pw" }); code != 1 || !strings.Contains(errOut, "password file") {
		t.Errorf("unreadable password file: code %d %q", code, errOut)
	}
	if code, _, errOut, _ := learnRun(t, ok, []string{"learn", "spam"}, "msg", func(v map[string]string) { v["MAILCTL_RSPAMD_URL"] = "http://127.0.0.1:1" }); code != 1 || !strings.HasPrefix(errOut, "error: ") {
		t.Errorf("unreachable rspamd: code %d %q", code, errOut)
	}
}

func TestLearnNeedsNoStateDirectory(t *testing.T) {
	state := filepath.Join(t.TempDir(), "never-created")
	code, _, errOut, _ := learnRun(t, func(http.ResponseWriter, *http.Request) {}, []string{"learn", "ham"}, "msg",
		func(v map[string]string) { v["MAILCTL_STATE"] = state })
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut)
	}
	if _, err := os.Stat(state); err == nil {
		t.Error("learn created the state directory")
	}
}

func TestInstallSelf(t *testing.T) {
	dir := t.TempDir()
	var out, errOut bytes.Buffer
	if code := run([]string{"install-self", dir}, func(string) string { return "" }, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
	}
	st, err := os.Stat(filepath.Join(dir, "mailctl"))
	if err != nil || st.Mode().Perm() != 0o755 || st.Size() == 0 {
		t.Fatalf("installed binary: %v %v", st, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	if code := run([]string{"install-self", filepath.Join(dir, "missing")}, func(string) string { return "" }, strings.NewReader(""), &out, &errOut); code != 1 {
		t.Errorf("a missing directory: code %d", code)
	}
	if code := run([]string{"install-self"}, func(string) string { return "" }, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Errorf("no directory: code %d", code)
	}
}
