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

// learnRun starts a fake rspamd controller and runs mailctl with the arguments args
// builds from its URL and a password file that holds the controller password.
func learnRun(t *testing.T, handler http.HandlerFunc, args func(url, pwFile string) []string, stdin string) (code int, stdout, stderr string, got *recorded) {
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
	var out, errOut bytes.Buffer
	code = run(args(srv.URL, pwFile), func(string) string { return "" }, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String(), got
}

func learnArgs(extra ...string) func(url, pwFile string) []string {
	return func(url, pwFile string) []string {
		return append([]string{"learn", "--controller", url, "--password-file", pwFile}, extra...)
	}
}

func TestLearnPostsTheMessageWithThePasswordHeader(t *testing.T) {
	for _, kind := range []string{"spam", "ham"} {
		code, out, errOut, got := learnRun(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"success":true}`)) },
			learnArgs(kind), "Subject: hi\r\n\r\nbody")
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
			code, _, errOut, _ := learnRun(t, tc.h, learnArgs("spam"), "msg")
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
	if code, _, errOut, got := learnRun(t, ok, learnArgs(), "msg"); code != 2 || got != nil || !strings.Contains(errOut, "usage: mailctl learn") {
		t.Errorf("no kind: code %d %q", code, errOut)
	}
	if code, _, _, _ := learnRun(t, ok, learnArgs("junk"), "msg"); code != 2 {
		t.Errorf("bad kind: code %d", code)
	}
	if code, _, _, _ := learnRun(t, ok, learnArgs("spam", "ham"), "msg"); code != 2 {
		t.Errorf("two kinds: code %d", code)
	}
	if code, _, errOut, got := learnRun(t, ok, learnArgs("spam"), ""); code != 1 || got != nil || !strings.Contains(errOut, "stdin") {
		t.Errorf("empty message: code %d %q", code, errOut)
	}
	if code, _, errOut, got := learnRun(t, ok, func(url, _ string) []string { return []string{"learn", "--controller", url, "spam"} }, "msg"); code != 2 || got != nil || !strings.Contains(errOut, "usage: mailctl learn") {
		t.Errorf("no --password-file: code %d %q", code, errOut)
	}
	if code, _, errOut, got := learnRun(t, ok, func(_, pwFile string) []string { return []string{"learn", "--password-file", pwFile, "spam"} }, "msg"); code != 2 || got != nil || !strings.Contains(errOut, "usage: mailctl learn") {
		t.Errorf("no --controller: code %d %q", code, errOut)
	}
	if code, _, errOut, got := learnRun(t, ok, func(url, _ string) []string {
		return []string{"learn", "--controller", url, "--password-file", "/nonexistent/pw", "spam"}
	}, "msg"); code != 1 || got != nil || !strings.Contains(errOut, "password file") {
		t.Errorf("unreadable password file: code %d %q", code, errOut)
	}
	if code, _, errOut, _ := learnRun(t, ok, func(_, pwFile string) []string {
		return []string{"learn", "--controller", "http://127.0.0.1:1", "--password-file", pwFile, "spam"}
	}, "msg"); code != 1 || !strings.HasPrefix(errOut, "error: ") {
		t.Errorf("unreachable rspamd: code %d %q", code, errOut)
	}
	if code, _, _, got := learnRun(t, ok, func(url, pwFile string) []string {
		return []string{"learn", "spam", "--controller", url + "/", "--password-file", pwFile}
	}, "msg"); code != 0 || got == nil || got.path != "/learnspam" {
		t.Errorf("flags after the kind, trailing slash: code %d %+v", code, got)
	}
}

func TestLearnNeedsNoStateDirectory(t *testing.T) {
	state := filepath.Join(t.TempDir(), "never-created")
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	pwFile := filepath.Join(t.TempDir(), "pw")
	if err := os.WriteFile(pwFile, []byte("pw"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"learn", "--controller", srv.URL, "--password-file", pwFile, "ham"},
		func(k string) string {
			if k == "MAILCTL_STATE" {
				return state
			}
			return ""
		}, strings.NewReader("msg"), &out, &errOut)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errOut.String())
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
