package access_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/kspears/mailstack/internal/access"
	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/web"
)

var now = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	seg := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b64(b)
	}
	signing := seg(map[string]any{"alg": "RS256", "kid": "k1"}) + "." + seg(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

// TestWebHandlerWithCloudflareIdentifier drives the real handler with the real
// verifier, so a change to either that lets a bad token through fails here.
func TestWebHandlerWithCloudflareIdentifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	certs := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "n": b64(key.N.Bytes()), "e": b64([]byte{1, 0, 1}),
		}}})
	}))
	defer certs.Close()
	u, _ := url.Parse(certs.URL)
	const aud = "aud-tag-1"
	cf := access.NewCloudflareForTest(u.Host, aud, []string{"admin@example.test"}, certs.Client(), certs.URL, func() time.Time { return now })

	dir := t.TempDir()
	admin, err := generate.Open(generate.Config{State: filepath.Join(dir, "state"), MailRoot: filepath.Join(dir, "mail"), WatcherOff: true}, false)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	h, err := web.New(web.Config{Admin: admin, Identifier: cf, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}

	claims := func(mod func(map[string]any)) map[string]any {
		c := map[string]any{
			"iss": "https://" + u.Host, "aud": []string{aud}, "email": "admin@example.test",
			"exp": now.Add(time.Hour).Unix(), "iat": now.Add(-time.Minute).Unix(),
		}
		if mod != nil {
			mod(c)
		}
		return c
	}
	cases := []struct {
		name  string
		token string
		want  int
	}{
		{"valid", sign(t, key, claims(nil)), http.StatusOK},
		{"missing", "", http.StatusForbidden},
		{"expired", sign(t, key, claims(func(c map[string]any) { c["exp"] = now.Add(-time.Minute).Unix() })), http.StatusForbidden},
		{"wrong signature", sign(t, other, claims(nil)), http.StatusForbidden},
		{"wrong audience", sign(t, key, claims(func(c map[string]any) { c["aud"] = []string{"some-other-app"} })), http.StatusForbidden},
		{"not an admin", sign(t, key, claims(func(c map[string]any) { c["email"] = "mallory@example.test" })), http.StatusForbidden},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodGet, "/mailboxes", nil)
		r.Host = "mail.example.test"
		if tc.token != "" {
			r.Header.Set("Cf-Access-Jwt-Assertion", tc.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, w.Code, tc.want)
		}
	}
}
