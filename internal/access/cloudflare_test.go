package access

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

const testAUD = "aud-tag-1"

var testNow = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jsonSeg(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b64(b)
}

func signRS256(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	signing := jsonSeg(t, header) + "." + jsonSeg(t, claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

type fixture struct {
	key    *rsa.PrivateKey
	issuer string
	cf     *Cloudflare
	hits   *atomic.Int32
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := newKey(t)
	hits := new(atomic.Int32)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/cdn-cgi/access/certs" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256",
			"n": b64(key.N.Bytes()), "e": b64([]byte{1, 0, 1}),
		}}})
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	src := fetchJWKS(srv.Client(), srv.URL+"/cdn-cgi/access/certs")
	cf := newCloudflare(u.Host, testAUD, []string{"Admin@example.test"}, src, func() time.Time { return testNow })
	return &fixture{key: key, issuer: "https://" + u.Host, cf: cf, hits: hits}
}

func (f *fixture) claims(mod func(map[string]any)) map[string]any {
	c := map[string]any{
		"iss": f.issuer, "aud": []string{testAUD}, "email": "admin@example.test",
		"exp": testNow.Add(time.Hour).Unix(), "iat": testNow.Add(-time.Minute).Unix(), "nbf": testNow.Add(-time.Minute).Unix(),
	}
	if mod != nil {
		mod(c)
	}
	return c
}

func (f *fixture) token(t *testing.T, mod func(map[string]any)) string {
	return signRS256(t, f.key, map[string]any{"alg": "RS256", "kid": "k1"}, f.claims(mod))
}

func identify(cf *Cloudflare, token string) (string, error) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		r.Header.Set(jwtHeader, token)
	}
	r.Header.Set("Cf-Access-Authenticated-User-Email", "admin@example.test")
	return cf.Identify(r)
}

func TestValidTokenAccepted(t *testing.T) {
	f := newFixture(t)
	got, err := identify(f.cf, f.token(t, nil))
	if err != nil || got != "admin@example.test" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := identify(f.cf, f.token(t, func(c map[string]any) { c["aud"] = testAUD; c["email"] = "ADMIN@example.test" })); err != nil {
		t.Errorf("string aud and mixed-case email: %v", err)
	}
	if f.hits.Load() != 1 {
		t.Errorf("keys fetched %d times, want cached after first", f.hits.Load())
	}
}

func TestRejected(t *testing.T) {
	f := newFixture(t)
	other := newKey(t)
	hmacToken := func() string {
		signing := jsonSeg(t, map[string]any{"alg": "HS256", "kid": "k1"}) + "." + jsonSeg(t, f.claims(nil))
		m := hmac.New(sha256.New, f.key.N.Bytes())
		m.Write([]byte(signing))
		return signing + "." + b64(m.Sum(nil))
	}
	cases := map[string]string{
		"missing header": "",
		"malformed":      "not-a-jwt",
		"bad segments":   "a.b.c",
		"expired":        f.token(t, func(c map[string]any) { c["exp"] = testNow.Add(-time.Minute).Unix() }),
		"no exp":         f.token(t, func(c map[string]any) { delete(c, "exp") }),
		"nbf in future":  f.token(t, func(c map[string]any) { c["nbf"] = testNow.Add(5 * time.Minute).Unix() }),
		"iat in future":  f.token(t, func(c map[string]any) { c["iat"] = testNow.Add(5 * time.Minute).Unix() }),
		"wrong key":      signRS256(t, other, map[string]any{"alg": "RS256", "kid": "k1"}, f.claims(nil)),
		"wrong audience": f.token(t, func(c map[string]any) { c["aud"] = []string{"someone-else"} }),
		"wrong issuer":   f.token(t, func(c map[string]any) { c["iss"] = "https://evil.example.test" }),
		"no email":       f.token(t, func(c map[string]any) { delete(c, "email") }),
		"not an admin":   f.token(t, func(c map[string]any) { c["email"] = "stranger@example.test" }),
		"alg none":       jsonSeg(t, map[string]any{"alg": "none", "kid": "k1"}) + "." + jsonSeg(t, f.claims(nil)) + ".",
		"alg HS256":      hmacToken(),
		"unknown kid":    signRS256(t, f.key, map[string]any{"alg": "RS256", "kid": "nope"}, f.claims(nil)),
		"no kid or alg":  signRS256(t, f.key, map[string]any{}, f.claims(nil)),
	}
	for name, token := range cases {
		if got, err := identify(f.cf, token); err == nil {
			t.Errorf("%s: accepted as %q", name, got)
		}
	}
}

func TestKeyRefetchIsThrottled(t *testing.T) {
	f := newFixture(t)
	unknown := signRS256(t, f.key, map[string]any{"alg": "RS256", "kid": "nope"}, f.claims(nil))
	identify(f.cf, unknown)
	identify(f.cf, unknown)
	identify(f.cf, f.token(t, nil))
	if f.hits.Load() != 1 {
		t.Errorf("keys fetched %d times within a minute, want 1", f.hits.Load())
	}
	f.cf.keys.now = func() time.Time { return testNow.Add(2 * time.Minute) }
	identify(f.cf, unknown)
	if f.hits.Load() != 2 {
		t.Errorf("keys fetched %d times after a minute, want 2", f.hits.Load())
	}
}

func TestDev(t *testing.T) {
	got, err := Dev{Email: "dev@example.test"}.Identify(httptest.NewRequest(http.MethodGet, "/", nil))
	if err != nil || got != "dev@example.test" {
		t.Fatalf("got %q, %v", got, err)
	}
}
