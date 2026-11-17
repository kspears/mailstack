package access

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	jwtHeader       = "Cf-Access-Jwt-Assertion"
	clockSkew       = 60 * time.Second
	keyMaxAge       = time.Hour
	keyMinRefetch   = time.Minute
	keyFetchTimeout = 5 * time.Second
	maxJWKSBytes    = 1 << 20
)

// keySource returns the team's current signing keys by key id.
type keySource func(ctx context.Context) (map[string]*rsa.PublicKey, error)

// Cloudflare verifies the Cloudflare Access JWT and checks the email against an allow-list.
type Cloudflare struct {
	issuer   string
	audience string
	admins   map[string]bool
	keys     *keyCache
	now      func() time.Time
}

// NewCloudflare verifies tokens issued by the team domain (for example
// example.cloudflareaccess.com) for one application audience tag, and admits
// only the listed emails. Keys are fetched from the team's certs endpoint.
func NewCloudflare(teamDomain, audience string, admins []string) *Cloudflare {
	client := &http.Client{Timeout: 5 * time.Second}
	return newCloudflare(teamDomain, audience, admins, fetchJWKS(client, "https://"+teamDomain+"/cdn-cgi/access/certs"), time.Now)
}

func newCloudflare(teamDomain, audience string, admins []string, src keySource, now func() time.Time) *Cloudflare {
	allowed := make(map[string]bool, len(admins))
	for _, a := range admins {
		allowed[strings.ToLower(strings.TrimSpace(a))] = true
	}
	return &Cloudflare{
		issuer:   "https://" + teamDomain,
		audience: audience,
		admins:   allowed,
		keys:     &keyCache{src: src, now: now},
		now:      now,
	}
}

type claims struct {
	Issuer    string          `json:"iss"`
	Audience  json.RawMessage `json:"aud"`
	Expires   *float64        `json:"exp"`
	NotBefore *float64        `json:"nbf"`
	IssuedAt  *float64        `json:"iat"`
	Email     string          `json:"email"`
}

func (c *Cloudflare) Identify(r *http.Request) (string, error) {
	token := r.Header.Get(jwtHeader)
	if token == "" {
		return "", errors.New("no " + jwtHeader + " header")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("token is not three dot-separated parts")
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &header); err != nil {
		return "", fmt.Errorf("token header: %w", err)
	}
	if header.Alg != "RS256" {
		return "", fmt.Errorf("token alg %q is not RS256", header.Alg)
	}
	key, err := c.keys.get(header.Kid)
	if err != nil {
		return "", err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("token signature is not base64url")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig); err != nil {
		return "", errors.New("token signature does not verify")
	}
	var cl claims
	if err := decodeSegment(parts[1], &cl); err != nil {
		return "", fmt.Errorf("token claims: %w", err)
	}
	return c.checkClaims(cl)
}

func (c *Cloudflare) checkClaims(cl claims) (string, error) {
	if cl.Issuer != c.issuer {
		return "", fmt.Errorf("token issuer %q is not %q", cl.Issuer, c.issuer)
	}
	if !audienceContains(cl.Audience, c.audience) {
		return "", errors.New("token audience does not include the configured tag")
	}
	now := c.now()
	if cl.Expires == nil || !now.Before(unix(*cl.Expires)) {
		return "", errors.New("token is expired or has no exp")
	}
	if cl.NotBefore != nil && unix(*cl.NotBefore).After(now.Add(clockSkew)) {
		return "", errors.New("token is not valid yet (nbf)")
	}
	if cl.IssuedAt != nil && unix(*cl.IssuedAt).After(now.Add(clockSkew)) {
		return "", errors.New("token was issued in the future (iat)")
	}
	email := strings.ToLower(strings.TrimSpace(cl.Email))
	if email == "" {
		return "", errors.New("token has no email claim")
	}
	if !c.admins[email] {
		return "", fmt.Errorf("%s is not in the admin allow-list", email)
	}
	return email, nil
}

func unix(sec float64) time.Time { return time.Unix(int64(sec), 0) }

func audienceContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, want)
}

func decodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return errors.New("not base64url")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("not JSON")
	}
	return nil
}

// keyCache holds the signing keys. It refetches on an unknown kid or when
// older than keyMaxAge, and never more than once per keyMinRefetch.
type keyCache struct {
	src keySource
	now func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func (k *keyCache) get(kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	age := now.Sub(k.fetched)
	if key, ok := k.keys[kid]; ok && age < keyMaxAge {
		return key, nil
	}
	if !k.fetched.IsZero() && age < keyMinRefetch {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	// Not the request's context: k.fetched is set whether or not the fetch worked, so a
	// request that was cancelled mid-fetch would otherwise leave every other request
	// without keys for keyMinRefetch.
	ctx, cancel := context.WithTimeout(context.Background(), keyFetchTimeout)
	defer cancel()
	keys, err := k.src(ctx)
	k.fetched = now
	if err != nil {
		return nil, fmt.Errorf("fetch signing keys: %w", err)
	}
	k.keys = keys
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	return key, nil
}

func fetchJWKS(client *http.Client, url string) keySource {
	return func(ctx context.Context) (map[string]*rsa.PublicKey, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("%s returned %s", url, resp.Status)
		}
		var set struct {
			Keys []struct {
				Kty, Kid, N, E string
			} `json:"keys"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
			return nil, fmt.Errorf("decode %s: %w", url, err)
		}
		keys := make(map[string]*rsa.PublicKey)
		for _, k := range set.Keys {
			if k.Kty != "RSA" {
				continue
			}
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		}
		return keys, nil
	}
}
