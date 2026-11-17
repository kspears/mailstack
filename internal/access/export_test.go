package access

import (
	"net/http"
	"time"
)

// NewCloudflareForTest builds a verifier that fetches keys with client from certsURL
// and reads the clock from now, for tests outside this package.
func NewCloudflareForTest(teamDomain, audience string, admins []string, client *http.Client, certsURL string, now func() time.Time) *Cloudflare {
	return newCloudflare(teamDomain, audience, admins, fetchJWKS(client, certsURL), now)
}
