// Package access turns an HTTP request into an admin identity. The web UI
// depends only on Identifier, so the sign-in mechanism can be replaced.
package access

import "net/http"

// Identifier returns the admin making the request, or an error if there is none.
// The error is for server-side logs only and must never reach the client.
type Identifier interface {
	Identify(r *http.Request) (actor string, err error)
}

// Dev identifies every request as one fixed admin. For local development only.
type Dev struct{ Email string }

func (d Dev) Identify(*http.Request) (string, error) { return d.Email, nil }
