package web

import (
	"net/http"

	"github.com/kspears/mailstack/internal/store"
)

// sessionOf returns the signed-in admin's session, which guard put there.
func sessionOf(r *http.Request) (store.Session, bool) {
	sess, ok := r.Context().Value(ctxKey{}).(store.Session)
	return sess, ok
}

// actorOf is the admin's address for the change log, or "" when signed out.
func actorOf(r *http.Request) string {
	sess, _ := sessionOf(r)
	return sess.Admin
}
