package web

import (
	"context"
	"net/http"
)

func contextWithActor(r *http.Request, actor string) context.Context {
	return context.WithValue(r.Context(), ctxKey{}, actor)
}

func actorOf(r *http.Request) string {
	actor, _ := r.Context().Value(ctxKey{}).(string)
	return actor
}
