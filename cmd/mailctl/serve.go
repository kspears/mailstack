package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/kspears/mailstack/internal/access"
	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/web"
)

func (e *env) serve(args []string) error {
	if len(args) > 0 {
		return usageError("serve")
	}
	listen := e.getenv("MAILCTL_LISTEN")
	if listen == "" {
		listen = ":8080"
	}
	id, err := e.identifier(listen)
	if err != nil {
		return err
	}
	cfg, err := generate.ConfigFromEnv(e.getenv)
	if err != nil {
		return err
	}
	admin, err := generate.Open(cfg)
	if err != nil {
		return err
	}
	defer admin.Close()

	logger := log.New(e.stdout, "", log.LstdFlags)
	handler, err := web.New(web.Config{Admin: admin, Identifier: id, Logf: logger.Printf})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w (set MAILCTL_LISTEN to change it)", listen, err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      cfg.Timeout + 30*time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), cfg.Timeout+10*time.Second)
		defer cancel()
		srv.Shutdown(shutdown)
	}()
	logger.Printf("serving the admin UI on %s", ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// identifier builds the request identifier from the environment. The dev
// identity is only honoured on a loopback listen address.
func (e *env) identifier(listen string) (access.Identifier, error) {
	if dev := e.getenv("MAILCTL_DEV_IDENTITY"); dev != "" {
		if !loopback(listen) {
			return nil, fmt.Errorf("MAILCTL_DEV_IDENTITY skips sign-in, so it is only allowed when MAILCTL_LISTEN is a loopback address such as 127.0.0.1:8080, not %q", listen)
		}
		return access.Dev{Email: dev}, nil
	}
	team := e.getenv("MAILCTL_ACCESS_TEAM_DOMAIN")
	aud := e.getenv("MAILCTL_ACCESS_AUD")
	var admins []string
	for _, a := range strings.Split(e.getenv("MAILCTL_ADMINS"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			admins = append(admins, a)
		}
	}
	for _, need := range []struct {
		name  string
		unset bool
		hint  string
	}{
		{"MAILCTL_ACCESS_TEAM_DOMAIN", team == "", "the Cloudflare Access team domain, for example example.cloudflareaccess.com"},
		{"MAILCTL_ACCESS_AUD", aud == "", "the Access application audience tag"},
		{"MAILCTL_ADMINS", len(admins) == 0, "comma-separated admin emails"},
	} {
		if need.unset {
			return nil, fmt.Errorf("%s is not set; it is %s", need.name, need.hint)
		}
	}
	return access.NewCloudflare(team, aud, admins), nil
}

func loopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	return err == nil && slices.Contains([]string{"127.0.0.1", "localhost", "::1"}, host)
}
