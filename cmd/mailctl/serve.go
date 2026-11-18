package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/kspears/mailstack/internal/auth"
	"github.com/kspears/mailstack/internal/generate"
	"github.com/kspears/mailstack/internal/web"
)

func (e *env) serve(args []string) error {
	if len(args) > 0 {
		return usageError("serve")
	}
	listen := cmp.Or(e.getenv("MAILCTL_LISTEN"), ":8080")
	site, err := e.site()
	if err != nil {
		return err
	}
	if site.insecure && !loopback(listen) {
		return fmt.Errorf("MAILCTL_DEV=1 sends cookies over plain HTTP, so it is only allowed when MAILCTL_LISTEN is a loopback address such as 127.0.0.1:8080, not %q", listen)
	}
	cfg, err := generate.ConfigFromEnv(e.getenv)
	if err != nil {
		return err
	}
	admin, err := generate.Open(cfg, false)
	if err != nil {
		return err
	}
	defer admin.Close()

	logger := log.New(e.stdout, "", log.LstdFlags)
	service, err := site.service(admin, logger.Printf)
	if err != nil {
		return err
	}
	handler, err := web.New(web.Config{
		Admin: admin, Auth: service, AdminHost: site.adminHost, RspamdHost: site.rspamdHost, Insecure: site.insecure,
		TrustedProxy: site.proxy, ClientAddrHeader: site.addrHeader, Logf: logger.Printf,
	})
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
	logger.Printf("serving the admin UI for %s on %s", site.adminHost, ln.Addr())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// site is where the UI is served, read from the environment. The command line
// needs it too: an enrolment link has to name the hostname.
type site struct {
	adminHost, rspamdHost string
	insecure              bool
	proxy                 netip.Addr
	addrHeader            string
}

func (e *env) site() (site, error) {
	s := site{
		adminHost:  strings.ToLower(e.getenv("MAILCTL_ADMIN_HOST")),
		rspamdHost: strings.ToLower(e.getenv("MAILCTL_RSPAMD_HOST")),
		insecure:   e.getenv("MAILCTL_DEV") == "1",
		addrHeader: cmp.Or(e.getenv("MAILCTL_CLIENT_ADDR_HEADER"), "X-Forwarded-For"),
	}
	if s.adminHost == "" {
		return s, errors.New("MAILCTL_ADMIN_HOST is not set; it is the hostname the admin UI is served on, for example admin.example.test")
	}
	if proxy := e.getenv("MAILCTL_TRUSTED_PROXY"); proxy != "" {
		addr, err := netip.ParseAddr(proxy)
		if err != nil {
			return s, fmt.Errorf("MAILCTL_TRUSTED_PROXY=%q is not one IP address; a network is not accepted, because every host on it could then name the address that gets banned", proxy)
		}
		s.proxy = addr
	}
	return s, nil
}

func (s site) origin() string {
	if s.insecure {
		return "http://" + s.adminHost
	}
	return "https://" + s.adminHost
}

func (s site) service(admin *generate.Admin, logf func(string, ...any)) (*auth.Service, error) {
	return auth.New(admin.Store(), auth.Config{AdminHost: s.adminHost, Origin: s.origin(), Logf: logf})
}

func loopback(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	return err == nil && slices.Contains([]string{"127.0.0.1", "localhost", "::1"}, host)
}
