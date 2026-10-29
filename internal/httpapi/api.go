// Package httpapi serves the in-process /api/v1 admin skeleton on beaver serve.
package httpapi

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/dkimout"
	"github.com/BeaverMail/beavermaild/internal/domaintls"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/servicestatus"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
)

const (
	apiPrefix     = "/api/v1"
	sessionCookie = "beaver_session"
	sessionTTL    = 12 * time.Hour
)

// Options configures the HTTP API server.
type Options struct {
	Listen string
	// PlainListen is an optional cleartext listener serving only ACME HTTP-01 and redirects to HTTPS.
	PlainListen string
	Dir         *directory.Local
	Log         *slog.Logger
	AuthKey     string
	Certs       *tlsload.Certs
	AuthGate    security.AuthGate
	// Blobs is required for domain/account delete (mail purge).
	Blobs *blob.FS
	// Queue is the outbound mail queue (nil disables queue endpoints).
	Queue *mail.Queue
	// Inbox is used for domain storage usage aggregates (nil → storage_used 0).
	Inbox *mail.Inbox
	// DKIM registry is updated when a domain is created with DKIM enabled.
	DKIM *dkimout.Registry
	// DomainTLS handles per-domain custom/ACME certs (nil disables ACME HTTP-01).
	DomainTLS *domaintls.Manager
	// Remote configures outbound delivery probes (nil/empty disables).
	Remote *smtp.RemoteConfig
	// Status is the process-wide service registry (nil disables /status).
	Status *servicestatus.Registry
	// LogFile is the rotating JSON log path for /logs history (empty disables).
	LogFile string
	// LogFileKeep is the rotation file count for history reads (0 = default).
	LogFileKeep int
	// UI is the embedded admin SPA (nil when not attached).
	UI fs.FS
}

// Server is the optional admin/API HTTP listener.
type Server struct {
	listen      string
	plainListen string
	dir         *directory.Local
	log         *slog.Logger
	authKey     []byte
	certs       *tlsload.Certs
	useTLS      bool
	authGate    security.AuthGate
	blobs       *blob.FS
	queue       *mail.Queue
	inbox       *mail.Inbox
	dkim        *dkimout.Registry
	domainTLS   *domaintls.Manager
	remote      *smtp.RemoteConfig
	status      *servicestatus.Registry
	logFile     string
	logFileKeep int
	ui          fs.FS
	mux         *http.ServeMux
}

// New builds an API server. Call Serve to bind listen.
func New(opts Options) (*Server, error) {
	listen := strings.TrimSpace(opts.Listen)
	if listen == "" {
		return nil, fmt.Errorf("httpapi: listen address required")
	}
	if opts.Dir == nil {
		return nil, fmt.Errorf("httpapi: directory required")
	}
	key, err := decodeAuthKey(opts.AuthKey)
	if err != nil {
		return nil, err
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	gate := opts.AuthGate
	if gate == nil {
		gate = security.NopGate{}
	}
	useTLS := !isLoopbackListen(listen)
	if useTLS && (opts.Certs == nil || opts.Certs.Config() == nil) {
		return nil, fmt.Errorf("httpapi: non-loopback listen %q requires TLS (tls.cert_file/key_file or tls.acme_hosts)", listen)
	}
	plainListen := strings.TrimSpace(opts.PlainListen)
	if plainListen != "" && !useTLS {
		return nil, fmt.Errorf("httpapi: plain_listen %q needs a TLS listen to redirect to", plainListen)
	}
	s := &Server{
		listen:      listen,
		plainListen: plainListen,
		dir:         opts.Dir,
		log:         log,
		authKey:     key,
		certs:       opts.Certs,
		useTLS:      useTLS,
		authGate:    gate,
		blobs:       opts.Blobs,
		queue:       opts.Queue,
		inbox:       opts.Inbox,
		dkim:        opts.DKIM,
		domainTLS:   opts.DomainTLS,
		remote:      opts.Remote,
		status:      opts.Status,
		logFile:     strings.TrimSpace(opts.LogFile),
		logFileKeep: opts.LogFileKeep,
		ui:          opts.UI,
		mux:         http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) handler() http.Handler {
	if s.domainTLS != nil {
		return s.domainTLS.HTTPHandler(s.mux)
	}
	return s.mux
}

// Serve binds listen and serves until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	var ln net.Listener
	var err error
	if s.useTLS {
		ln, err = s.certs.Listen("tcp", s.listen)
	} else {
		ln, err = net.Listen("tcp", s.listen)
	}
	if err != nil {
		if s.status != nil {
			s.status.Set(servicestatus.Entry{
				ID:     "http",
				Name:   "HTTP admin",
				Listen: s.listen,
				State:  servicestatus.StateError,
				Error:  err.Error(),
			})
		}
		return fmt.Errorf("httpapi: listen: %w", err)
	}
	if s.status != nil {
		s.status.Set(servicestatus.Entry{
			ID:     "http",
			Name:   "HTTP admin",
			Listen: ln.Addr().String(),
			State:  servicestatus.StateUp,
		})
	}

	if s.plainListen != "" {
		pln, err := net.Listen("tcp", s.plainListen)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("httpapi: plain listen: %w", err)
		}
		s.log.Info("http plain listening", "listen", s.plainListen)
		// Either listener stopping takes the other down, so Serve's error reaches the app and stops all services.
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		errCh := make(chan error, 2)
		go func() { errCh <- serveHTTP(ctx, pln, s.PlainHandler()) }()
		go func() { errCh <- serveHTTP(ctx, ln, s.handler()) }()
		s.log.Info("http api listening", "listen", s.listen, "tls", s.useTLS, "web_ui", s.ui != nil)
		if err := <-errCh; err != nil {
			return err
		}
		return <-errCh
	}

	s.log.Info("http api listening", "listen", s.listen, "tls", s.useTLS, "web_ui", s.ui != nil)
	return serveHTTP(ctx, ln, s.handler())
}

// serveHTTP serves h on ln until ctx is canceled.
func serveHTTP(ctx context.Context, ln net.Listener, h http.Handler) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// PlainHandler serves ACME HTTP-01 challenges and redirects everything else to the HTTPS listener.
func (s *Server) PlainHandler() http.Handler {
	_, port, _ := net.SplitHostPort(s.listen)
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	if s.domainTLS != nil {
		return s.domainTLS.HTTPHandler(redirect)
	}
	return redirect
}

// Handler returns the HTTP handler for tests (includes ACME wrapper when configured).
func (s *Server) Handler() http.Handler { return s.handler() }

// TLSConfig exposes the TLS config when serving HTTPS (tests/inspection).
func (s *Server) TLSConfig() *tls.Config {
	if s == nil || s.certs == nil {
		return nil
	}
	return s.certs.Config()
}

// isLoopbackListen reports whether addr is bound only to loopback.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
