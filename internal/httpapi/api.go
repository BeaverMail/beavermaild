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

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/servicestatus"
	"github.com/BeaverMail/beaver/internal/smtp"
	"github.com/BeaverMail/beaver/internal/storage/blob"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

const (
	apiPrefix     = "/api/v1"
	sessionCookie = "beaver_session"
	sessionTTL    = 12 * time.Hour
)

// Options configures the HTTP API server.
type Options struct {
	Listen   string
	Dir      *directory.Local
	Log      *slog.Logger
	AuthKey  string
	Certs    *tlsload.Certs
	AuthGate security.AuthGate
	// Blobs is required for domain/account delete (mail purge).
	Blobs *blob.FS
	// Queue is the outbound mail queue (nil disables queue endpoints).
	Queue *mail.Queue
	// Remote configures outbound delivery probes (nil/empty disables).
	Remote *smtp.RemoteConfig
	// Status is the process-wide service registry (nil disables /status).
	Status *servicestatus.Registry
	// UI is the embedded admin SPA (nil when not attached).
	UI fs.FS
}

// Server is the optional admin/API HTTP listener.
type Server struct {
	listen   string
	dir      *directory.Local
	log      *slog.Logger
	authKey  []byte
	certs    *tlsload.Certs
	useTLS   bool
	authGate security.AuthGate
	blobs    *blob.FS
	queue    *mail.Queue
	remote   *smtp.RemoteConfig
	status   *servicestatus.Registry
	ui       fs.FS
	mux      *http.ServeMux
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
	s := &Server{
		listen:   listen,
		dir:      opts.Dir,
		log:      log,
		authKey:  key,
		certs:    opts.Certs,
		useTLS:   useTLS,
		authGate: gate,
		blobs:    opts.Blobs,
		queue:    opts.Queue,
		remote:   opts.Remote,
		status:   opts.Status,
		ui:       opts.UI,
		mux:      http.NewServeMux(),
	}
	s.routes()
	return s, nil
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

	srv := &http.Server{
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.log.Info("http api listening", "listen", s.listen, "tls", s.useTLS, "web_ui", s.ui != nil)
	err = srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Handler returns the mux for tests.
func (s *Server) Handler() http.Handler { return s.mux }

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
