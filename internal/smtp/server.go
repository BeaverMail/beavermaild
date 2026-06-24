// SMTP inbound server (RFC 5321 subset for local delivery).
package smtp

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

// Options configures optional TLS for SMTP listeners.
type Options struct {
	Certs       *tlsload.Certs
	TLSRequired bool
}

// Server accepts inbound SMTP connections.
type Server struct {
	log         *slog.Logger
	plainAddrs  []string
	dir         *directory.Local
	inbox       *mail.Inbox
	queue       *mail.Queue
	certs       *tlsload.Certs
	tlsRequired bool
}

// NewServer returns an SMTP server. submissionAddr is optional second plain listener (e.g. :587).
func NewServer(log *slog.Logger, addr string, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, submissionAddr string, opts Options) *Server {
	addrs := []string{addr}
	if submissionAddr != "" {
		addrs = append(addrs, submissionAddr)
	}
	return &Server{
		log:         log,
		plainAddrs:  addrs,
		dir:         dir,
		inbox:       inbox,
		queue:       queue,
		certs:       opts.Certs,
		tlsRequired: opts.TLSRequired,
	}
}

// Serve listens on configured addresses until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	var listeners []net.Listener
	for _, addr := range s.plainAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range listeners {
				_ = l.Close()
			}
			return err
		}
		listeners = append(listeners, ln)
	}
	return s.serve(ctx, listeners)
}

// ServeListener serves on an existing listener (for tests).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []net.Listener{ln})
}

func (s *Server) serve(ctx context.Context, listeners []net.Listener) error {
	for _, ln := range listeners {
		ln := ln
		s.log.Info("smtp listening", "addr", ln.Addr().String())
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						return
					}
					s.log.Warn("smtp accept", slog.Any("err", err))
					continue
				}
				go s.serveConn(ctx, conn, false)
			}
		}()
	}

	<-ctx.Done()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	return nil
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn, secure bool) {
	defer conn.Close()
	sess := newSession(s.log, conn, s.dir, s.inbox, s.queue, s.certs, secure, s.tlsRequired)
	if err := sess.run(ctx); err != nil && ctx.Err() == nil {
		s.log.Debug("smtp session", slog.Any("err", err))
	}
}

// CertsConfigured reports whether STARTTLS may be offered.
func (s *Server) CertsConfigured() bool {
	return s.certs != nil && s.certs.Config() != nil
}
