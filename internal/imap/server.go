// IMAP4rev1 server (minimal LOGIN, SELECT INBOX, FETCH).
package imap

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
)

// Server accepts IMAP connections.
type Server struct {
	log   *slog.Logger
	addr  string
	dir   *directory.Local
	inbox *mail.Inbox
	ln    net.Listener
}

// NewServer returns an IMAP server bound to addr later via Serve.
func NewServer(log *slog.Logger, addr string, dir *directory.Local, inbox *mail.Inbox) *Server {
	return &Server{log: log, addr: addr, dir: dir, inbox: inbox}
}

// Serve listens on s.addr until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	return s.serve(ctx, ln)
}

// ServeListener serves on an existing listener (for tests).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, ln)
}

func (s *Server) serve(ctx context.Context, ln net.Listener) error {
	s.ln = ln
	s.log.Info("imap listening", "addr", ln.Addr().String())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn("imap accept", slog.Any("err", err))
			continue
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	sess := newSession(s.log, conn, s.dir, s.inbox)
	if err := sess.run(ctx); err != nil && ctx.Err() == nil {
		s.log.Debug("imap session", slog.Any("err", err))
	}
}
