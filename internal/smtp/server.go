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
	tlsAddr     string
	dir         *directory.Local
	inbox       *mail.Inbox
	queue       *mail.Queue
	certs       *tlsload.Certs
	tlsRequired bool
}

// NewServer returns an SMTP server. submissionAddr is optional plain listener (e.g. :587).
// submissionTLSAddr enables implicit TLS on :465 when certs are configured.
func NewServer(log *slog.Logger, addr string, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, submissionAddr, submissionTLSAddr string, opts Options) *Server {
	addrs := []string{addr}
	if submissionAddr != "" {
		addrs = append(addrs, submissionAddr)
	}
	return &Server{
		log:         log,
		plainAddrs:  addrs,
		tlsAddr:     submissionTLSAddr,
		dir:         dir,
		inbox:       inbox,
		queue:       queue,
		certs:       opts.Certs,
		tlsRequired: opts.TLSRequired,
	}
}

type listenerSlot struct {
	ln     net.Listener
	secure bool
}

// Serve listens on configured addresses until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	var slots []listenerSlot
	for _, addr := range s.plainAddrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, slot := range slots {
				_ = slot.ln.Close()
			}
			return err
		}
		slots = append(slots, listenerSlot{ln: ln, secure: false})
		s.log.Info("smtp listening", "addr", ln.Addr().String())
	}
	if s.tlsAddr != "" && s.certs != nil {
		tlsLn, err := s.certs.Listen("tcp", s.tlsAddr)
		if err != nil {
			for _, slot := range slots {
				_ = slot.ln.Close()
			}
			return err
		}
		slots = append(slots, listenerSlot{ln: tlsLn, secure: true})
		s.log.Info("smtp tls listening", "addr", tlsLn.Addr().String())
	}
	return s.serve(ctx, slots)
}

// ServeListener serves on an existing listener (for tests).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: false}})
}

// ServeTLSListener serves implicit TLS on an existing listener (for tests).
func (s *Server) ServeTLSListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: true}})
}

func (s *Server) serve(ctx context.Context, slots []listenerSlot) error {
	for _, slot := range slots {
		slot := slot
		go func() {
			for {
				conn, err := slot.ln.Accept()
				if err != nil {
					if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
						return
					}
					s.log.Warn("smtp accept", slog.Any("err", err))
					continue
				}
				go s.serveConn(ctx, conn, slot.secure)
			}
		}()
	}

	<-ctx.Done()
	for _, slot := range slots {
		_ = slot.ln.Close()
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
