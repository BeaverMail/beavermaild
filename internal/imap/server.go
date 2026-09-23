// IMAP4rev1 server (minimal LOGIN, SELECT INBOX, FETCH).
package imap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/servicestatus"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

// Options configures optional TLS for IMAP listeners.
type Options struct {
	Certs          *tlsload.Certs
	TLSListen      string
	TLSRequired    bool
	AuthGate       security.AuthGate
	MaxConnections int           // 0 = unlimited (tests); positive = per-listener cap
	ReadTimeout    time.Duration // 0 = no idle read deadline
	Status         *servicestatus.Registry
}

// Server accepts IMAP connections.
type Server struct {
	log            *slog.Logger
	plainAddr      string
	tlsAddr        string
	dir            *directory.Local
	inbox          *mail.Inbox
	certs          *tlsload.Certs
	tlsRequired    bool
	authGate       security.AuthGate
	maxConnections int
	readTimeout    time.Duration
	status         *servicestatus.Registry
}

// NewServer returns an IMAP server bound to plainAddr; tlsAddr enables implicit TLS on :993.
func NewServer(log *slog.Logger, plainAddr string, dir *directory.Local, inbox *mail.Inbox, opts Options) *Server {
	gate := opts.AuthGate
	if gate == nil {
		gate = security.NopGate{}
	}
	return &Server{
		log:            log,
		plainAddr:      plainAddr,
		tlsAddr:        opts.TLSListen,
		dir:            dir,
		inbox:          inbox,
		certs:          opts.Certs,
		tlsRequired:    opts.TLSRequired,
		authGate:       gate,
		maxConnections: opts.MaxConnections,
		readTimeout:    opts.ReadTimeout,
		status:         opts.Status,
	}
}

type listenerSlot struct {
	ln      net.Listener
	secure  bool
	limiter *security.ConnLimiter
}

// Serve listens until ctx is canceled. TLS bind failure does not take down plain IMAP.
func (s *Server) Serve(ctx context.Context) error {
	var slots []listenerSlot
	if s.plainAddr != "" {
		ln, err := net.Listen("tcp", s.plainAddr)
		if err != nil {
			s.setStatus(servicestatus.Entry{ID: "imap", Name: "IMAP", Listen: s.plainAddr, State: servicestatus.StateError, Error: err.Error()})
			s.log.Warn("imap listen failed", "addr", s.plainAddr, slog.Any("err", err))
		} else {
			s.setStatus(servicestatus.Entry{ID: "imap", Name: "IMAP", Listen: ln.Addr().String(), State: servicestatus.StateUp})
			s.log.Info("imap listening", "addr", ln.Addr().String())
			slots = append(slots, listenerSlot{ln: ln, secure: false, limiter: security.NewConnLimiter(s.maxConnections)})
		}
	}
	if s.tlsAddr != "" {
		if s.certs == nil {
			s.setStatus(servicestatus.Entry{ID: "imap_tls", Name: "IMAP TLS", Listen: s.tlsAddr, State: servicestatus.StateDisabled, Error: "tls not configured"})
		} else {
			tlsLn, err := s.certs.Listen("tcp", s.tlsAddr)
			if err != nil {
				s.setStatus(servicestatus.Entry{ID: "imap_tls", Name: "IMAP TLS", Listen: s.tlsAddr, State: servicestatus.StateError, Error: err.Error()})
				s.log.Warn("imap tls listen failed", "addr", s.tlsAddr, slog.Any("err", err))
			} else {
				s.setStatus(servicestatus.Entry{ID: "imap_tls", Name: "IMAP TLS", Listen: tlsLn.Addr().String(), State: servicestatus.StateUp})
				s.log.Info("imap tls listening", "addr", tlsLn.Addr().String())
				slots = append(slots, listenerSlot{ln: tlsLn, secure: true, limiter: security.NewConnLimiter(s.maxConnections)})
			}
		}
	}
	if len(slots) == 0 {
		<-ctx.Done()
		return nil
	}
	return s.serve(ctx, slots)
}

func (s *Server) setStatus(e servicestatus.Entry) {
	if s.status != nil {
		s.status.Set(e)
	}
}

// ServeListener serves on an existing listener (for tests).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: false, limiter: security.NewConnLimiter(s.maxConnections)}})
}

// ServeTLSListener serves implicit TLS on an existing listener (for tests).
func (s *Server) ServeTLSListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: true, limiter: security.NewConnLimiter(s.maxConnections)}})
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
					s.log.Warn("imap accept", slog.Any("err", err))
					continue
				}
				if !slot.limiter.Acquire() {
					_, _ = conn.Write([]byte("* BYE [ALERT] Too many connections\r\n"))
					_ = conn.Close()
					continue
				}
				go s.serveConn(ctx, conn, slot.secure, slot.limiter)
			}
		}()
	}

	<-ctx.Done()
	for _, slot := range slots {
		_ = slot.ln.Close()
	}
	return nil
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn, secure bool, lim *security.ConnLimiter) {
	defer lim.Release()
	defer conn.Close()
	sess := newSession(s.log, conn, s.dir, s.inbox, s.certs, secure, s.tlsRequired, s.authGate, s.readTimeout)
	if err := sess.run(ctx); err != nil && ctx.Err() == nil {
		s.log.Debug("imap session", slog.Any("err", err))
	}
}
