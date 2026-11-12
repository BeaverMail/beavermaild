// IMAP4rev1 server (minimal LOGIN, SELECT INBOX, FETCH).
package imap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime/debug"
	"time"

	"github.com/BeaverMail/beavermaild/internal/connset"
	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/servicestatus"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
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
	sessions       connset.Set
	preAuth        *security.IPLimiter
}

// maxPreAuthPerIP caps the unauthenticated connections of one client network (IPv4 address or
// IPv6 /64). Without it, 200 idle connections from one address filled the listener and locked
// everybody out; a logged-in session no longer counts, so NAT-ed offices are not limited.
const maxPreAuthPerIP = 10

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
		preAuth:        security.NewIPLimiter(maxPreAuthPerIP),
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
	if !s.sessions.Drain(drainTimeout) {
		s.log.Warn("imap shutdown: sessions still open after drain timeout", "open", s.sessions.Len())
	}
	return nil
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn, secure bool, lim *security.ConnLimiter) {
	defer lim.Release()
	releasePreAuth, ok := s.preAuth.Acquire(security.ClientIP(conn))
	if !ok {
		_, _ = conn.Write([]byte("* BYE [UNAVAILABLE] Too many connections from your address\r\n"))
		_ = conn.Close()
		return
	}
	defer releasePreAuth()
	sess := newSession(s.log, conn, s.dir, s.inbox, s.certs, secure, s.tlsRequired, s.authGate, s.readTimeout)
	sess.releasePreAuth = releasePreAuth
	sess.stopping = &s.sessions.Stopping
	s.sessions.Add(sess, conn)
	defer s.sessions.Remove(sess)
	// After STARTTLS sess.conn is the TLS conn; closing it sends close_notify.
	defer func() { _ = sess.conn.Close() }()
	// A bug on one message must not take down the whole server (and every other session).
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("imap session panic", append(sess.logAttrs(), "panic", r, "stack", string(debug.Stack()))...)
		}
	}()
	// Commands in flight during shutdown must finish (and say BYE): the stopping flag, not
	// ctx cancellation, ends the session.
	err := sess.run(context.WithoutCancel(ctx))
	switch {
	case err == nil || ctx.Err() != nil:
	case clientGone(err):
		s.log.Debug("imap session closed", slog.Any("err", err))
	default:
		// A server-side failure (storage, contention...) that dropped the connection.
		s.log.Warn("imap command failed", append(sess.logAttrs(), slog.Any("err", err))...)
	}
}

// logAttrs describes the session for logs: the failing command, account, mailbox and client.
func (s *session) logAttrs() []any {
	attrs := []any{"cmd", s.lastCmd, "remote", s.conn.RemoteAddr().String()}
	if s.principal.AccountID != 0 {
		attrs = append(attrs, "account", s.principal.AccountID)
	}
	if s.selected {
		attrs = append(attrs, "mailbox", s.mbox.Name)
	}
	return attrs
}

// clientGone reports errors that mean the client went away or the connection broke, not a
// server fault: EOF, resets, timeouts and other network or TLS errors.
func clientGone(err error) bool {
	var opErr *net.OpError
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, os.ErrDeadlineExceeded) || errors.As(err, &opErr)
}
