// SMTP inbound server (RFC 5321 subset for local delivery).
package smtp

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"runtime/debug"
	"time"

	"github.com/BeaverMail/beavermaild/internal/connset"
	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/mailauth"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/servicestatus"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
)

// Options configures optional TLS and protocol knobs for SMTP listeners.
type Options struct {
	Certs           *tlsload.Certs
	TLSRequired     bool
	VRFYEnabled     bool
	DataLimits      DataLimits
	Filter          MessageFilter
	FilterTmpDir    string
	FilterTimeoutMs int
	MailAuth        *mailauth.Verifier
	AuthGate        security.AuthGate
	SendGate        security.SendGate
	Greylist        *Greylist
	ASNLookup       *ASNLookup
	MaxConnections  int           // 0 = unlimited (tests); positive = per-listener cap
	ReadTimeout     time.Duration // 0 = no idle read deadline
	Status          *servicestatus.Registry
	Hostname        string // banner and EHLO name (default "localhost")
}

// Server accepts inbound SMTP connections.
type Server struct {
	log                 *slog.Logger
	inboundAddr         string
	submissionPlainAddr string
	submissionTLSAddr   string
	dir                 *directory.Local
	inbox               *mail.Inbox
	queue               *mail.Queue
	certs               *tlsload.Certs
	tlsRequired         bool
	vrfyEnabled         bool
	dataLimits          DataLimits
	filter              MessageFilter
	filterTmpDir        string
	filterTimeoutMs     int
	mailAuth            *mailauth.Verifier
	authGate            security.AuthGate
	sendGate            security.SendGate
	greylist            *Greylist
	asnLookup           *ASNLookup
	maxConnections      int
	readTimeout         time.Duration
	status              *servicestatus.Registry
	hostname            string
	sessions            connset.Set
}

// NewServer returns an SMTP server. submissionAddr is optional plain listener (e.g. :587).
// submissionTLSAddr enables implicit TLS on :465 when certs are configured.
func NewServer(log *slog.Logger, addr string, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, submissionAddr, submissionTLSAddr string, opts Options) *Server {
	gate := opts.AuthGate
	if gate == nil {
		gate = security.NopGate{}
	}
	sendGate := opts.SendGate
	if sendGate == nil {
		sendGate = security.NopSendGate{}
	}
	return &Server{
		log:                 log,
		inboundAddr:         addr,
		submissionPlainAddr: submissionAddr,
		submissionTLSAddr:   submissionTLSAddr,
		dir:                 dir,
		inbox:               inbox,
		queue:               queue,
		certs:               opts.Certs,
		tlsRequired:         opts.TLSRequired,
		vrfyEnabled:         opts.VRFYEnabled,
		dataLimits:          opts.DataLimits.withDefaults(),
		filter:              opts.Filter,
		filterTmpDir:        opts.FilterTmpDir,
		filterTimeoutMs:     opts.FilterTimeoutMs,
		mailAuth:            opts.MailAuth,
		authGate:            gate,
		sendGate:            sendGate,
		greylist:            opts.Greylist,
		asnLookup:           opts.ASNLookup,
		maxConnections:      opts.MaxConnections,
		readTimeout:         opts.ReadTimeout,
		status:              opts.Status,
		hostname:            opts.Hostname,
	}
}

// SetFilter replaces the SMTP message filter (e.g. after daemon plugins start).
func (s *Server) SetFilter(f MessageFilter) {
	if f == nil {
		f = NopFilter{}
	}
	s.filter = f
}

type listenerSlot struct {
	ln         net.Listener
	secure     bool
	submission bool
	limiter    *security.ConnLimiter
}

// Serve listens on configured addresses until ctx is canceled.
// Each listener is independent: a bind failure is recorded and other listeners still start.
func (s *Server) Serve(ctx context.Context) error {
	var slots []listenerSlot
	if s.inboundAddr != "" {
		if ln, ok := s.listenSlot(ctx, "smtp_inbound", "SMTP inbound", s.inboundAddr, false, false); ok {
			slots = append(slots, ln)
		}
	}
	if s.submissionPlainAddr != "" {
		if ln, ok := s.listenSlot(ctx, "smtp_submission", "SMTP submission", s.submissionPlainAddr, false, true); ok {
			slots = append(slots, ln)
		}
	}
	if s.submissionTLSAddr != "" {
		if s.certs == nil {
			s.setStatus(servicestatus.Entry{
				ID:     "smtp_submission_tls",
				Name:   "SMTP submission TLS",
				Listen: s.submissionTLSAddr,
				State:  servicestatus.StateDisabled,
				Error:  "tls not configured",
			})
		} else if ln, ok := s.listenTLSSlot(ctx, "smtp_submission_tls", "SMTP submission TLS", s.submissionTLSAddr); ok {
			slots = append(slots, ln)
		}
	}
	if len(slots) == 0 {
		<-ctx.Done()
		return nil
	}
	return s.serve(ctx, slots)
}

func (s *Server) listenSlot(_ context.Context, id, name, addr string, secure, submission bool) (listenerSlot, bool) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.setStatus(servicestatus.Entry{ID: id, Name: name, Listen: addr, State: servicestatus.StateError, Error: err.Error()})
		s.log.Warn("smtp listen failed", "id", id, "addr", addr, slog.Any("err", err))
		return listenerSlot{}, false
	}
	s.setStatus(servicestatus.Entry{ID: id, Name: name, Listen: ln.Addr().String(), State: servicestatus.StateUp})
	s.log.Info("smtp listening", "addr", ln.Addr().String(), "submission", submission, "tls", secure)
	return listenerSlot{ln: ln, secure: secure, submission: submission, limiter: security.NewConnLimiter(s.maxConnections)}, true
}

func (s *Server) listenTLSSlot(_ context.Context, id, name, addr string) (listenerSlot, bool) {
	ln, err := s.certs.Listen("tcp", addr)
	if err != nil {
		s.setStatus(servicestatus.Entry{ID: id, Name: name, Listen: addr, State: servicestatus.StateError, Error: err.Error()})
		s.log.Warn("smtp tls listen failed", "id", id, "addr", addr, slog.Any("err", err))
		return listenerSlot{}, false
	}
	s.setStatus(servicestatus.Entry{ID: id, Name: name, Listen: ln.Addr().String(), State: servicestatus.StateUp})
	s.log.Info("smtp tls listening", "addr", ln.Addr().String(), "submission", true)
	return listenerSlot{ln: ln, secure: true, submission: true, limiter: security.NewConnLimiter(s.maxConnections)}, true
}

func (s *Server) setStatus(e servicestatus.Entry) {
	if s.status != nil {
		s.status.Set(e)
	}
}

// ServeListener serves inbound SMTP on an existing listener (for tests).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: false, submission: false, limiter: security.NewConnLimiter(s.maxConnections)}})
}

// ServeTLSListener serves implicit TLS without submission semantics (for tests).
func (s *Server) ServeTLSListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: true, submission: false, limiter: security.NewConnLimiter(s.maxConnections)}})
}

// ServeSubmissionListener serves submission SMTP on an existing listener (for tests).
func (s *Server) ServeSubmissionListener(ctx context.Context, ln net.Listener, secure bool) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: secure, submission: true, limiter: security.NewConnLimiter(s.maxConnections)}})
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
				if !slot.limiter.Acquire() {
					_, _ = conn.Write([]byte("421 4.7.0 Too many connections\r\n"))
					_ = conn.Close()
					continue
				}
				go s.serveConn(ctx, conn, slot.secure, slot.submission, slot.limiter)
			}
		}()
	}

	<-ctx.Done()
	for _, slot := range slots {
		_ = slot.ln.Close()
	}
	if !s.sessions.Drain(drainTimeout) {
		s.log.Warn("smtp shutdown: sessions still open after drain timeout", "open", s.sessions.Len())
	}
	return nil
}

// drainTimeout bounds how long Serve waits for sessions to close on shutdown.
const drainTimeout = 5 * time.Second

func (s *Server) serveConn(ctx context.Context, conn net.Conn, secure, submission bool, lim *security.ConnLimiter) {
	defer lim.Release()
	sess := newSession(s.log, conn, s.dir, s.inbox, s.queue, s.certs, secure, s.tlsRequired, s.vrfyEnabled, submission, s.dataLimits, s.filter, s.filterTmpDir, s.filterTimeoutMs, s.mailAuth, s.authGate, s.sendGate, s.greylist, s.asnLookup, s.readTimeout)
	// Close the session's current conn: after STARTTLS it is the TLS conn, whose Close sends
	// close_notify (closing only the raw TCP conn makes peers log "TLS not properly terminated").
	defer func() { _ = sess.conn.Close() }()
	// A bug on one message must not take down the whole server (and every other session).
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("smtp session panic", "panic", r, "stack", string(debug.Stack()))
		}
	}()
	if s.hostname != "" {
		sess.hostname = s.hostname
	}
	sess.stopping = &s.sessions.Stopping
	s.sessions.Add(sess, conn)
	defer s.sessions.Remove(sess)
	// Transactions in flight during shutdown must finish (and reply 421 after): the stopping
	// flag, not ctx cancellation, ends the session.
	if err := sess.run(context.WithoutCancel(ctx)); err != nil && ctx.Err() == nil {
		s.log.Debug("smtp session", slog.Any("err", err))
	}
}

// CertsConfigured reports whether STARTTLS may be offered.
func (s *Server) CertsConfigured() bool {
	return s.certs != nil && s.certs.Config() != nil
}
