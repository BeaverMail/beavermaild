// SMTP inbound server (RFC 5321 subset for local delivery).
package smtp

import (
	"context"
	"errors"
	"log/slog"
	"net"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/mailauth"
	"github.com/BeaverMail/beaver/internal/security"
	"github.com/BeaverMail/beaver/internal/tlsload"
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
	Greylist        *Greylist
	ASNLookup       *ASNLookup
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
	greylist            *Greylist
	asnLookup           *ASNLookup
}

// NewServer returns an SMTP server. submissionAddr is optional plain listener (e.g. :587).
// submissionTLSAddr enables implicit TLS on :465 when certs are configured.
func NewServer(log *slog.Logger, addr string, dir *directory.Local, inbox *mail.Inbox, queue *mail.Queue, submissionAddr, submissionTLSAddr string, opts Options) *Server {
	gate := opts.AuthGate
	if gate == nil {
		gate = security.NopGate{}
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
		greylist:            opts.Greylist,
		asnLookup:           opts.ASNLookup,
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
}

// Serve listens on configured addresses until ctx is canceled.
func (s *Server) Serve(ctx context.Context) error {
	var slots []listenerSlot
	if s.inboundAddr != "" {
		ln, err := net.Listen("tcp", s.inboundAddr)
		if err != nil {
			return err
		}
		slots = append(slots, listenerSlot{ln: ln, secure: false, submission: false})
		s.log.Info("smtp listening", "addr", ln.Addr().String())
	}
	if s.submissionPlainAddr != "" {
		ln, err := net.Listen("tcp", s.submissionPlainAddr)
		if err != nil {
			for _, slot := range slots {
				_ = slot.ln.Close()
			}
			return err
		}
		slots = append(slots, listenerSlot{ln: ln, secure: false, submission: true})
		s.log.Info("smtp listening", "addr", ln.Addr().String(), "submission", true)
	}
	if s.submissionTLSAddr != "" && s.certs != nil {
		tlsLn, err := s.certs.Listen("tcp", s.submissionTLSAddr)
		if err != nil {
			for _, slot := range slots {
				_ = slot.ln.Close()
			}
			return err
		}
		slots = append(slots, listenerSlot{ln: tlsLn, secure: true, submission: true})
		s.log.Info("smtp tls listening", "addr", tlsLn.Addr().String(), "submission", true)
	}
	return s.serve(ctx, slots)
}

// ServeListener serves inbound SMTP on an existing listener (for tests).
func (s *Server) ServeListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: false, submission: false}})
}

// ServeTLSListener serves implicit TLS without submission semantics (for tests).
func (s *Server) ServeTLSListener(ctx context.Context, ln net.Listener) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: true, submission: false}})
}

// ServeSubmissionListener serves submission SMTP on an existing listener (for tests).
func (s *Server) ServeSubmissionListener(ctx context.Context, ln net.Listener, secure bool) error {
	return s.serve(ctx, []listenerSlot{{ln: ln, secure: secure, submission: true}})
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
				go s.serveConn(ctx, conn, slot.secure, slot.submission)
			}
		}()
	}

	<-ctx.Done()
	for _, slot := range slots {
		_ = slot.ln.Close()
	}
	return nil
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn, secure, submission bool) {
	defer conn.Close()
	sess := newSession(s.log, conn, s.dir, s.inbox, s.queue, s.certs, secure, s.tlsRequired, s.vrfyEnabled, submission, s.dataLimits, s.filter, s.filterTmpDir, s.filterTimeoutMs, s.mailAuth, s.authGate, s.greylist, s.asnLookup)
	if err := sess.run(ctx); err != nil && ctx.Err() == nil {
		s.log.Debug("smtp session", slog.Any("err", err))
	}
}

// CertsConfigured reports whether STARTTLS may be offered.
func (s *Server) CertsConfigured() bool {
	return s.certs != nil && s.certs.Config() != nil
}
