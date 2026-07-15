// SMTP session plugin filter helpers.
package smtp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func (s *session) nextFilterID() string {
	s.filterSeq++
	return strconv.Itoa(s.filterSeq)
}

// currentFilterID keeps one correlation ID across all phases of a transaction.
func (s *session) currentFilterID() string {
	if s.filterTxnID == "" {
		s.filterTxnID = s.nextFilterID()
	}
	return s.filterTxnID
}

func (s *session) clientIP() string {
	host, _, err := net.SplitHostPort(s.conn.RemoteAddr().String())
	if err != nil {
		return s.conn.RemoteAddr().String()
	}
	return host
}

func (s *session) filterListener() string {
	if s.submission {
		return FilterListenerSubmission
	}
	return FilterListenerInbound
}

func (s *session) buildFilterRequest(phase string, to []string, bodyPath string) FilterRequest {
	req := FilterRequest{
		ID:            s.currentFilterID(),
		Phase:         phase,
		From:          s.mailFrom,
		To:            to,
		ClientIP:      s.clientIP(),
		BodyPath:      bodyPath,
		TimeoutMs:     s.filterTimeoutMs,
		Listener:      s.filterListener(),
		TLS:           s.secure,
		EHLODomain:    s.heloDomain,
		Authenticated: s.principal.AccountID != 0,
		IPRevPTR:      s.iprevPTR,
		IPRevResult:   s.iprevResult,
	}
	if phase == FilterPhaseHelo || phase == FilterPhaseMail || phase == FilterPhaseRcpt || phase == FilterPhaseData || phase == FilterPhaseEom {
		req.Auth = s.authWire()
	}
	return req
}

func (s *session) authWire() *FilterAuth {
	if s.mailAuth == nil || !s.mailAuth.Enabled() {
		return nil
	}
	w := s.authState.Wire()
	if w.SPFEhlo == "" && w.SPFMailFrom == "" && w.DKIM == "" && w.DMARC == "" && w.ARC == "" {
		return nil
	}
	return &FilterAuth{
		SPFEhlo:     w.SPFEhlo,
		SPFMailFrom: w.SPFMailFrom,
		DKIM:        w.DKIM,
		DMARC:       w.DMARC,
		DMARCPolicy: w.DMARCPolicy,
		ARC:         w.ARC,
	}
}

func (s *session) runFilter(ctx context.Context, phase string, to []string, bodyPath string) (FilterOutcome, error) {
	if s.filter == nil {
		return FilterOutcome{Action: FilterActionAccept}, nil
	}
	return s.filter.Filter(ctx, s.buildFilterRequest(phase, to, bodyPath))
}

func (s *session) filterEom(ctx context.Context, raw []byte) (FilterOutcome, error) {
	if s.filter == nil {
		return FilterOutcome{Action: FilterActionAccept}, nil
	}
	if s.filterTmpDir == "" {
		return s.runFilter(ctx, FilterPhaseEom, s.rcptAddresses(), "")
	}
	if err := os.MkdirAll(s.filterTmpDir, 0o755); err != nil {
		return FilterOutcome{}, err
	}
	id := s.currentFilterID()
	path := filepath.Join(s.filterTmpDir, "smtp-filter-"+id+".eml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return FilterOutcome{}, err
	}
	defer os.Remove(path)

	if s.mailAuth != nil && s.mailAuth.Enabled() {
		s.authState = s.mailAuth.FinishEom(ctx, path, s.mailFrom, s.heloDomain, s.authState)
	}

	req := s.buildFilterRequest(FilterPhaseEom, s.rcptAddresses(), path)
	req.ID = id
	return s.filter.Filter(ctx, req)
}

func (s *session) rcptAddresses() []string {
	out := make([]string, len(s.rcpt))
	for i, t := range s.rcpt {
		out[i] = t.address
	}
	return out
}

func (s *session) replyFilterAction(action string) (string, bool) {
	switch action {
	case FilterActionAccept:
		return "", true
	case FilterActionReject:
		return replyFilterReject, false
	case FilterActionTempfail:
		return replyFilterTempfail, false
	case FilterActionDiscard:
		return replyOK, false
	default:
		return replyFilterTempfail, false
	}
}

// appendFilterHeaders inserts plugin headers before the blank line separating headers from body.
func appendFilterHeaders(raw []byte, headers map[string]string) []byte {
	if len(headers) == 0 {
		return raw
	}
	var prefix []byte
	for k, v := range headers {
		prefix = append(prefix, fmt.Sprintf("%s: %s\r\n", k, v)...)
	}
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		idx = bytes.Index(raw, []byte("\n\n"))
	}
	if idx >= 0 {
		out := make([]byte, 0, len(prefix)+len(raw))
		out = append(out, raw[:idx]...)
		out = append(out, prefix...)
		out = append(out, raw[idx:]...)
		return out
	}
	return append(append(prefix, raw...), '\r', '\n')
}

func (s *session) deliverAfterFilter(ctx context.Context, raw []byte) error {
	out, err := s.filterEom(ctx, raw)
	if err != nil {
		s.log.Warn("smtp filter error", slog.Any("err", err))
		if err := s.writef(replyFilterTempfail); err != nil {
			return err
		}
		s.reset()
		return nil
	}
	reply, deliver := s.replyFilterAction(out.Action)
	if !deliver {
		if reply == "" {
			reply = replyFilterReject
		}
		if err := s.writef(reply); err != nil {
			return err
		}
		s.reset()
		return nil
	}
	if len(out.Headers) > 0 {
		raw = appendFilterHeaders(raw, out.Headers)
	}
	return s.finishDelivery(ctx, raw)
}

// checkSPFEhlo runs EHLO/HELO SPF when mailauth is enabled.
func (s *session) checkSPFEhlo(ctx context.Context) {
	if s.mailAuth == nil || !s.mailAuth.Enabled() || s.heloDomain == "" {
		return
	}
	ip := net.ParseIP(s.clientIP())
	if ip == nil {
		return
	}
	s.authState.SPFEhlo = s.mailAuth.CheckSPF(ctx, ip, "", s.heloDomain)
}

// checkSPFMailFrom runs MAIL FROM SPF when mailauth is enabled.
func (s *session) checkSPFMailFrom(ctx context.Context) {
	if s.mailAuth == nil || !s.mailAuth.Enabled() {
		return
	}
	ip := net.ParseIP(s.clientIP())
	if ip == nil {
		return
	}
	s.authState.SPFMailFrom = s.mailAuth.CheckSPF(ctx, ip, s.mailFrom, s.heloDomain)
}

// ensureIPRev resolves client PTR once per connection for filter wire.
func (s *session) ensureIPRev(ctx context.Context) {
	if s.iprevDone {
		return
	}
	s.iprevDone = true
	timeout := time.Duration(s.filterTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	s.iprevPTR, s.iprevResult = LookupIPRev(ctx, s.clientIP(), timeout)
}
