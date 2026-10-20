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
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/mailauth"
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
		ASN:           s.clientASN,
		Country:       s.clientCountry,
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
	if s.skipAntiSpam(ctx, phase, to) {
		return FilterOutcome{Action: FilterActionAccept}, nil
	}
	return s.filter.Filter(ctx, s.buildFilterRequest(phase, to, bodyPath))
}

func (s *session) filterEom(ctx context.Context, raw []byte) (FilterOutcome, error) {
	runFilter := s.filter != nil && !s.skipAntiSpam(ctx, FilterPhaseEom, s.rcptAddresses())
	// Inbound mail is always verified, filter or not, so Authentication-Results can be added.
	runAuth := s.authApplies()
	if !runFilter && !runAuth {
		return FilterOutcome{Action: FilterActionAccept}, nil
	}
	if s.filterTmpDir == "" {
		if !runFilter {
			return FilterOutcome{Action: FilterActionAccept}, nil
		}
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

	if runAuth {
		s.authState = s.mailAuth.FinishEom(ctx, path, s.mailFrom, s.heloDomain, s.authState)
		s.authDone = true
	}
	if !runFilter {
		return FilterOutcome{Action: FilterActionAccept}, nil
	}

	req := s.buildFilterRequest(FilterPhaseEom, s.rcptAddresses(), path)
	req.ID = id
	return s.filter.Filter(ctx, req)
}

// skipAntiSpam reports whether per-domain AntiSpam is off for this filter phase.
// CONNECT/HELO/MAIL stay global (domain unknown). RCPT/DATA/EOM honor domain flags.
func (s *session) skipAntiSpam(ctx context.Context, phase string, to []string) bool {
	if s.submission {
		return false
	}
	switch phase {
	case FilterPhaseRcpt:
		if len(to) == 0 {
			return false
		}
		return !s.domainAntiSpamOn(ctx, to[0])
	case FilterPhaseData, FilterPhaseEom:
		if len(s.rcpt) == 0 {
			return false
		}
		for _, t := range s.rcpt {
			if t.accountID == 0 {
				return false
			}
			if s.domainAntiSpamOn(ctx, t.address) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (s *session) domainAntiSpamOn(ctx context.Context, addr string) bool {
	domName, err := DomainFromAddress(addr)
	if err != nil {
		return true
	}
	dom, err := s.dir.LookupDomain(ctx, domName)
	if err != nil {
		return true
	}
	// Legacy / plain CreateDomain leave SSLMode empty → keep global filters on.
	if dom.SSLMode == "" {
		return true
	}
	return dom.AntiSpam
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
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var prefix []byte
	for _, k := range keys {
		prefix = append(prefix, fmt.Sprintf("%s: %s\r\n", k, headers[k])...)
	}
	// Insert after the last header's line ending, not before it: otherwise the new
	// header is glued onto the last one (e.g. corrupting a multipart boundary).
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx >= 0 {
		idx += 2
	} else if idx = bytes.Index(raw, []byte("\n\n")); idx >= 0 {
		idx++
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
	if s.authDone && !s.submission {
		raw = prependAuthResults(raw, s.hostname, mailauth.AuthResults(s.hostname, s.mailFrom, s.heloDomain, s.authState))
	}
	return s.finishDelivery(ctx, raw)
}

// prependAuthResults removes Authentication-Results fields that claim our authserv-id
// (RFC 8601 §5: a sender could forge them) and puts ours at the top, using the message's
// own line ending.
func prependAuthResults(raw []byte, authservID, value string) []byte {
	nl := "\r\n"
	if !bytes.Contains(raw, []byte("\r\n")) {
		nl = "\n"
	}
	header := "Authentication-Results: " + strings.ReplaceAll(value, "\r\n", nl) + nl
	return append([]byte(header), stripAuthResults(raw, authservID)...)
}

// stripAuthResults drops header fields "Authentication-Results: <authservID>[ version];...",
// including their folded continuation lines; the body is left untouched.
func stripAuthResults(raw []byte, authservID string) []byte {
	out := make([]byte, 0, len(raw))
	dropping := false
	rest := raw
	for len(rest) > 0 {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line = rest[:i+1]
		}
		rest = rest[len(line):]
		if len(bytes.TrimRight(line, "\r\n")) == 0 { // end of header
			out = append(out, line...)
			return append(out, rest...)
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !dropping {
				out = append(out, line...)
			}
			continue
		}
		dropping = false
		if name, val, ok := bytes.Cut(line, []byte(":")); ok && strings.EqualFold(strings.TrimSpace(string(name)), "Authentication-Results") {
			id, _, _ := strings.Cut(strings.TrimSpace(string(val)), ";")
			if fields := strings.Fields(id); len(fields) > 0 && strings.EqualFold(fields[0], authservID) {
				dropping = true
				continue
			}
		}
		out = append(out, line...)
	}
	return out
}

// authApplies reports whether SPF/DKIM/DMARC describe this transaction. Not on submission:
// there they would judge the client's IP (e.g. an app server outside the SPF record), while
// the message leaves from our IP with our DKIM signature; scoring them flagged own mail as spam.
func (s *session) authApplies() bool {
	return s.mailAuth != nil && s.mailAuth.Enabled() && !s.submission
}

// checkSPFEhlo runs EHLO/HELO SPF when mailauth applies.
func (s *session) checkSPFEhlo(ctx context.Context) {
	if !s.authApplies() || s.heloDomain == "" {
		return
	}
	ip := net.ParseIP(s.clientIP())
	if ip == nil {
		return
	}
	s.authState.SPFEhlo = s.mailAuth.CheckSPF(ctx, ip, "", s.heloDomain)
}

// checkSPFMailFrom runs MAIL FROM SPF when mailauth applies.
func (s *session) checkSPFMailFrom(ctx context.Context) {
	if !s.authApplies() {
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

// ensureASN resolves client ASN/country once per connection for filter wire.
func (s *session) ensureASN(ctx context.Context) {
	if s.asnDone {
		return
	}
	s.asnDone = true
	if s.asnLookup == nil {
		return
	}
	s.clientASN, s.clientCountry = s.asnLookup.Lookup(ctx, s.clientIP())
}
