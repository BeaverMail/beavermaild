// SMTP session plugin filter helpers.
package smtp

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
)

func (s *session) nextFilterID() string {
	s.filterSeq++
	return strconv.Itoa(s.filterSeq)
}

func (s *session) clientIP() string {
	host, _, err := net.SplitHostPort(s.conn.RemoteAddr().String())
	if err != nil {
		return s.conn.RemoteAddr().String()
	}
	return host
}

func (s *session) runFilter(ctx context.Context, phase string, to []string, bodyPath string) (string, error) {
	if s.filter == nil {
		return FilterActionAccept, nil
	}
	return s.filter.Filter(ctx, FilterRequest{
		ID:        s.nextFilterID(),
		Phase:     phase,
		From:      s.mailFrom,
		To:        to,
		ClientIP:  s.clientIP(),
		BodyPath:  bodyPath,
		TimeoutMs: s.filterTimeoutMs,
	})
}

func (s *session) filterEom(ctx context.Context, raw []byte) (string, error) {
	if s.filter == nil || s.filterTmpDir == "" {
		return s.runFilter(ctx, FilterPhaseEom, s.rcptAddresses(), "")
	}
	if err := os.MkdirAll(s.filterTmpDir, 0o755); err != nil {
		return "", err
	}
	id := s.nextFilterID()
	path := filepath.Join(s.filterTmpDir, "smtp-filter-"+id+".eml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return "", err
	}
	defer os.Remove(path)

	req := FilterRequest{
		ID:        id,
		Phase:     FilterPhaseEom,
		From:      s.mailFrom,
		To:        s.rcptAddresses(),
		ClientIP:  s.clientIP(),
		BodyPath:  path,
		TimeoutMs: s.filterTimeoutMs,
	}
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

func (s *session) deliverAfterFilter(ctx context.Context, raw []byte) error {
	action, err := s.filterEom(ctx, raw)
	if err != nil {
		s.log.Warn("smtp filter error", slog.Any("err", err))
		if err := s.writef(replyFilterTempfail); err != nil {
			return err
		}
		s.reset()
		return nil
	}
	reply, deliver := s.replyFilterAction(action)
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
	return s.finishDelivery(ctx, raw)
}
