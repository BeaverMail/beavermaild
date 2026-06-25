// IMAP IDLE command (RFC 2177 subset).
package imap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const idlePollInterval = 500 * time.Millisecond

// cmdIdle waits for DONE while polling the selected mailbox for new messages.
func (s *session) cmdIdle(ctx context.Context, tag string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if _, err := fmt.Fprintf(s.conn, "+ idling\r\n"); err != nil {
		return err
	}
	defer func() { _ = s.conn.SetReadDeadline(time.Time{}) }()

	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(idlePollInterval))
		line, err := s.readLine()
		if err == nil {
			if strings.EqualFold(strings.TrimSpace(line), "DONE") {
				return s.tagged(tag, "OK IDLE terminated")
			}
			return s.tagged(tag, "BAD invalid IDLE continuation")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return err
		}
		if err := s.pushIdleMailboxChanges(ctx); err != nil {
			return err
		}
	}
}
