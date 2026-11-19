// IMAP IDLE command (RFC 2177).
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

// cmdIdle waits for DONE while polling the selected mailbox, if any, for changes. IDLE is valid in
// the authenticated state too (RFC 2177 4), where only NOTIFY has events to send.
func (s *session) cmdIdle(ctx context.Context, tag string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	if _, err := fmt.Fprintf(s.conn, "+ idling\r\n"); err != nil {
		return err
	}
	defer func() {
		// Clear IDLE poll deadline; next readLine restores the session idle timeout.
		_ = s.conn.SetReadDeadline(time.Time{})
	}()

	started := time.Now()
	for {
		if s.readTimeout > 0 && time.Since(started) > s.readTimeout {
			_ = s.untagged("BYE Autologout; idle for too long") // RFC 2177 3 allows it, RFC 3501 5.4: not under 30 min
			return errByeSent
		}
		if s.isStopping() {
			_ = s.untagged("BYE [UNAVAILABLE] Server shutting down")
			return errShuttingDown
		}
		// readLine would replace this short poll deadline with the session idle timeout,
		// so IDLE would never wake up to push new mail when a timeout is configured.
		_ = s.conn.SetReadDeadline(time.Now().Add(idlePollInterval))
		line, err := s.readLineNoDeadline()
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
		// With NOTIFY, IDLE sends exactly the events it set up (RFC 5465 4).
		if s.notify != nil {
			if err := s.notifyPoll(ctx, true); err != nil {
				return err
			}
		} else if s.selected {
			if err := s.pushIdleMailboxChanges(ctx); err != nil {
				return err
			}
		}
	}
}
