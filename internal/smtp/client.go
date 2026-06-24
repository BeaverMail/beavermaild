// Minimal SMTP client for outbound message submission.
package smtp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const clientTimeout = 30 * time.Second

// Send submits one message to addr (relay or MX host:port).
func Send(ctx context.Context, addr, mailFrom, rcptTo string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	dialer := net.Dialer{Timeout: clientTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp client dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(clientTimeout))

	r := bufio.NewReader(conn)
	if err := expectCode(r, 220); err != nil {
		return err
	}
	if err := cmd(conn, r, "EHLO localhost", 250); err != nil {
		return err
	}
	if err := cmd(conn, r, fmt.Sprintf("MAIL FROM:<%s>", mailFrom), 250); err != nil {
		return err
	}
	if err := cmd(conn, r, fmt.Sprintf("RCPT TO:<%s>", rcptTo), 250); err != nil {
		return err
	}
	if err := cmd(conn, r, "DATA", 354); err != nil {
		return err
	}
	if err := writeDATABody(conn, data); err != nil {
		return err
	}
	if err := expectCode(r, 250); err != nil {
		return err
	}
	_ = cmd(conn, r, "QUIT", 221)
	return nil
}

func cmd(conn net.Conn, r *bufio.Reader, line string, want int) error {
	if _, err := fmt.Fprintf(conn, "%s\r\n", line); err != nil {
		return err
	}
	return expectCode(r, want)
}

func expectCode(r *bufio.Reader, want int) error {
	line, err := r.ReadString('\n')
	if err != nil {
		return err
	}
	if len(line) < 3 {
		return fmt.Errorf("smtp client: short response %q", line)
	}
	code := 0
	_, _ = fmt.Sscanf(line[:3], "%d", &code)
	if code != want {
		return &ResponseError{Code: code, Line: strings.TrimSpace(line)}
	}
	return nil
}
