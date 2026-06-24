// Minimal SMTP client for outbound message submission.
package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"time"
)

const clientTimeout = 30 * time.Second

// ClientOptions configures optional STARTTLS and AUTH for outbound submission.
type ClientOptions struct {
	STARTTLS bool
	User     string
	Password string
}

// Send submits one message to addr (relay or MX host:port).
func Send(ctx context.Context, addr, mailFrom, rcptTo string, data []byte, opts ClientOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
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
	caps, err := ehlo(conn, r, "localhost")
	if err != nil {
		return err
	}
	if opts.STARTTLS && caps.StartTLS {
		if err := cmd(conn, r, "STARTTLS", 220); err != nil {
			return err
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			return fmt.Errorf("smtp client starttls: %w", err)
		}
		conn = tlsConn
		r = bufio.NewReader(conn)
		caps, err = ehlo(conn, r, "localhost")
		if err != nil {
			return err
		}
	}
	if opts.User != "" && opts.Password != "" {
		if err := authPlain(conn, r, caps, opts.User, opts.Password); err != nil {
			return err
		}
	}

	mailLine := "MAIL FROM:<>"
	if strings.TrimSpace(mailFrom) != "" {
		mailLine = fmt.Sprintf("MAIL FROM:<%s>", mailFrom)
	}
	if len(data) > 0 {
		mailLine += fmt.Sprintf(" SIZE=%d", len(data))
	}
	if caps.EightBitMIME {
		mailLine += " BODY=8BITMIME"
	}
	if err := cmd(conn, r, mailLine, 250); err != nil {
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

type clientCaps struct {
	SizeLimit    int
	StartTLS     bool
	EightBitMIME bool
	Auth         []string
}

func ehlo(conn net.Conn, r *bufio.Reader, name string) (clientCaps, error) {
	if _, err := fmt.Fprintf(conn, "EHLO %s\r\n", name); err != nil {
		return clientCaps{}, err
	}
	return readEHLOCaps(r)
}

func readEHLOCaps(r *bufio.Reader) (clientCaps, error) {
	var caps clientCaps
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return caps, err
		}
		trimmed := strings.TrimSpace(line)
		if len(trimmed) < 3 {
			return caps, fmt.Errorf("smtp client: short response %q", line)
		}
		code := 0
		_, _ = fmt.Sscanf(trimmed[:3], "%d", &code)
		if code != 250 {
			return caps, &ResponseError{Code: code, Line: trimmed}
		}
		if len(trimmed) >= 4 && trimmed[3] != '-' {
			break
		}
		rest := strings.TrimSpace(trimmed[4:])
		upper := strings.ToUpper(rest)
		if strings.HasPrefix(upper, "SIZE ") || strings.HasPrefix(upper, "SIZE\t") {
			_, _ = fmt.Sscanf(upper, "SIZE %d", &caps.SizeLimit)
		}
		if strings.Contains(upper, "STARTTLS") {
			caps.StartTLS = true
		}
		if strings.Contains(upper, "8BITMIME") {
			caps.EightBitMIME = true
		}
		if strings.HasPrefix(upper, "AUTH ") {
			caps.Auth = append(caps.Auth, strings.Fields(upper[5:])...)
		}
	}
	return caps, nil
}

func authPlain(conn net.Conn, r *bufio.Reader, caps clientCaps, user, pass string) error {
	hasPlain := false
	for _, mech := range caps.Auth {
		if strings.EqualFold(mech, "PLAIN") {
			hasPlain = true
			break
		}
	}
	if !hasPlain {
		return fmt.Errorf("smtp client: AUTH PLAIN not advertised")
	}
	cred := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + pass))
	return cmd(conn, r, "AUTH PLAIN "+cred, 235)
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
