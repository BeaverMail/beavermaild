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

	"github.com/BeaverMail/beavermaild/internal/mail"
)

const clientTimeout = 30 * time.Second

// ClientOptions configures STARTTLS, AUTH, TLS verify, and MX opportunistic TLS for outbound Send.
type ClientOptions struct {
	STARTTLS              bool // relay: upgrade when configured
	OpportunisticSTARTTLS bool // MX: upgrade when EHLO offers STARTTLS
	TLSInsecureSkipVerify bool // skip server cert verification (dev/self-signed relay only)
	MTASTSRequireTLS      bool // MX: RFC 8461 enforce requires STARTTLS with PKIX verify
	User                  string
	Password              string
	HeloName              string // EHLO name; should match the sending IP's PTR (default "localhost")
}

// Send submits one message to addr (relay or MX host:port).
func Send(ctx context.Context, addr, mailFrom, rcptTo string, data []byte, opts ClientOptions) error {
	_, err := SendReply(ctx, addr, mailFrom, rcptTo, data, opts)
	return err
}

// SendReply is Send returning the server's final reply to the message (e.g. "250 2.0.0 OK ... - gsmtp").
func SendReply(ctx context.Context, addr, mailFrom, rcptTo string, data []byte, opts ClientOptions) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// BDAT sends bytes verbatim and SIZE counts them: both need the CRLF wire form.
	data = mail.CRLF(data)

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	dialer := net.Dialer{Timeout: clientTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("smtp client dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(clientTimeout))

	r := bufio.NewReader(conn)
	if err := expectCode(r, 220); err != nil {
		return "", err
	}
	helo := opts.HeloName
	if helo == "" {
		helo = "localhost"
	}
	caps, err := ehlo(conn, r, helo)
	if err != nil {
		return "", err
	}
	if wantSTARTTLS(opts) && caps.StartTLS {
		conn, err = startTLS(conn, r, host, opts.TLSInsecureSkipVerify)
		if err != nil {
			if opts.MTASTSRequireTLS {
				return "", &DeliveryError{Err: fmt.Errorf("smtp client starttls: %w", err), Permanent: true}
			}
			return "", err
		}
		r = bufio.NewReader(conn)
		caps, err = ehlo(conn, r, helo)
		if err != nil {
			return "", err
		}
	} else if opts.MTASTSRequireTLS {
		return "", &DeliveryError{Err: fmt.Errorf("mta-sts: STARTTLS required but not advertised"), Permanent: true}
	}
	if opts.User != "" && opts.Password != "" {
		if err := authPlain(conn, r, caps, opts.User, opts.Password); err != nil {
			return "", err
		}
	}

	mailLine := mailFromLine(mailFrom, data, caps)
	rcptLine := fmt.Sprintf("RCPT TO:<%s>", rcptTo)

	if caps.Pipelining {
		return sendPipelined(conn, r, mailLine, rcptLine, data, caps)
	}
	return sendSequential(conn, r, mailLine, rcptLine, data, caps)
}

func wantSTARTTLS(opts ClientOptions) bool {
	return opts.STARTTLS || opts.OpportunisticSTARTTLS || opts.MTASTSRequireTLS
}

func mailFromLine(mailFrom string, data []byte, caps clientCaps) string {
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
	return mailLine
}

func sendSequential(conn net.Conn, r *bufio.Reader, mailLine, rcptLine string, data []byte, caps clientCaps) (string, error) {
	if err := cmd(conn, r, mailLine, 250); err != nil {
		return "", err
	}
	if err := cmd(conn, r, rcptLine, 250); err != nil {
		return "", err
	}
	return sendBody(conn, r, data, caps)
}

func sendPipelined(conn net.Conn, r *bufio.Reader, mailLine, rcptLine string, data []byte, caps clientCaps) (string, error) {
	useBDAT := caps.Chunking && len(data) > 0
	if err := writeLine(conn, mailLine); err != nil {
		return "", err
	}
	if err := writeLine(conn, rcptLine); err != nil {
		return "", err
	}
	if useBDAT {
		if err := writeBDATChunk(conn, data); err != nil {
			return "", err
		}
	} else {
		if err := writeLine(conn, "DATA"); err != nil {
			return "", err
		}
	}
	if err := expectCode(r, 250); err != nil {
		return "", err
	}
	if err := expectCode(r, 250); err != nil {
		return "", err
	}
	if !useBDAT {
		if err := expectCode(r, 354); err != nil {
			return "", err
		}
		if err := writeDATABody(conn, data); err != nil {
			return "", err
		}
	}
	return finishMessage(conn, r)
}

func sendBody(conn net.Conn, r *bufio.Reader, data []byte, caps clientCaps) (string, error) {
	if caps.Chunking && len(data) > 0 {
		if err := writeBDATChunk(conn, data); err != nil {
			return "", err
		}
	} else {
		if err := cmd(conn, r, "DATA", 354); err != nil {
			return "", err
		}
		if err := writeDATABody(conn, data); err != nil {
			return "", err
		}
	}
	return finishMessage(conn, r)
}

// finishMessage reads the server's verdict on the message body, then quits.
func finishMessage(conn net.Conn, r *bufio.Reader) (string, error) {
	reply, err := expectReply(r, 250)
	if err != nil {
		return "", err
	}
	_ = cmd(conn, r, "QUIT", 221)
	return reply, nil
}

// writeBDATChunk sends "BDAT n LAST" immediately followed by exactly n bytes (RFC 3030):
// the server replies only after reading the chunk, so waiting for a reply in between deadlocks.
func writeBDATChunk(conn net.Conn, data []byte) error {
	if err := writeLine(conn, fmt.Sprintf("BDAT %d LAST", len(data))); err != nil {
		return err
	}
	_, err := conn.Write(data)
	return err
}

func writeLine(conn net.Conn, line string) error {
	_, err := fmt.Fprintf(conn, "%s\r\n", line)
	return err
}

func startTLS(conn net.Conn, r *bufio.Reader, host string, insecureSkipVerify bool) (net.Conn, error) {
	if err := cmd(conn, r, "STARTTLS", 220); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecureSkipVerify,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("smtp client starttls: %w", err)
	}
	return tlsConn, nil
}

type clientCaps struct {
	SizeLimit    int
	StartTLS     bool
	EightBitMIME bool
	Chunking     bool
	Pipelining   bool
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
		if strings.Contains(upper, "CHUNKING") {
			caps.Chunking = true
		}
		if strings.Contains(upper, "PIPELINING") {
			caps.Pipelining = true
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
	if err := writeLine(conn, line); err != nil {
		return err
	}
	return expectCode(r, want)
}

func expectCode(r *bufio.Reader, want int) error {
	_, err := expectReply(r, want)
	return err
}

// expectReply reads one reply, including every "NNN-" continuation line (RFC 5321
// multi-line replies, e.g. Exim's BDAT "250- 1249 byte chunk" then "250 OK id=..."), and
// returns its final line trimmed when the code matches want.
func expectReply(r *bufio.Reader, want int) (string, error) {
	var line string
	for {
		l, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if len(l) < 3 {
			return "", fmt.Errorf("smtp client: short response %q", l)
		}
		line = l
		if len(l) < 4 || l[3] != '-' {
			break
		}
	}
	code := 0
	_, _ = fmt.Sscanf(line[:3], "%d", &code)
	if code != want {
		return "", &ResponseError{Code: code, Line: strings.TrimSpace(line)}
	}
	return strings.TrimSpace(line), nil
}
