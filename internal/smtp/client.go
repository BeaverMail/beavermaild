// Minimal SMTP client for outbound message submission.
package smtp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/security"
)

// RFC 5321 4.5.3.2: "a timer is set for each SMTP command and for each buffer of the data transfer",
// never one for the whole transaction. The timer starts when we write (a command or a data buffer) and
// the whole reply must arrive before it fires: 5 minutes for the greeting and commands (4.5.3.2.1-3),
// 10 minutes once the transaction starts, which covers the wait after the final "." (4.5.3.2.6).
// Reads never renew it, so a server that dribbles its reply cannot hold the (sequential) queue worker.
const (
	clientDialTimeout    = 30 * time.Second
	clientCommandTimeout = 5 * time.Minute
	clientDataTimeout    = 10 * time.Minute
)

// timeoutConn starts a fresh timer on every Write (one command or data buffer); Reads run against it.
type timeoutConn struct {
	net.Conn
	d time.Duration
}

func (c *timeoutConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetDeadline(time.Now().Add(c.d))
	return c.Conn.Write(p)
}

// ClientOptions configures STARTTLS, AUTH, TLS verify, and MX opportunistic TLS for outbound Send.
type ClientOptions struct {
	STARTTLS              bool // relay: upgrade when configured
	OpportunisticSTARTTLS bool // MX: upgrade when EHLO offers STARTTLS
	TLSInsecureSkipVerify bool // skip server cert verification (dev/self-signed relay only)
	RequireTLS            bool // STARTTLS mandatory, TLS 1.2+, never clear (MTA-STS enforce, smtp.tls_policy)
	User                  string
	Password              string
	HeloName              string // EHLO name; should match the sending IP's PTR (default "localhost")
	// AllowPlainAuth lets User/Password go out without TLS; only for a relay on the loopback interface
	// (see IsLoopbackAddr), where nothing can sniff or strip STARTTLS.
	AllowPlainAuth bool
	// RejectPrivate refuses to connect to loopback, private, link-local or unspecified addresses (MX
	// delivery: a remote domain must not make us talk to our own network).
	RejectPrivate bool
	// DSN carries the recipient's DSN parameters (RFC 3461 5.2.1); the client sets DSN.Passed when
	// the server offered DSN and received them.
	DSN *mail.RelayDSN
}

var (
	// errStartTLSMissing: STARTTLS was configured for the relay but not offered, the sign of a
	// downgrade (STARTTLS stripping); carrying on would send the session, and maybe AUTH, in clear.
	errStartTLSMissing = errors.New("smtp client: STARTTLS is required for this relay but the server does not offer it")
	// errPlainAuth: credentials would travel in clear (RFC 4954 4 / 14).
	errPlainAuth = errors.New("smtp client: refusing to send AUTH credentials without TLS")
)

// relaySecurity checks, before AUTH, what the relay policy needs from the session so far: offered
// caps are those of the first EHLO.
func relaySecurity(opts ClientOptions, preTLSCaps clientCaps, conn net.Conn) error {
	if opts.STARTTLS && !preTLSCaps.StartTLS {
		return errStartTLSMissing
	}
	if opts.User == "" || opts.Password == "" || opts.AllowPlainAuth {
		return nil
	}
	if _, ok := conn.(*tls.Conn); !ok {
		return errPlainAuth
	}
	return nil
}

// errPrivateAddr: the target resolved to an address of our own network (see ClientOptions.RejectPrivate).
var errPrivateAddr = security.ErrPrivateAddr

// IsLoopbackAddr reports whether host:port (or host) names the loopback interface.
func IsLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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
	// RFC 6531 3.2: an A-label domain is not internationalized, so only a UTF-8 local part or UTF-8
	// header fields need SMTPUTF8.
	mailFrom, rcptTo = asciiDomain(mailFrom), asciiDomain(rcptTo)
	needUTF8 := addressNeedsUTF8(mailFrom) || addressNeedsUTF8(rcptTo) || mail.Has8Bit(data) && mail.Has8BitHeaders(data)

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	dialer := net.Dialer{Timeout: clientDialTimeout}
	if opts.RejectPrivate {
		dialer.Control = security.RejectInternalDial
	}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", fmt.Errorf("smtp client dial: %w", err)
	}
	defer raw.Close()
	defer context.AfterFunc(ctx, func() { _ = raw.Close() })() // shutdown must not wait for the timeouts
	tc := &timeoutConn{Conn: raw, d: clientCommandTimeout}
	_ = raw.SetDeadline(time.Now().Add(clientCommandTimeout)) // the 220 greeting (4.5.3.2.1)
	var conn net.Conn = tc

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
	preTLSCaps := caps
	if wantSTARTTLS(opts) && caps.StartTLS {
		tlsConn, err := startTLS(conn, r, host, opts)
		switch {
		case err == nil:
			conn, r = tlsConn, bufio.NewReader(tlsConn)
			if caps, err = ehlo(conn, r, helo); err != nil {
				return "", err
			}
		case !staysClearAfterRefusal(opts, err):
			return "", tlsFailure{err}
		}
	} else if opts.RequireTLS {
		return "", tlsFailure{errors.New("smtp client: TLS is required for this host but STARTTLS is not advertised")}
	}
	if err := relaySecurity(opts, preTLSCaps, conn); err != nil {
		return "", err
	}
	if opts.User != "" && opts.Password != "" {
		if err := authPlain(conn, r, caps, opts.User, opts.Password); err != nil {
			return "", err
		}
	}

	// RFC 1870 7: a message over the server's announced limit would only be refused after the
	// transfer; it is undeliverable there, so fail it now without sending it.
	if caps.SizeLimit > 0 && len(data) > caps.SizeLimit {
		return "", &DeliveryError{Err: fmt.Errorf("smtp client: message of %d octets over the server's SIZE %d", len(data), caps.SizeLimit), Permanent: true}
	}
	// RFC 6531 3.2: UTF-8 addresses and header fields never go to a server without SMTPUTF8 (5.6.7).
	if needUTF8 && !caps.SMTPUTF8 {
		return "", &DeliveryError{Err: mail.ErrNeedsSMTPUTF8, Permanent: true}
	}
	// RFC 6152 3: 8-bit content never goes to a server without 8BITMIME; fail before MAIL (5.6.3).
	if !caps.EightBitMIME && mail.Has8Bit(data) {
		return "", &DeliveryError{Err: mail.ErrNeeds7Bit, Permanent: true}
	}
	tc.d = clientDataTimeout
	mailLine := mailFromLine(mailFrom, data, caps, opts.User != "" && opts.Password != "")
	if needUTF8 {
		mailLine += " SMTPUTF8" // RFC 6531 3.4: MUST when the envelope or message needs it
	}
	rcptLine := fmt.Sprintf("RCPT TO:<%s>", rcptTo)
	// RFC 3461 5.2.1: to a server with DSN, the parameters received go along unchanged, and only
	// those received; it reports from there on. Without DSN none is sent (5.2.2 (a)).
	if d := opts.DSN; d != nil && caps.DSN {
		if d.Ret != mail.RetNone {
			mailLine += " RET=" + string(d.Ret)
		}
		if d.Envid != "" {
			mailLine += " ENVID=" + d.Envid
		}
		if kw := mail.NotifyKeyword(d.Notify); kw != "" {
			rcptLine += " NOTIFY=" + kw
		}
		if d.Orcpt != "" {
			orcpt := d.Orcpt
			if !needUTF8 {
				orcpt = mail.OrcptASCII(orcpt) // RFC 6533 3: 7-bit form without SMTPUTF8
			}
			rcptLine += " ORCPT=" + orcpt
		}
		d.Passed = true
	}

	if caps.Pipelining {
		return sendPipelined(conn, r, mailLine, rcptLine, data, caps)
	}
	return sendSequential(conn, r, mailLine, rcptLine, data, caps)
}

func wantSTARTTLS(opts ClientOptions) bool {
	return opts.STARTTLS || opts.OpportunisticSTARTTLS || opts.RequireTLS
}

// mailFromLine builds MAIL FROM. After authenticating to the server it adds AUTH=<>: RFC 4954 5
// requires it when relaying to a server one has authenticated to, and this server vouches for
// no submitter identity.
func mailFromLine(mailFrom string, data []byte, caps clientCaps, authenticated bool) string {
	mailLine := "MAIL FROM:<>"
	if strings.TrimSpace(mailFrom) != "" {
		mailLine = fmt.Sprintf("MAIL FROM:<%s>", mailFrom)
	}
	if authenticated {
		mailLine += " AUTH=<>"
	}
	if len(data) > 0 && caps.Size { // only to a server offering SIZE (RFC 5321 4.1.1.11)
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

// staysClearAfterRefusal reports whether, the server having refused STARTTLS with a reply (no handshake
// started, the session still in clear and usable), the transaction goes on in clear: only for
// opportunistic TLS (RFC 7435 3, 4: cleartext is the baseline, a refusal is no reason not to deliver).
// 421 means the server is closing: that MX is unusable.
func staysClearAfterRefusal(opts ClientOptions, err error) bool {
	var re *ResponseError
	return opts.OpportunisticSTARTTLS && !opts.RequireTLS && errors.As(err, &re) && re.Code != 421
}

// startTLS upgrades the session. ServerName is always the host, for SNI (RFC 8461 7.1). TLS 1.2 is the
// floor even for opportunistic TLS: RFC 8996 2-3 "TLS 1.0 [1.1] MUST NOT be used", with no exception
// for unauthenticated encryption; Go's default suites leave out static RSA (RFC 9325 4.1 SHOULD NOT).
func startTLS(conn net.Conn, r *bufio.Reader, host string, opts ClientOptions) (net.Conn, error) {
	if err := cmd(conn, r, "STARTTLS", 220); err != nil {
		return nil, err
	}
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.TLSInsecureSkipVerify,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("smtp client starttls: %w", err)
	}
	return tlsConn, nil
}

type clientCaps struct {
	Size         bool // SIZE offered, with or without a limit
	SizeLimit    int
	StartTLS     bool
	EightBitMIME bool
	Chunking     bool
	Pipelining   bool
	DSN          bool
	SMTPUTF8     bool
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
	for first := true; ; first = false {
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
		last := len(trimmed) == 3 || trimmed[3] != '-'
		// RFC 5321 4.1.1.1: the first line carries the domain; every later line, the last one included, is an ehlo-line.
		if fields := strings.Fields(trimmed[min(4, len(trimmed)):]); !first && len(fields) > 0 {
			switch strings.ToUpper(fields[0]) {
			case "SIZE":
				caps.Size = true
				if len(fields) > 1 {
					_, _ = fmt.Sscanf(fields[1], "%d", &caps.SizeLimit)
				}
			case "STARTTLS":
				caps.StartTLS = true
			case "8BITMIME":
				caps.EightBitMIME = true
			case "CHUNKING":
				caps.Chunking = true
			case "PIPELINING":
				caps.Pipelining = true
			case "DSN":
				caps.DSN = true
			case "SMTPUTF8":
				caps.SMTPUTF8 = true
			case "AUTH":
				for _, m := range fields[1:] {
					caps.Auth = append(caps.Auth, strings.ToUpper(m))
				}
			}
		}
		if last {
			return caps, nil
		}
	}
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

// asciiDomain writes the domain of an address with an ASCII local part as A-labels, so it needs no
// SMTPUTF8 (RFC 6531 3.2). A UTF-8 local part keeps the address as it is.
func asciiDomain(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || addressNeedsUTF8(addr[:at]) || !addressNeedsUTF8(addr[at:]) {
		return addr
	}
	return addr[:at+1] + dnsname.ToASCII(addr[at+1:])
}
