// RFC 5321 §4.4 trace fields: Received on every accepted message, Return-Path at final
// delivery, and the hop limit that detects mail loops.
package smtp

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"strings"
	"time"
	"unicode"
)

// maxReceivedHops is the Received-field count above which a message is treated as looping
// (RFC 5321 §6.3 suggests at least 100; 50 is the common MTA default).
const maxReceivedHops = 50

const replyMailLoop = "554 5.4.6 Too many hops, mail loop detected"

// receivedField returns the value of this hop's Received field (folded with CRLF+TAB).
func (s *session) receivedField(now time.Time) string {
	ptr := strings.TrimSuffix(s.iprevPTR, ".")
	if ptr == "" {
		ptr = "unknown"
	}
	// RFC 3848 "with" keywords: SMTP after HELO; ESMTP plus S (TLS) and A (authenticated);
	// UTF8SMTP for a transaction with the SMTPUTF8 parameter (RFC 6531 3.7.3, 4.3).
	proto := "SMTP"
	if s.pipelining {
		proto = "ESMTP"
		if s.mailUTF8 {
			proto = "UTF8SMTP"
		}
		if s.secure {
			proto += "S"
		}
		if s.principal.AccountID != 0 {
			proto += "A"
		}
	}
	ip := s.clientIP()
	if strings.Contains(ip, ":") {
		ip = "IPv6:" + ip // RFC 5321 4.1.3 IPv6-address-literal
	}
	v := fmt.Sprintf("from %s (%s [%s])\r\n\tby %s (BeaverMail) with %s id %s",
		traceToken(s.heloDomain), traceToken(ptr), ip, s.hostname, proto, s.currentFilterID())
	if len(s.rcpt) == 1 {
		v += "\r\n\tfor <" + s.rcpt[0].address + ">"
	}
	if tc, ok := s.conn.(*tls.Conn); ok {
		// RFC 8314 4.3: the registered "tls" clause with the IANA cipher suite name (CipherSuiteName
		// gives "0x%04X" for an unknown one, the tls-cipher-hex form), after "for" as RFC 5321 4.4
		// puts Additional-Registered-Clauses last; the version goes in a comment.
		st := tc.ConnectionState()
		v += fmt.Sprintf("\r\n\ttls %s (%s)", tls.CipherSuiteName(st.CipherSuite), tls.VersionName(st.Version))
	}
	return v + "; " + now.Format(time.RFC1123Z)
}

// traceToken makes a client-chosen name (HELO argument, PTR) safe inside a header:
// first word only, no control characters, "unknown" when empty.
func traceToken(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "unknown"
	}
	t := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '(' || r == ')' || r == ';' {
			return -1
		}
		return r
	}, fields[0])
	if t == "" {
		return "unknown"
	}
	return t
}

// countReceived counts Received fields in the header block.
func countReceived(raw []byte) int {
	n := 0
	forEachHeaderLine(raw, func(line []byte) bool {
		if name, _, ok := bytes.Cut(line, []byte(":")); ok && line[0] != ' ' && line[0] != '\t' &&
			strings.EqualFold(strings.TrimSpace(string(name)), "Received") {
			n++
		}
		return true
	})
	return n
}

// prependHeader puts "name: value" on top of raw, folding value's CRLFs to the message's own
// line ending (DATA messages are stored with LF).
func prependHeader(raw []byte, name, value string) []byte {
	nl := "\r\n"
	if !bytes.Contains(raw, []byte("\r\n")) {
		nl = "\n"
	}
	return append([]byte(name+": "+strings.ReplaceAll(value, "\r\n", nl)+nl), raw...)
}

// stripHeaderFields drops header fields called name (with their folded continuation lines)
// for which drop(value) is true; drop nil removes them all. The body is left untouched.
func stripHeaderFields(raw []byte, name string, drop func(value string) bool) []byte {
	out := make([]byte, 0, len(raw))
	var field []byte // the current field: its first line and continuation lines
	flush := func() {
		if len(field) == 0 {
			return
		}
		// drop sees the whole value, continuation lines included: deciding on the first line alone
		// let "Authentication-Results:" + an authserv-id on the next line through.
		if n, val, ok := bytes.Cut(field, []byte(":")); !ok || !strings.EqualFold(strings.TrimSpace(string(n)), name) ||
			drop != nil && !drop(string(val)) {
			out = append(out, field...)
		}
		field = nil
	}
	rest := raw
	for len(rest) > 0 {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line = rest[:i+1]
		}
		rest = rest[len(line):]
		if len(bytes.TrimRight(line, "\r\n")) == 0 { // end of header
			flush()
			out = append(out, line...)
			return append(out, rest...)
		}
		if line[0] == ' ' || line[0] == '\t' {
			field = append(field, line...)
			continue
		}
		flush()
		field = append(field, line...)
	}
	flush()
	return out
}

// forEachHeaderLine calls fn for each header line (continuations included) until the blank
// line ending the header, or until fn returns false.
func forEachHeaderLine(raw []byte, fn func(line []byte) bool) {
	for len(raw) > 0 {
		line := raw
		if i := bytes.IndexByte(raw, '\n'); i >= 0 {
			line = raw[:i+1]
		}
		raw = raw[len(line):]
		trimmed := bytes.TrimRight(line, "\r\n")
		if len(trimmed) == 0 || !fn(trimmed) {
			return
		}
	}
}
