// RFC 3501 ENVELOPE construction for IMAP FETCH responses.
package imap

import (
	"bytes"
	"fmt"
	"net/mail"
	"strconv"
	"strings"
)

// formatEnvelope builds the ten-slot ENVELOPE structure from RFC 822 headers.
func formatEnvelope(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return envelopeNIL()
	}
	h := msg.Header
	date := nstring(h.Get("Date"))
	subject := nstring(h.Get("Subject"))
	from := formatAddressField(h.Get("From"))
	sender := formatAddressField(h.Get("Sender"))
	if sender == "NIL" {
		sender = from
	}
	replyTo := formatAddressField(h.Get("Reply-To"))
	if replyTo == "NIL" {
		replyTo = from
	}
	to := formatAddressField(h.Get("To"))
	cc := formatAddressField(h.Get("Cc"))
	bcc := formatAddressField(h.Get("Bcc"))
	inReplyTo := nstring(strings.TrimSpace(h.Get("In-Reply-To")))
	messageID := nstring(strings.TrimSpace(h.Get("Message-ID")))
	return fmt.Sprintf("(%s %s %s %s %s %s %s %s %s %s)",
		date, subject, from, sender, replyTo, to, cc, bcc, inReplyTo, messageID)
}

func envelopeNIL() string {
	return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"
}

// parseEnvelopeAddresses parses RFC 822 address lists, skipping group syntax entries.
func parseEnvelopeAddresses(s string) []*mail.Address {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(s)
	if err != nil {
		if a, err := mail.ParseAddress(s); err == nil {
			return []*mail.Address{a}
		}
		return parseEnvelopeAddressesFallback(s)
	}
	out := make([]*mail.Address, 0, len(addrs))
	for _, a := range addrs {
		if strings.TrimSpace(a.Address) == "" {
			continue
		}
		out = append(out, a)
	}
	if len(out) > 0 {
		return out
	}
	return parseEnvelopeAddressesFallback(s)
}

// parseEnvelopeAddressesFallback extracts angle-addr tokens when the stdlib parser fails.
func parseEnvelopeAddressesFallback(s string) []*mail.Address {
	var out []*mail.Address
	for s != "" {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			break
		}
		if i := strings.IndexByte(s, '<'); i >= 0 {
			j := strings.IndexByte(s[i:], '>')
			if j < 0 {
				break
			}
			j += i
			addr := strings.TrimSpace(s[i+1 : j])
			name := strings.TrimSpace(strings.Trim(s[:i], `"`))
			if addr != "" {
				out = append(out, &mail.Address{Name: name, Address: addr})
			}
			s = s[j+1:]
			continue
		}
		if at := strings.IndexByte(s, '@'); at > 0 {
			end := strings.IndexAny(s[at:], ",; \t")
			addr := strings.TrimSpace(s)
			if end >= 0 {
				addr = strings.TrimSpace(s[:at+end])
				s = s[at+end:]
			} else {
				s = ""
			}
			if a, err := mail.ParseAddress(addr); err == nil {
				out = append(out, a)
			}
			continue
		}
		break
	}
	return out
}

// formatAddressField renders an address header for ENVELOPE. RFC 822 group syntax
// ("name: a@b, c@d;") becomes a group start (NIL NIL "name" NIL), the members, and a group end
// (NIL NIL NIL NIL), as RFC 3501 requires; groups are not expanded away.
func formatAddressField(value string) string {
	var parts []string
	var cur strings.Builder
	flush := func() {
		for _, a := range parseEnvelopeAddresses(cur.String()) {
			parts = append(parts, formatMailbox(a))
		}
		cur.Reset()
	}
	inQuote, inGroup := false, false
	angle, comment := 0, 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c == '\\' && i+1 < len(value):
			cur.WriteByte(c)
			i++
			c = value[i]
		case comment > 0:
			if c == '(' {
				comment++
			} else if c == ')' {
				comment--
			}
		case inQuote:
			inQuote = c != '"'
		case c == '"':
			inQuote = true
		case c == '(':
			comment++
		case c == '<':
			angle++
		case c == '>' && angle > 0:
			angle--
		case angle == 0 && c == ':' && !inGroup:
			name := strings.Trim(strings.TrimSpace(cur.String()), `"`)
			cur.Reset()
			parts = append(parts, "(NIL NIL "+nstring(name)+" NIL)")
			inGroup = true
			continue
		case angle == 0 && c == ';' && inGroup:
			flush()
			parts = append(parts, "(NIL NIL NIL NIL)")
			inGroup = false
			continue
		case angle == 0 && c == ',':
			flush()
			continue
		}
		cur.WriteByte(c)
	}
	flush()
	if inGroup {
		parts = append(parts, "(NIL NIL NIL NIL)")
	}
	if len(parts) == 0 {
		return "NIL"
	}
	return "(" + strings.Join(parts, "") + ")"
}

// formatMailbox renders one RFC 3501 address (name adl mailbox host).
func formatMailbox(a *mail.Address) string {
	addr := strings.TrimSpace(a.Address)
	// An obsolete source route ("<@route:user@domain>", RFC 822) goes in the adl slot.
	var route string
	if strings.HasPrefix(addr, "@") {
		if r, rest, ok := strings.Cut(addr, ":"); ok {
			route, addr = r, rest
		}
	}
	mailbox, host, ok := strings.Cut(addr, "@")
	if !ok || mailbox == "" || host == "" {
		return "(NIL NIL NIL NIL)"
	}
	return fmt.Sprintf("(%s %s %s %s)", nstring(a.Name), nstring(route), nstring(mailbox), nstring(host))
}

// nstring returns NIL or a quoted IMAP string for envelope slots.
func nstring(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "NIL"
	}
	return quoteIMAPString(s)
}

// quoteIMAPString encodes an IMAP string for FETCH responses. An empty value is "" (not NIL:
// body-fld-param values must be strings). CR/LF become spaces and NUL is dropped: neither fits a
// quoted string, and NUL fits no IMAP4rev1 string at all. A value with 8-bit bytes (decoded
// RFC 2047 names, RFC 2231 filenames) is sent as a literal, since quoted strings are 7-bit only.
func quoteIMAPString(s string) string {
	s = strings.TrimSpace(s)
	var clean strings.Builder
	eightBit := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == 0:
		case c == '\r' || c == '\n':
			clean.WriteByte(' ')
		default:
			if c >= 0x80 {
				eightBit = true
			}
			clean.WriteByte(c)
		}
	}
	v := clean.String()
	if eightBit {
		return "{" + strconv.Itoa(len(v)) + "}\r\n" + v
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' || v[i] == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(v[i])
	}
	b.WriteByte('"')
	return b.String()
}
