// RFC 3501 ENVELOPE construction for IMAP FETCH responses.
package imap

import (
	"bytes"
	"fmt"
	"net/mail"
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
	from := formatAddressList(parseEnvelopeAddresses(h.Get("From")))
	sender := formatAddressList(parseEnvelopeAddresses(h.Get("Sender")))
	if sender == "NIL" {
		sender = from
	}
	replyTo := formatAddressList(parseEnvelopeAddresses(h.Get("Reply-To")))
	if replyTo == "NIL" {
		replyTo = from
	}
	to := formatAddressList(parseEnvelopeAddresses(h.Get("To")))
	cc := formatAddressList(parseEnvelopeAddresses(h.Get("Cc")))
	bcc := formatAddressList(parseEnvelopeAddresses(h.Get("Bcc")))
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

func formatAddressList(addrs []*mail.Address) string {
	if len(addrs) == 0 {
		return "NIL"
	}
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = formatMailbox(a)
	}
	return "(" + strings.Join(parts, " ") + ")"
}

// formatMailbox renders one RFC 3501 address (name adl mailbox host).
func formatMailbox(a *mail.Address) string {
	mailbox, host, ok := strings.Cut(strings.TrimSpace(a.Address), "@")
	if !ok || mailbox == "" || host == "" {
		return "(NIL NIL NIL NIL)"
	}
	return fmt.Sprintf("(%s NIL %s %s)", nstring(a.Name), nstring(mailbox), nstring(host))
}

// nstring returns NIL or a quoted IMAP string for envelope slots.
func nstring(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "NIL"
	}
	return quoteIMAPString(s)
}

// quoteIMAPString encodes an IMAP quoted string (escapes \ and ").
func quoteIMAPString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "NIL"
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' || s[i] == '"' {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	b.WriteByte('"')
	return b.String()
}
