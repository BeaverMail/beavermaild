// RFC 3501 ENVELOPE construction for IMAP FETCH responses.
package imap

import (
	"bytes"
	"fmt"
	"mime"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/rfc5322"
)

// formatEnvelope builds the ten-slot ENVELOPE structure from RFC 822 headers.
func formatEnvelope(raw []byte) string {
	msg, err := rfc5322.ReadMessage(bytes.NewReader(raw))
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

// formatAddressField renders an address header for ENVELOPE (RFC 3501 7.4.2), groups as a group
// start, the members and a group end; the list is the one SORT derives its keys from.
func formatAddressField(value string) string {
	addrs := mail.ParseAddressField(value)
	if len(addrs) == 0 {
		return "NIL"
	}
	var b strings.Builder
	b.WriteByte('(')
	for _, a := range addrs {
		if a.Host == "" { // a group start (its name in Mailbox), a group end, or an unreadable address
			b.WriteString("(NIL NIL " + nstring(a.Mailbox) + " NIL)")
			continue
		}
		fmt.Fprintf(&b, "(%s %s %s %s)", nphrase(a.Name), nstring(a.Route), nstring(a.Mailbox), nstring(a.Host))
	}
	b.WriteByte(')')
	return b.String()
}

// nstring returns NIL or a quoted IMAP string for envelope and body structure slots.
func nstring(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "NIL"
	}
	return quoteIMAPString(s)
}

// nphrase is nstring for text where RFC 2047 allows encoded-words: a display name (phrase) or a
// *text field such as Content-Description (RFC 2047 5). Go's parsers decode those words into
// UTF-8, but IMAP4rev1 strings carry 8-bit text only with its charset identified (RFC 3501
// 4.3.1): valid UTF-8 goes back out as an encoded-word, 7-bit, charset named. B encoding: its
// alphabet is all inside the set RFC 2047 5(3) allows in a phrase, Q leaves "," and "." bare.
// Never for addresses, parameters or other structured text, where RFC 2047 5 forbids them.
func nphrase(s string) string {
	s = strings.TrimSpace(s)
	if s != "" && has8bit(s) && utf8.ValidString(s) {
		s = mime.BEncoding.Encode("utf-8", s)
	}
	return nstring(s)
}

func has8bit(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
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
