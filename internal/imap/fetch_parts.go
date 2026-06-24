// IMAP FETCH helpers for ENVELOPE and partial header fields.
package imap

import (
	"bytes"
	"fmt"
	"net/mail"
	"strings"
)

// extractHeaderFields returns requested RFC 822 header lines (CRLF separated).
func extractHeaderFields(raw []byte, fields []string) []byte {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil
	}
	want := make(map[string]struct{}, len(fields))
	for _, f := range fields {
		want[strings.ToUpper(strings.TrimSpace(f))] = struct{}{}
	}
	var b strings.Builder
	for key, vals := range msg.Header {
		if _, ok := want[strings.ToUpper(key)]; !ok {
			continue
		}
		for _, v := range vals {
			b.WriteString(key)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return []byte(b.String())
}

// formatEnvelope builds a minimal RFC 3501 ENVELOPE response from raw message bytes.
func formatEnvelope(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return envelopeNIL()
	}
	h := msg.Header
	date := quoteIMAPString(h.Get("Date"))
	subject := quoteIMAPString(h.Get("Subject"))
	from := formatAddressList(parseAddresses(h.Get("From")))
	sender := from
	replyTo := formatAddressList(parseAddresses(h.Get("Reply-To")))
	if replyTo == "NIL" {
		replyTo = from
	}
	to := formatAddressList(parseAddresses(h.Get("To")))
	cc := formatAddressList(parseAddresses(h.Get("Cc")))
	bcc := formatAddressList(parseAddresses(h.Get("Bcc")))
	inReplyTo := quoteIMAPString(strings.TrimSpace(h.Get("In-Reply-To")))
	messageID := quoteIMAPString(strings.TrimSpace(h.Get("Message-ID")))
	return fmt.Sprintf("(%s %s %s %s %s %s %s %s %s %s)",
		date, subject, from, sender, replyTo, to, cc, bcc, inReplyTo, messageID)
}

func envelopeNIL() string {
	return "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)"
}

func parseAddresses(s string) []*mail.Address {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	addrs, err := mail.ParseAddressList(s)
	if err != nil {
		if a, err := mail.ParseAddress(s); err == nil {
			return []*mail.Address{a}
		}
		return nil
	}
	return addrs
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

func formatMailbox(a *mail.Address) string {
	mailbox, host, ok := strings.Cut(strings.TrimSpace(a.Address), "@")
	if !ok || mailbox == "" || host == "" {
		return "(NIL NIL NIL NIL)"
	}
	return fmt.Sprintf("(%s NIL %s %s)", quoteIMAPString(a.Name), quoteIMAPString(mailbox), quoteIMAPString(host))
}

func quoteIMAPString(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "NIL"
	}
	return `"` + strings.ReplaceAll(s, `\`, `\\`) + `"`
}

// parseHeaderFieldsFetch detects BODY[HEADER.FIELDS (...)] in a FETCH item list.
func parseHeaderFieldsFetch(rest string) ([]string, bool) {
	upper := strings.ToUpper(rest)
	idx := strings.Index(upper, "HEADER.FIELDS")
	if idx < 0 {
		return nil, false
	}
	rest = rest[idx+len("HEADER.FIELDS"):]
	rest = strings.TrimSpace(rest)
	if rest == "" || rest[0] != '(' {
		return nil, true
	}
	depth := 0
	end := -1
	for i, c := range rest {
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				goto done
			}
		}
	}
done:
	if end < 0 {
		return nil, true
	}
	inner := strings.TrimSpace(rest[1:end])
	if inner == "" {
		return []string{}, true
	}
	return strings.Fields(inner), true
}

func headerFieldsItemName(fields []string) string {
	return "BODY[HEADER.FIELDS (" + strings.Join(fields, " ") + ")]"
}
