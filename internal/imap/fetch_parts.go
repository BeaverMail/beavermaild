// IMAP FETCH helpers for partial RFC 822 header fields in BODY sections.
package imap

import (
	"bytes"
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
