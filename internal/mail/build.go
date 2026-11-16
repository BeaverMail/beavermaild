package mail

import (
	"strings"
	"time"
)

// BuildSimpleMessage returns a minimal RFC 5322 message for queue testing: Date and From are
// required, Message-ID SHOULD be present (3.6).
func BuildSimpleMessage(from, to, body string) []byte {
	host := "localhost"
	if i := strings.LastIndexByte(from, '@'); i >= 0 && i < len(from)-1 {
		host = from[i+1:]
	}
	var b strings.Builder
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z))
	b.WriteString("\r\nMessage-ID: <" + dsnMessageID() + "@" + host + ">")
	b.WriteString("\r\nFrom: ")
	b.WriteString(from)
	b.WriteString("\r\nTo: ")
	b.WriteString(to)
	b.WriteString("\r\nSubject: queued\r\n\r\n")
	b.WriteString(body)
	if !strings.HasSuffix(body, "\r\n") {
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}
