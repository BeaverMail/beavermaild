// RFC 822 header helpers shared by SEARCH, SORT, and THREAD.
package mail

import (
	"bytes"
	"net/mail"
	"strings"
)

// MsgHeaders holds parsed header fields used for SORT and THREAD.
type MsgHeaders struct {
	Date       string
	From       string
	To         string
	Cc         string
	Subject    string
	MessageID  string
	InReplyTo  string
	References []string
}

// ParseMsgHeaders reads common envelope headers from a raw message.
func ParseMsgHeaders(raw []byte) MsgHeaders {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return MsgHeaders{}
	}
	h := msg.Header
	return MsgHeaders{
		Date:       strings.TrimSpace(h.Get("Date")),
		From:       strings.TrimSpace(h.Get("From")),
		To:         strings.TrimSpace(h.Get("To")),
		Cc:         strings.TrimSpace(h.Get("Cc")),
		Subject:    strings.TrimSpace(h.Get("Subject")),
		MessageID:  NormalizeMessageID(h.Get("Message-ID")),
		InReplyTo:  NormalizeMessageID(h.Get("In-Reply-To")),
		References: ParseMessageIDList(h.Get("References")),
	}
}

// NormalizeMessageID lowercases and strips angle brackets from a Message-ID token.
func NormalizeMessageID(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "<>")
	return strings.ToLower(s)
}

// ParseMessageIDList extracts Message-ID tokens from a References (or similar) header.
func ParseMessageIDList(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for s != "" {
		if s[0] == '<' {
			end := strings.IndexByte(s, '>')
			if end < 0 {
				break
			}
			out = append(out, NormalizeMessageID(s[:end+1]))
			s = strings.TrimSpace(s[end+1:])
			continue
		}
		i := strings.IndexByte(s, ' ')
		if i < 0 {
			out = append(out, NormalizeMessageID(s))
			break
		}
		out = append(out, NormalizeMessageID(s[:i]))
		s = strings.TrimSpace(s[i+1:])
	}
	return out
}
