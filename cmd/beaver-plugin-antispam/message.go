// Message header parsing for antispam classify (body_path, no store access).
package main

import (
	"errors"
	"mime"
	"strings"
	"time"
)

const gtubeSubject = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"

// parsedMessage holds headers extracted from a raw RFC 5322 message file.
type parsedMessage struct {
	Subject   string
	From      string
	ReplyTo   string
	To        []string
	Cc        []string
	Bcc       []string
	fromAddrs []string
	Date      string
	MessageID string
	DateTime  time.Time
	hasDate   bool
	received  []string
	headers   map[string][]string
}

func (m *parsedMessage) headersText(name string) string {
	vals := m.headers[strings.ToLower(name)]
	return strings.Join(vals, " ")
}

// loadParsedMessage reads headers from bodyPath up to maxHeaderBytes.
func loadParsedMessage(bodyPath string, maxHeaderBytes int) (*parsedMessage, error) {
	if bodyPath == "" {
		return &parsedMessage{headers: make(map[string][]string)}, nil
	}
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = 65536
	}
	b, err := osReadFileLimit(bodyPath, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	header, _ := splitHeadersBody(b)
	return parseMessageHeaders(header), nil
}

// parseMessageHeaders builds parsedMessage from raw header bytes.
func parseMessageHeaders(header []byte) *parsedMessage {
	meta := &parsedMessage{headers: make(map[string][]string)}
	for name, vals := range unfoldHeaders(header) {
		ln := strings.ToLower(name)
		meta.headers[ln] = append(meta.headers[ln], vals...)
		switch ln {
		case "subject":
			if len(vals) > 0 {
				meta.Subject = decodeHeaderValue(vals[len(vals)-1])
			}
		case "from":
			for _, v := range vals {
				a := parseAddr(v)
				if a != "" {
					meta.fromAddrs = append(meta.fromAddrs, a)
					if meta.From == "" {
						meta.From = a
					}
				}
			}
		case "reply-to":
			if len(vals) > 0 {
				meta.ReplyTo = parseAddr(vals[len(vals)-1])
			}
		case "to":
			for _, v := range vals {
				meta.To = append(meta.To, parseAddr(v))
			}
		case "cc":
			for _, v := range vals {
				meta.Cc = append(meta.Cc, parseAddr(v))
			}
		case "bcc":
			for _, v := range vals {
				meta.Bcc = append(meta.Bcc, parseAddr(v))
			}
		case "date":
			if len(vals) > 0 {
				meta.Date = strings.TrimSpace(vals[len(vals)-1])
				if t, err := parseMailDate(meta.Date); err == nil {
					meta.DateTime = t
					meta.hasDate = true
				}
			}
		case "message-id":
			if len(vals) > 0 {
				meta.MessageID = strings.Trim(strings.TrimSpace(vals[len(vals)-1]), "<>")
			}
		case "received":
			for _, v := range vals {
				meta.received = append(meta.received, strings.TrimSpace(v))
			}
		}
	}
	return meta
}

func headerFirst(headers []byte, name string) string {
	for n, vals := range unfoldHeaders(headers) {
		if n == strings.ToLower(name) && len(vals) > 0 {
			return decodeHeaderValue(vals[0])
		}
	}
	return ""
}

// unfoldHeaders returns header values; repeated names accumulate (e.g. Received).
func unfoldHeaders(headers []byte) map[string][]string {
	out := make(map[string][]string)
	var curName string
	var curVal strings.Builder
	flush := func() {
		if curName == "" {
			return
		}
		out[curName] = append(out[curName], strings.TrimSpace(curVal.String()))
		curName = ""
		curVal.Reset()
	}
	for _, line := range strings.Split(string(headers), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if curName != "" {
				curVal.WriteByte(' ')
				curVal.WriteString(strings.TrimSpace(line))
			}
			continue
		}
		flush()
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		curName = strings.ToLower(strings.TrimSpace(line[:colon]))
		curVal.WriteString(strings.TrimSpace(line[colon+1:]))
	}
	flush()
	return out
}

func decodeHeaderValue(raw string) string {
	dec := new(mime.WordDecoder)
	if s, err := dec.DecodeHeader(raw); err == nil {
		return s
	}
	return raw
}

func extractSubject(headers []byte) string {
	return headerFirst(headers, "subject")
}

func splitHeadersBody(raw []byte) (header, body []byte) {
	s := string(raw)
	if i := strings.Index(s, "\r\n\r\n"); i >= 0 {
		return []byte(s[:i]), []byte(s[i+4:])
	}
	if i := strings.Index(s, "\n\n"); i >= 0 {
		return []byte(s[:i]), []byte(s[i+2:])
	}
	return raw, nil
}

func parseMailDate(s string) (time.Time, error) {
	layouts := []string{
		time.RFC1123Z,
		time.RFC1123,
		"Mon, 2 Jan 2006 15:04:05 -0700",
		"2 Jan 2006 15:04:05 -0700",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("invalid date")
}
