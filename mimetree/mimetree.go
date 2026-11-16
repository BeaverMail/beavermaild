// Package mimetree splits a message into its MIME parts (RFC 2045, RFC 2046) once, with the limits
// and robustness rules every reader of the message must share. The IMAP server shows clients this
// tree and the antispam plugin judges the same tree: two parsers with different rules or limits let
// a sender put content where one of them looks and the other does not.
package mimetree

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
)

const (
	// MaxDepth bounds the multipart and message/rfc822 levels entered. Each level scans its whole
	// body for its boundary, so an unbounded walk costs O(depth x size) (Dovecot CVE-2020-12100).
	MaxDepth = 100
	// MaxParts bounds the parts of one message: 32 MiB of empty parts is 4.8 million of them, and
	// one IMAP BODYSTRUCTURE of it took 22 GB of allocations. Same limits as Dovecot.
	MaxParts = 10000
)

// Part is one MIME entity. Header and Body are slices of the parsed message, never copies.
type Part struct {
	Header []byte               // header section with its blank line
	Body   []byte               // body, as stored
	MIME   textproto.MIMEHeader // parsed header; what was readable when a line is malformed
	Type   string               // lower-case media type, defaults applied (text/plain, or message/rfc822 in a digest)
	Params map[string]string    // media type parameters, lower-case names
	// BadType reports a Content-Type that is present but not valid: Type is then text/plain (RFC
	// 2045 5.2).
	BadType bool
	// BadHeader reports a header line that is not a field (no colon, a bad name, a continuation with
	// nothing to continue). It is skipped and the fields after it are read, as lenient clients do;
	// others end the header there, so the part is ambiguous.
	BadHeader bool
	// BadEncoding reports a multipart or message/rfc822 with a transfer encoding other than 7bit,
	// 8bit or binary, which RFC 2045 6.4 forbids. Its body is split as it is; a client that decodes
	// it first sees other parts.
	BadEncoding bool
	// Opaque reports a multipart or message/rfc822 part not entered because it is MaxDepth levels
	// down or the message has MaxParts parts already; Type is then application/octet-stream.
	Opaque bool
	// Truncated reports a multipart whose parts stop at MaxParts: the last one runs to the end of
	// the multipart body, delimiters included.
	Truncated bool
	Depth     int
	// Children are the parts of a multipart, or the one message a message/rfc822 part encapsulates.
	Children []*Part
}

// IsMultipart reports a multipart entity.
func (p *Part) IsMultipart() bool { return strings.HasPrefix(p.Type, "multipart/") }

// Parse returns the tree of raw, a whole message.
func Parse(raw []byte) *Part {
	budget := MaxParts
	return parse(raw, 0, false, &budget)
}

func parse(raw []byte, depth int, inDigest bool, budget *int) *Part {
	*budget--
	p := splitEntity(raw)
	p.Depth = depth
	p.MIME, p.BadHeader = readHeader(p.Header)
	p.Type, p.Params, p.BadType = mediaType(p.MIME.Get("Content-Type"), inDigest)
	if !p.IsMultipart() && p.Type != "message/rfc822" {
		return p
	}
	switch strings.ToLower(strings.TrimSpace(p.MIME.Get("Content-Transfer-Encoding"))) {
	case "", "7bit", "8bit", "binary", "7-bit", "8-bit":
	default:
		p.BadEncoding = true
	}
	if depth >= MaxDepth || *budget <= 0 {
		p.Type, p.Params, p.Opaque = "application/octet-stream", nil, true
		return p
	}
	if p.Type == "message/rfc822" {
		p.Children = []*Part{parse(p.Body, depth+1, false, budget)}
		return p
	}
	spans := splitMultipart(p.Body, p.Params["boundary"])
	digest := p.Type == "multipart/digest"
	for _, s := range spans {
		if *budget <= 0 && len(p.Children) > 0 {
			// The rest stays in the last part's body. Slices of one array: a slice's offset in
			// p.Body is the capacity it lost.
			last := p.Children[len(p.Children)-1]
			last.Body = p.Body[cap(p.Body)-cap(last.Body):]
			p.Truncated = true
			break
		}
		p.Children = append(p.Children, parse(p.Body[s[0]:s[1]], depth+1, digest, budget))
	}
	return p
}

// mediaType applies RFC 2045 5.2 (absent or invalid: text/plain) and RFC 2046 5.1.5 (in a digest
// the default is message/rfc822).
func mediaType(ct string, inDigest bool) (string, map[string]string, bool) {
	if strings.TrimSpace(ct) == "" {
		if inDigest {
			return "message/rfc822", map[string]string{}, false
		}
		return "text/plain", map[string]string{}, false
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil || !strings.Contains(mt, "/") {
		return "text/plain", map[string]string{}, true
	}
	return strings.ToLower(mt), params, false
}

// readHeader reads the fields of a header section. net/textproto stops at the first malformed
// line, so a Content-Type after it was lost here while a client that skips the line used it:
// content the filter never decoded. Values are unfolded with one space, as net/textproto does; white
// space before the colon is the obsolete form of the name (RFC 5322 4.5).
func readHeader(h []byte) (textproto.MIMEHeader, bool) {
	out := textproto.MIMEHeader{}
	bad := false
	var last []string
	for _, line := range strings.Split(string(h), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			break
		}
		if line[0] == ' ' || line[0] == '\t' {
			if last == nil {
				bad = true
				continue
			}
			if v := strings.TrimSpace(line); v != "" {
				if last[len(last)-1] != "" {
					v = " " + v
				}
				last[len(last)-1] += v
			}
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimRight(name, " \t")
		if !ok || !validFieldName(name) {
			bad, last = true, nil
			continue
		}
		key := textproto.CanonicalMIMEHeaderKey(name)
		out[key] = append(out[key], strings.TrimSpace(value))
		last = out[key]
	}
	return out, bad
}

// validFieldName: printable US-ASCII except colon (RFC 5322 2.2).
func validFieldName(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return false
		}
	}
	return s != ""
}

// splitEntity splits raw after its first empty line, whatever its line ends: CRLF or a bare LF,
// as clients see it (IMAP serves stored messages with every bare LF made CRLF, and BDAT stores what
// it receives, mixed ends included). Looking for "\r\n\r\n" first ended the header later than
// every client when a "\n\n" came before it. A part with no header fields starts with the empty
// line itself.
func splitEntity(raw []byte) *Part {
	for pos := 0; pos < len(raw); {
		if raw[pos] == '\n' {
			return &Part{Header: raw[:pos+1], Body: raw[pos+1:]}
		}
		if raw[pos] == '\r' && pos+1 < len(raw) && raw[pos+1] == '\n' {
			return &Part{Header: raw[:pos+2], Body: raw[pos+2:]}
		}
		nl := bytes.IndexByte(raw[pos:], '\n')
		if nl < 0 {
			break
		}
		pos += nl + 1
	}
	return &Part{Header: raw, Body: raw[len(raw):]}
}

// splitMultipart returns the [start, end) spans of the body parts between "--boundary" delimiter
// lines. The line break before a delimiter belongs to it; preamble and epilogue are dropped. A
// multipart with no close delimiter ends at the end of its body (RFC 2046 5.1.2): its last part is
// kept, not lost.
func splitMultipart(body []byte, boundary string) [][2]int {
	if boundary == "" {
		return nil
	}
	delim := []byte("--" + boundary)
	var spans [][2]int
	start := -1
	for pos := 0; ; {
		i := indexLineStart(body, pos, delim)
		if i >= 0 && !delimiterEnds(body[i+len(delim):]) {
			pos = i + 1 // "--b10" is not the delimiter of boundary "b1"
			continue
		}
		if start >= 0 {
			end := len(body)
			if i >= 0 {
				end = i
				if end >= start+2 && body[end-2] == '\r' && body[end-1] == '\n' {
					end -= 2
				} else if end >= start+1 && body[end-1] == '\n' {
					end--
				}
			}
			spans = append(spans, [2]int{start, max(end, start)})
		}
		if i < 0 {
			return spans
		}
		after := i + len(delim)
		if bytes.HasPrefix(body[after:], []byte("--")) {
			return spans
		}
		nl := bytes.IndexByte(body[after:], '\n')
		if nl < 0 {
			return spans
		}
		start = after + nl + 1
		pos = start
	}
}

// delimiterEnds reports whether rest, the bytes after "--boundary", completes a delimiter line:
// "--" (close delimiter) or optional linear white space up to the end of the line (RFC 2046 5.1.1).
func delimiterEnds(rest []byte) bool {
	if bytes.HasPrefix(rest, []byte("--")) {
		return true
	}
	line, _, _ := bytes.Cut(rest, []byte("\n"))
	return len(bytes.Trim(line, " \t\r")) == 0
}

// indexLineStart finds sep at the start of a line at or after from.
func indexLineStart(b []byte, from int, sep []byte) int {
	for from <= len(b) {
		i := bytes.Index(b[from:], sep)
		if i < 0 {
			return -1
		}
		i += from
		if i == 0 || b[i-1] == '\n' {
			return i
		}
		from = i + 1
	}
	return -1
}

// Decode returns body decoded from its Content-Transfer-Encoding, read as robustly as RFC 2045
// asks: base64 ignores every character outside its alphabet (6.8), quoted-printable passes control
// bytes through (6.7). ok is false for an encoding it does not know; body is then returned as is.
func Decode(cte string, body []byte) (out []byte, ok bool) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "", "7bit", "8bit", "binary", "7-bit", "8-bit":
		return body, true
	case "base64":
		clean := bytes.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' {
				return r
			}
			return -1
		}, body)
		if len(clean)%4 == 1 { // a lone trailing character holds no full byte
			clean = clean[:len(clean)-1]
		}
		out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
		n, _ := base64.RawStdEncoding.Decode(out, clean)
		return out[:n], true
	case "quoted-printable":
		out, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(escapeQPControls(body))))
		return out, true
	}
	return body, false
}

// escapeQPControls writes as =XX the control bytes Go's quoted-printable reader rejects: it would
// stop there and truncate the part.
func escapeQPControls(b []byte) []byte {
	var out []byte
	for i, c := range b {
		if c < ' ' && c != '\t' && c != '\r' && c != '\n' || c == 0x7f {
			if out == nil {
				out = append(make([]byte, 0, len(b)+8), b[:i]...)
			}
			out = append(out, '=', "0123456789ABCDEF"[c>>4], "0123456789ABCDEF"[c&15])
			continue
		}
		if out != nil {
			out = append(out, c)
		}
	}
	if out == nil {
		return b
	}
	return out
}
