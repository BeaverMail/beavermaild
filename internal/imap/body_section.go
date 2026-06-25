// IMAP FETCH BODY[section] extraction from RFC 822/MIME messages.
package imap

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/mail"
	"strings"
)

// bodySectionFetch is one BODY[...] or RFC822.* literal item in a FETCH response.
type bodySectionFetch struct {
	itemName   string
	section    string
	hdrFields  []string // set for HEADER.FIELDS sections
}

func parseAllBodyFetches(rest string) []bodySectionFetch {
	var out []bodySectionFetch
	upper := strings.ToUpper(rest)
	for pos := 0; pos < len(rest); {
		tail := strings.ToUpper(rest[pos:])
		peekAt := strings.Index(tail, "BODY.PEEK[")
		bodyAt := strings.Index(tail, "BODY[")
		pick := -1
		switch {
		case peekAt >= 0 && (bodyAt < 0 || peekAt <= bodyAt):
			pick = pos + peekAt
		case bodyAt >= 0:
			pick = pos + bodyAt
		default:
			pos = len(rest)
			continue
		}
		_, _, item, spec, next, ok := scanBodyBracketItem(rest, pick)
		if !ok {
			pos = pick + 1
			continue
		}
		spec = strings.TrimSpace(spec)
		if spec == "" {
			out = append(out, bodySectionFetch{itemName: item, section: ""})
		} else if fields, ok := parseHeaderFieldsSection(spec); ok {
			out = append(out, bodySectionFetch{itemName: item, section: "HEADER.FIELDS", hdrFields: fields})
		} else {
			out = append(out, bodySectionFetch{itemName: item, section: spec})
		}
		pos = next
	}
	if strings.Contains(upper, "RFC822.HEADER") {
		out = append(out, bodySectionFetch{itemName: "RFC822.HEADER", section: "HEADER"})
	}
	if strings.Contains(upper, "RFC822.TEXT") {
		out = append(out, bodySectionFetch{itemName: "RFC822.TEXT", section: "TEXT"})
	}
	hasFull := false
	for _, bs := range out {
		if bs.section == "" {
			hasFull = true
			break
		}
	}
	if !hasFull && strings.Contains(upper, "RFC822") && !strings.Contains(upper, "RFC822.SIZE") &&
		!strings.Contains(upper, "RFC822.HEADER") && !strings.Contains(upper, "RFC822.TEXT") {
		out = append(out, bodySectionFetch{itemName: "RFC822", section: ""})
	}
	return out
}

func scanBodyBracketItem(s string, from int) (start int, peek bool, itemName, spec string, next int, ok bool) {
	rem := strings.ToUpper(s[from:])
	switch {
	case strings.HasPrefix(rem, "BODY.PEEK["):
		start = from
		peek = true
		from += len("BODY.PEEK[")
	case strings.HasPrefix(rem, "BODY["):
		start = from
		from += len("BODY[")
	default:
		return 0, false, "", "", from, false
	}
	end := strings.IndexByte(s[from:], ']')
	if end < 0 {
		return 0, false, "", "", from, false
	}
	end += from
	itemName = s[start : end+1]
	spec = itemName[strings.IndexByte(itemName, '[')+1 : len(itemName)-1]
	return start, peek, itemName, spec, end + 1, true
}

func parseHeaderFieldsSection(spec string) ([]string, bool) {
	spec = strings.TrimSpace(spec)
	if !strings.HasPrefix(strings.ToUpper(spec), "HEADER.FIELDS") {
		return nil, false
	}
	rest := strings.TrimSpace(spec[len("HEADER.FIELDS"):])
	if rest == "" || rest[0] != '(' {
		return []string{}, true
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
		return nil, false
	}
	inner := strings.TrimSpace(rest[1:end])
	if inner == "" {
		return []string{}, true
	}
	return strings.Fields(inner), true
}

// extractBodySection returns bytes for an IMAP BODY section specifier.
func extractBodySection(raw []byte, section string, hdrFields []string) []byte {
	section = strings.TrimSpace(section)
	if section == "" {
		return raw
	}
	if strings.EqualFold(section, "HEADER.FIELDS") {
		return extractHeaderFields(raw, hdrFields)
	}
	upper := strings.ToUpper(section)
	if upper == "HEADER" {
		hdr, _ := splitHeaderBody(raw)
		return hdr
	}
	if upper == "TEXT" {
		_, body := splitHeaderBody(raw)
		return body
	}

	suffix := ""
	pathStr := section
	for _, suf := range []string{".HEADER", ".TEXT", ".MIME"} {
		if strings.HasSuffix(strings.ToUpper(pathStr), suf) {
			suffix = strings.TrimPrefix(suf, ".")
			pathStr = strings.TrimSpace(pathStr[:len(pathStr)-len(suf)])
			break
		}
	}
	indices := parseSectionIndices(pathStr)
	part, ok := fetchMIMEPart(raw, indices)
	if !ok {
		return []byte{}
	}
	switch suffix {
	case "":
		return part
	case "HEADER", "MIME":
		hdr, _ := splitHeaderBody(part)
		return hdr
	case "TEXT":
		_, body := splitHeaderBody(part)
		return body
	default:
		return []byte{}
	}
}

func parseSectionIndices(path string) []int {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	parts := strings.Split(path, ".")
	var out []int
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 {
			return nil
		}
		out = append(out, n)
	}
	return out
}

func splitHeaderBody(raw []byte) (header, body []byte) {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[:i+4], raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[:i+2], raw[i+2:]
	}
	return raw, nil
}

func fetchMIMEPart(raw []byte, path []int) ([]byte, bool) {
	if len(path) == 0 {
		return raw, true
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, false
	}
	mediaType, params := parseMediaType(msg.Header.Get("Content-Type"))
	if !strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		if len(path) == 1 && path[0] == 1 {
			return raw, true
		}
		return nil, false
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, false
	}
	part, ok := readMultipartPart(params["boundary"], body, path[0])
	if !ok {
		return nil, false
	}
	if len(path) == 1 {
		return part, true
	}
	return fetchMIMEPart(part, path[1:])
}

func readMultipartPart(boundary string, body []byte, n int) ([]byte, bool) {
	if boundary == "" || n < 1 {
		return nil, false
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	for i := 1; ; i++ {
		p, err := mr.NextPart()
		if err == io.EOF {
			return nil, false
		}
		if err != nil {
			return nil, false
		}
		if i == n {
			return serializeMIMEPart(p)
		}
		_, _ = io.Copy(io.Discard, p)
	}
}

func serializeMIMEPart(p *multipart.Part) ([]byte, bool) {
	body, err := io.ReadAll(p)
	if err != nil {
		return nil, false
	}
	var b bytes.Buffer
	for key, vals := range p.Header {
		for _, v := range vals {
			b.WriteString(key)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.Bytes(), true
}
