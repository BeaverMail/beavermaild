// IMAP FETCH BODY[section] extraction from RFC 822/MIME messages.
package imap

import (
	"bufio"
	"bytes"
	"net/textproto"
	"strconv"
	"strings"
)

// bodySectionFetch is one BODY[...] or RFC822.* literal item in a FETCH response.
type bodySectionFetch struct {
	itemName  string
	section   string
	hdrFields []string // set for HEADER.FIELDS[.NOT] sections
	setsSeen  bool     // BODY[...] without PEEK, RFC822, RFC822.TEXT: fetching sets \Seen
	binary    bool     // BINARY[...]: the part decoded from its transfer encoding (RFC 3516)
	sizeOnly  bool     // BINARY.SIZE[...]: only the decoded size

	// partial is set for BODY[...]<origin.count>: only count bytes from origin are sent.
	partial bool
	origin  int
	count   int
}

// parsePartial parses a "<origin.count>" suffix at s[pos:], returning the bytes it spans.
func parsePartial(s string, pos int) (origin, count, n int, ok bool) {
	if pos >= len(s) || s[pos] != '<' {
		return 0, 0, 0, false
	}
	end := strings.IndexByte(s[pos:], '>')
	if end < 0 {
		return 0, 0, 0, false
	}
	o, c, found := strings.Cut(s[pos+1:pos+end], ".")
	if !found || !isDigits(o) || !isDigits(c) {
		return 0, 0, 0, false
	}
	origin, err1 := strconv.Atoi(o)
	count, err2 := strconv.Atoi(c)
	if err1 != nil || err2 != nil || count == 0 {
		return 0, 0, 0, false
	}
	return origin, count, end + 1, true
}

// partialData returns the bytes of data a BODY[...]<origin.count> fetch sends.
// wholeMessage reports a section that is the stored message as is (BODY[], RFC822, with or without
// <origin.count>), which FETCH can stream from the file.
func (bs bodySectionFetch) wholeMessage() bool {
	return strings.TrimSpace(bs.section) == "" && !bs.binary && !bs.sizeOnly && bs.hdrFields == nil
}

// partialRange is partialData as an offset and length into a message of size bytes.
func (bs bodySectionFetch) partialRange(size int64) (off, n int64) {
	if !bs.partial {
		return 0, size
	}
	off = int64(bs.origin)
	if off >= size {
		return size, 0
	}
	return off, min(int64(bs.count), size-off)
}

func (bs bodySectionFetch) partialData(data []byte) []byte {
	if !bs.partial {
		return data
	}
	if bs.origin >= len(data) {
		return nil
	}
	end := len(data)
	if bs.count < end-bs.origin {
		end = bs.origin + bs.count
	}
	return data[bs.origin:end]
}

// responseName is the item name in the FETCH response: BODY.PEEK becomes BODY, and a partial
// fetch carries only its origin (RFC 3501 section 7.4.2).
func (bs bodySectionFetch) responseName() string {
	name := bodyFetchResponseName(bs.itemName)
	if bs.partial {
		name += "<" + strconv.Itoa(bs.origin) + ">"
	}
	return name
}

func parseAllBodyFetches(rest string) []bodySectionFetch {
	var out []bodySectionFetch
	upper := strings.ToUpper(rest)
	for pos := 0; pos < len(rest); {
		tail := strings.ToUpper(rest[pos:])
		pick, kind := -1, bracketItem{}
		for _, k := range bracketItems {
			if at := strings.Index(tail, k.prefix); at >= 0 && (pick < 0 || pos+at < pick) {
				pick, kind = pos+at, k
			}
		}
		if pick < 0 {
			break
		}
		end := strings.IndexByte(rest[pick:], ']')
		if end < 0 {
			pos = pick + 1
			continue
		}
		item := rest[pick : pick+end+1]
		spec := strings.TrimSpace(item[len(kind.prefix) : len(item)-1])
		next, peek := pick+end+1, kind.peek
		var bs bodySectionFetch
		if kind.binary {
			// BINARY takes a part number only, no HEADER/TEXT/MIME (RFC 3516).
			if _, ok := parseSectionPath(spec); !ok {
				pos = next
				continue
			}
			bs = bodySectionFetch{itemName: item, section: spec, binary: true, sizeOnly: kind.size}
		} else if spec == "" {
			bs = bodySectionFetch{itemName: item, section: ""}
		} else if section, fields, ok := parseHeaderFieldsSection(spec); ok {
			bs = bodySectionFetch{itemName: item, section: section, hdrFields: fields}
		} else {
			bs = bodySectionFetch{itemName: item, section: spec}
		}
		bs.setsSeen = !peek
		if origin, count, n, ok := parsePartial(rest, next); ok && !bs.sizeOnly {
			bs.partial, bs.origin, bs.count = true, origin, count
			next += n
		}
		out = append(out, bs)
		pos = next
	}
	if strings.Contains(upper, "RFC822.HEADER") {
		out = append(out, bodySectionFetch{itemName: "RFC822.HEADER", section: "HEADER"})
	}
	if strings.Contains(upper, "RFC822.TEXT") {
		out = append(out, bodySectionFetch{itemName: "RFC822.TEXT", section: "TEXT", setsSeen: true})
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
		out = append(out, bodySectionFetch{itemName: "RFC822", section: "", setsSeen: true})
	}
	return out
}

// bracketItem is a FETCH item with a [section]: BODY, BINARY (RFC 3516), and their variants.
type bracketItem struct {
	prefix             string
	peek, binary, size bool
}

var bracketItems = []bracketItem{
	{prefix: "BODY.PEEK[", peek: true},
	{prefix: "BODY["},
	{prefix: "BINARY.PEEK[", peek: true, binary: true},
	{prefix: "BINARY.SIZE[", peek: true, binary: true, size: true},
	{prefix: "BINARY[", binary: true},
}

// parseHeaderFieldsSection parses "[path.]HEADER.FIELDS[.NOT] (f1 f2)" and returns the section
// without the field list (e.g. "1.HEADER.FIELDS.NOT") and the fields.
func parseHeaderFieldsSection(spec string) (section string, fields []string, ok bool) {
	spec = strings.TrimSpace(spec)
	upper := strings.ToUpper(spec)
	idx := strings.Index(upper, "HEADER.FIELDS")
	if idx < 0 {
		return "", nil, false
	}
	if _, ok := parseSectionPath(strings.TrimSuffix(upper[:idx], ".")); !ok {
		return "", nil, false
	}
	nameEnd := idx + len("HEADER.FIELDS")
	if strings.HasPrefix(upper[nameEnd:], ".NOT") {
		nameEnd += len(".NOT")
	}
	section = upper[:nameEnd]
	rest := strings.TrimSpace(spec[nameEnd:])
	if !strings.HasPrefix(rest, "(") || !strings.HasSuffix(rest, ")") {
		return "", nil, false
	}
	return section, strings.Fields(rest[1 : len(rest)-1]), true
}

// bodyFetchResponseName drops PEEK in FETCH responses: BODY.PEEK[...] is answered as BODY[...],
// BINARY.PEEK[...] as BINARY[...] (RFC 3501, RFC 3516).
func bodyFetchResponseName(itemName string) string {
	if i := strings.Index(strings.ToUpper(itemName), ".PEEK["); i >= 0 {
		return itemName[:i] + itemName[i+len(".PEEK"):]
	}
	return itemName
}

// mimeEntity is one MIME entity as raw slices of the message: header (with its blank line) and body.
type mimeEntity struct {
	header, body []byte
	inDigest     bool // child of multipart/digest: no Content-Type means message/rfc822 (RFC 2046)
}

func splitEntity(raw []byte) mimeEntity {
	// A part with no header fields starts with the blank line itself.
	for _, nl := range []string{"\r\n", "\n"} {
		if strings.HasPrefix(string(raw[:min(len(raw), 2)]), nl) {
			return mimeEntity{header: raw[:len(nl)], body: raw[len(nl):]}
		}
	}
	h, b := splitHeaderBody(raw)
	return mimeEntity{header: h, body: b}
}

// mediaType returns the entity's lower-case media type and parameters, with the RFC 2046 default.
func (e mimeEntity) mediaType() (string, map[string]string) {
	hdr, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(e.header))).ReadMIMEHeader()
	return entityMediaType(hdr.Get("Content-Type"), e.inDigest)
}

func entityMediaType(contentType string, inDigest bool) (string, map[string]string) {
	if strings.TrimSpace(contentType) == "" {
		if inDigest {
			return "message/rfc822", map[string]string{}
		}
		return "text/plain", map[string]string{}
	}
	mt, params := parseMediaType(contentType)
	return strings.ToLower(mt), params
}

// extractBodySection returns the bytes of BODY[section] (RFC 3501 6.4.5), exactly as stored.
func extractBodySection(raw []byte, section string, hdrFields []string) []byte {
	upper := strings.ToUpper(strings.TrimSpace(section))
	pathStr, text := upper, ""
	for _, suf := range []string{"HEADER.FIELDS.NOT", "HEADER.FIELDS", "HEADER", "TEXT", "MIME"} {
		if upper == suf || strings.HasSuffix(upper, "."+suf) {
			pathStr, text = strings.TrimSuffix(strings.TrimSuffix(upper, suf), "."), suf
			break
		}
	}
	path, ok := parseSectionPath(pathStr)
	if !ok {
		return []byte{}
	}
	if len(path) == 0 {
		if text == "" {
			return raw
		}
		return messageText(splitEntity(raw), text, hdrFields)
	}
	part, ok := findPart(raw, path)
	if !ok {
		return []byte{}
	}
	switch text {
	case "":
		return part.body
	case "MIME":
		return part.header
	}
	// HEADER/TEXT of a part refer to the message a message/rfc822 part encapsulates; other parts
	// are answered from their own header and body.
	if mt, _ := part.mediaType(); mt == "message/rfc822" {
		part = splitEntity(part.body)
	}
	return messageText(part, text, hdrFields)
}

func messageText(e mimeEntity, text string, fields []string) []byte {
	switch text {
	case "HEADER":
		return e.header
	case "TEXT":
		return e.body
	case "HEADER.FIELDS":
		return filterHeaderFields(e.header, fields, true)
	case "HEADER.FIELDS.NOT":
		return filterHeaderFields(e.header, fields, false)
	}
	return []byte{}
}

// findPart walks a part path: numbers index multipart children; a non-multipart message has a
// single part 1 (itself); a message/rfc822 part continues into the message it encapsulates.
func findPart(raw []byte, path []int) (mimeEntity, bool) {
	cur, isMessage := splitEntity(raw), true
	for i, n := range path {
		var part mimeEntity
		mt, params := cur.mediaType()
		switch {
		case strings.HasPrefix(mt, "multipart/"):
			children := splitMultipart(cur.body, params["boundary"])
			if n > len(children) {
				return mimeEntity{}, false
			}
			part = splitEntity(children[n-1])
			part.inDigest = mt == "multipart/digest"
		case isMessage && n == 1:
			part = cur
		default:
			return mimeEntity{}, false
		}
		if i == len(path)-1 {
			return part, true
		}
		if pt, _ := part.mediaType(); pt == "message/rfc822" {
			cur, isMessage = splitEntity(part.body), true
		} else {
			cur, isMessage = part, false
		}
	}
	return mimeEntity{}, false
}

// splitMultipart returns the raw body parts between "--boundary" delimiter lines; the line break
// before each delimiter belongs to the delimiter (RFC 2046), the preamble and epilogue are dropped.
func splitMultipart(body []byte, boundary string) [][]byte {
	if boundary == "" {
		return nil
	}
	delim := []byte("--" + boundary)
	var parts [][]byte
	start := -1
	for pos := 0; ; {
		i := indexLineStart(body, pos, delim)
		if i < 0 {
			return parts
		}
		if start >= 0 {
			end := i
			if end >= start+2 && body[end-2] == '\r' && body[end-1] == '\n' {
				end -= 2
			} else if end >= start+1 && body[end-1] == '\n' {
				end--
			}
			parts = append(parts, body[start:max(end, start)])
		}
		after := i + len(delim)
		if bytes.HasPrefix(body[after:], []byte("--")) {
			return parts
		}
		nl := bytes.IndexByte(body[after:], '\n')
		if nl < 0 {
			return parts
		}
		start = after + nl + 1
		pos = start
	}
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

// parseSectionPath parses "1.2.3" (empty for none); every number must be positive.
func parseSectionPath(path string) ([]int, bool) {
	if path == "" {
		return nil, true
	}
	var out []int
	for _, p := range strings.Split(path, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
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
