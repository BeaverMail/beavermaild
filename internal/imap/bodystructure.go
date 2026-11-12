// IMAP BODYSTRUCTURE and INTERNALDATE formatting from RFC 822/MIME bytes.
package imap

import (
	"bufio"
	"bytes"
	"maps"
	"mime"
	"net/mail"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"
)

// formatBodyStructure returns the RFC 3501 BODYSTRUCTURE parenthesized list for raw.
func formatBodyStructure(raw []byte) string { return formatBodyPart(raw, true, 0) }

// formatBody is the non-extensible BODY form: BODYSTRUCTURE without extension data.
func formatBody(raw []byte) string { return formatBodyPart(raw, false, 0) }

// formatBodyPart describes the message raw, depth levels of nesting down. Header and body are
// slices of raw, never copies: a message/rfc822 chain would otherwise hold one copy per level.
func formatBodyPart(raw []byte, ext bool, depth int) string {
	e := splitEntity(raw)
	hdr, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(e.header))).ReadMIMEHeader()
	mediaType, params := parseMediaType(hdr.Get("Content-Type"))
	return formatMIMEPart(mediaType, params, hdr, e.body, ext, depth)
}

func mimeGet(hdr map[string][]string, key string) string {
	if hdr == nil {
		return ""
	}
	return mail.Header(hdr).Get(key)
}

// formatInternalDate formats ReceivedAt as an IMAP INTERNALDATE quoted string (UTC).
func formatInternalDate(receivedAt int64) string {
	if receivedAt <= 0 {
		return `"01-Jan-1970 00:00:00 +0000"`
	}
	t := time.Unix(receivedAt, 0).UTC()
	return `"` + t.Format("02-Jan-2006 15:04:05 -0700") + `"`
}

func parseMediaType(ct string) (mediaType string, params map[string]string) {
	ct = strings.TrimSpace(ct)
	if ct == "" {
		return "text/plain", nil
	}
	mt, p, err := mime.ParseMediaType(ct)
	if err != nil {
		return "text/plain", nil
	}
	return mt, p
}

func formatMIMEPart(mediaType string, params map[string]string, hdr map[string][]string, body []byte, ext bool, depth int) string {
	major, subtype, _ := strings.Cut(strings.ToLower(mediaType), "/")
	if depth >= maxMIMEDepth && opaqueTooDeep(major+"/"+subtype) {
		major, subtype, params = "application", "octet-stream", nil
	}
	if major == "multipart" {
		return formatMultipart(subtype, params, hdr, body, ext, depth)
	}
	return formatLeafPart(major, subtype, params, hdr, body, ext, depth)
}

func formatMultipart(subtype string, params map[string]string, hdr map[string][]string, body []byte, ext bool, depth int) string {
	boundary := params["boundary"]
	if boundary == "" {
		return `(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0) "` + strings.ToUpper(subtype) + `" NIL)`
	}
	// Same raw split as BODY[n]: sizes and encodings match the bytes FETCH returns.
	var parts []string
	for _, child := range splitMultipart(body, boundary) {
		e := splitEntity(child)
		hdr, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(e.header))).ReadMIMEHeader()
		mt, pr := entityMediaType(hdr.Get("Content-Type"), strings.EqualFold(subtype, "digest"))
		parts = append(parts, formatMIMEPart(mt, pr, hdr, e.body, ext, depth+1))
	}
	if len(parts) == 0 {
		parts = append(parts, `("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0)`)
	}
	sub := strings.ToUpper(subtype)
	if sub == "" {
		sub = "MIXED"
	}
	// RFC 3501 body-type-mpart = 1*body SP media-subtype: child parts are written back to back.
	if !ext {
		return "(" + strings.Join(parts, "") + ` "` + sub + `")`
	}
	return "(" + strings.Join(parts, "") + ` "` + sub + `" ` + formatIMAPParams(params) + " " + bodyExt(hdr) + ")"
}

// bodyExt is the extension data shared by every part type (RFC 3501 7.4.2): disposition with its
// parameters, language and location.
func bodyExt(hdr map[string][]string) string {
	disp := "NIL"
	if v := mimeGet(hdr, "Content-Disposition"); v != "" {
		if d, p, err := mime.ParseMediaType(v); err == nil {
			disp = "(" + quoteHeaderString(strings.ToUpper(d)) + " " + formatIMAPParams(p) + ")"
		}
	}
	lang := "NIL"
	var tags []string
	for _, t := range strings.Split(mimeGet(hdr, "Content-Language"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, quoteHeaderString(t))
		}
	}
	switch len(tags) {
	case 0:
	case 1:
		lang = tags[0]
	default:
		lang = "(" + strings.Join(tags, " ") + ")"
	}
	return disp + " " + lang + " " + nstring(mimeGet(hdr, "Content-Location"))
}

func formatLeafPart(major, subtype string, params map[string]string, hdr map[string][]string, body []byte, ext bool, depth int) string {
	if major == "" {
		major = "text"
	}
	if subtype == "" {
		subtype = "plain"
	}
	major = strings.ToUpper(major)
	subtype = strings.ToUpper(subtype)
	enc := mapEncoding(mimeGet(hdr, "Content-Transfer-Encoding"))
	id := nstring(mimeGet(hdr, "Content-Id"))
	desc := nstring(mimeGet(hdr, "Content-Description"))
	size := len(body)
	paramsStr := formatIMAPParams(params)
	tail := ")"
	if ext { // body-ext-1part
		tail = " " + nstring(mimeGet(hdr, "Content-MD5")) + " " + bodyExt(hdr) + ")"
	}
	if major == "TEXT" {
		lines := countLines(body)
		return `("` + major + `" "` + subtype + `" ` + paramsStr + ` ` + id + ` ` + desc + ` "` + enc + `" ` + strconv.Itoa(size) + ` ` + strconv.Itoa(lines) + tail
	}
	// body-type-msg: a message/rfc822 part also carries the inner ENVELOPE, BODYSTRUCTURE and line count.
	if major == "MESSAGE" && subtype == "RFC822" {
		return `("` + major + `" "` + subtype + `" ` + paramsStr + ` ` + id + ` ` + desc + ` "` + enc + `" ` + strconv.Itoa(size) +
			` ` + formatEnvelope(body) + ` ` + formatBodyPart(body, ext, depth+1) + ` ` + strconv.Itoa(countLines(body)) + tail
	}
	return `("` + major + `" "` + subtype + `" ` + paramsStr + ` ` + id + ` ` + desc + ` "` + enc + `" ` + strconv.Itoa(size) + tail
}

func formatIMAPParams(params map[string]string) string {
	if len(params) == 0 {
		return "NIL"
	}
	// mime.ParseMediaType returns lower-case attribute names; a stable order keeps output and tests
	// deterministic. Sorted in O(n log n): a message may carry any number of parameters.
	keys := slices.Sorted(maps.Keys(params))
	var b strings.Builder
	b.WriteByte('(')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(quoteHeaderString(strings.ToUpper(k)))
		b.WriteByte(' ')
		b.WriteString(quoteHeaderString(params[k]))
	}
	b.WriteByte(')')
	return b.String()
}

func mapEncoding(cte string) string {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return "BASE64"
	case "quoted-printable":
		return "QUOTED-PRINTABLE"
	case "8bit", "8-bit":
		return "8BIT"
	case "binary":
		return "BINARY"
	case "", "7bit", "7-bit":
		return "7BIT"
	default: // body-fld-enc is any string: an unknown encoding is reported as it is
		return strings.ToUpper(strings.TrimSpace(cte))
	}
}

func countLines(body []byte) int {
	if len(body) == 0 {
		return 0
	}
	n := bytes.Count(body, []byte("\n"))
	if body[len(body)-1] != '\n' {
		n++
	}
	return n
}
