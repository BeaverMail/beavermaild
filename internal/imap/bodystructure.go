// IMAP BODYSTRUCTURE and INTERNALDATE formatting from RFC 822/MIME bytes.
package imap

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

// formatBodyStructure returns the RFC 3501 BODYSTRUCTURE parenthesized list for raw.
func formatBodyStructure(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return `("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0)`
	}
	body, _ := io.ReadAll(msg.Body)
	ct := msg.Header.Get("Content-Type")
	mediaType, params := parseMediaType(ct)
	return formatMIMEPart(mediaType, params, msg.Header, body)
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

func formatMIMEPart(mediaType string, params map[string]string, hdr map[string][]string, body []byte) string {
	major, subtype, _ := strings.Cut(strings.ToLower(mediaType), "/")
	if major == "multipart" {
		return formatMultipart(subtype, params, body)
	}
	return formatLeafPart(major, subtype, params, hdr, body)
}

func formatMultipart(subtype string, params map[string]string, body []byte) string {
	boundary := params["boundary"]
	if boundary == "" {
		return `(("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0) "` + strings.ToUpper(subtype) + `" NIL)`
	}
	mr := multipart.NewReader(bytes.NewReader(body), boundary)
	var parts []string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		partBody, _ := io.ReadAll(p)
		mt, pr := parseMediaType(p.Header.Get("Content-Type"))
		parts = append(parts, formatMIMEPart(mt, pr, p.Header, partBody))
	}
	if len(parts) == 0 {
		parts = append(parts, `("TEXT" "PLAIN" NIL NIL NIL "7BIT" 0 0)`)
	}
	sub := strings.ToUpper(subtype)
	if sub == "" {
		sub = "MIXED"
	}
	// RFC 3501 body-type-mpart = 1*body SP media-subtype: child parts are written back to back.
	return "(" + strings.Join(parts, "") + ` "` + sub + `" ` + formatIMAPParams(params) + ")"
}

func formatLeafPart(major, subtype string, params map[string]string, hdr map[string][]string, body []byte) string {
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
	if major == "TEXT" {
		lines := countLines(body)
		return `("` + major + `" "` + subtype + `" ` + paramsStr + ` ` + id + ` ` + desc + ` "` + enc + `" ` + strconv.Itoa(size) + ` ` + strconv.Itoa(lines) + `)`
	}
	// body-type-msg: a message/rfc822 part also carries the inner ENVELOPE, BODYSTRUCTURE and line count.
	if major == "MESSAGE" && subtype == "RFC822" {
		return `("` + major + `" "` + subtype + `" ` + paramsStr + ` ` + id + ` ` + desc + ` "` + enc + `" ` + strconv.Itoa(size) +
			` ` + formatEnvelope(body) + ` ` + formatBodyStructure(body) + ` ` + strconv.Itoa(countLines(body)) + `)`
	}
	return `("` + major + `" "` + subtype + `" ` + paramsStr + ` ` + id + ` ` + desc + ` "` + enc + `" ` + strconv.Itoa(size) + `)`
}

func formatIMAPParams(params map[string]string) string {
	if len(params) == 0 {
		return "NIL"
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		if strings.EqualFold(k, "boundary") {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return "NIL"
	}
	// ponytail: stable order not required by RFC; sort for tests
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if strings.ToUpper(keys[i]) > strings.ToUpper(keys[j]) {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	var b strings.Builder
	b.WriteByte('(')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(quoteIMAPString(strings.ToUpper(k)))
		b.WriteByte(' ')
		b.WriteString(quoteIMAPString(params[k]))
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
	default:
		return "7BIT"
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
