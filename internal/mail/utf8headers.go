package mail

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
)

// ErrNeedsSMTPUTF8 is returned by the SMTP client, before MAIL, when the envelope or the header
// fields need SMTPUTF8 and the next hop does not offer it: RFC 6531 3.2 forbids sending them. The
// delivery fails for good with status 5.6.7, as in Postfix.
var ErrNeedsSMTPUTF8 = errors.New("mail: next hop does not offer SMTPUTF8, message has UTF-8 addresses or header fields")

const maxUTF8HeaderDepth = 100

// Has8BitHeaders reports whether raw has a header field with octets outside US-ASCII at any level
// of its MIME structure (RFC 6531 3.2, RFC 6532): the message then needs SMTPUTF8. Body octets do
// not count, they only need 8BITMIME.
func Has8BitHeaders(raw []byte) bool {
	end := bytesIndexHeadersEnd(raw) // stored messages may use bare LF
	if end < 0 {
		end = len(raw)
	}
	if Has8Bit(raw[:end]) {
		return true
	}
	tp := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw)))
	hdr, err := tp.ReadMIMEHeader()
	if err != nil && len(hdr) == 0 {
		return false
	}
	return partHeaders8Bit(hdr, tp.R, 0)
}

// partHeaders8Bit walks the body r of an entity with header hdr and reports an 8-bit header field
// in any nested part or message.
func partHeaders8Bit(hdr textproto.MIMEHeader, r io.Reader, depth int) bool {
	if depth >= maxUTF8HeaderDepth {
		return false
	}
	mt, params, _ := mime.ParseMediaType(hdr.Get("Content-Type"))
	switch {
	case strings.HasPrefix(mt, "multipart/") && params["boundary"] != "":
		mr := multipart.NewReader(r, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return false
			}
			if mimeHeader8Bit(p.Header) || partHeaders8Bit(p.Header, p, depth+1) {
				return true
			}
		}
	case mt == "message/rfc822" || mt == "message/global":
		tp := textproto.NewReader(bufio.NewReader(r))
		inner, err := tp.ReadMIMEHeader()
		if mimeHeader8Bit(inner) {
			return true
		}
		if err != nil && len(inner) == 0 {
			return false
		}
		return partHeaders8Bit(inner, tp.R, depth+1)
	}
	return false
}

func mimeHeader8Bit(h textproto.MIMEHeader) bool {
	for k, vs := range h {
		if Has8Bit([]byte(k)) {
			return true
		}
		for _, v := range vs {
			if Has8Bit([]byte(v)) {
				return true
			}
		}
	}
	return false
}
