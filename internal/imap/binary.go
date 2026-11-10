// IMAP BINARY (RFC 3516): FETCH BINARY[part] decodes the part's Content-Transfer-Encoding.
package imap

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime/quotedprintable"
	"net/textproto"
	"strings"
)

// errUnknownCTE answers a BINARY fetch of a part whose transfer encoding cannot be decoded.
var errUnknownCTE = errors.New("imap: unknown content-transfer-encoding")

// binarySection returns BINARY[section]: the whole message as stored for an empty section, else
// the part's body decoded from base64 or quoted-printable. Identity encodings, multiparts and
// message/rfc822 parts are returned as they are; a missing part is empty, as for BODY.
func binarySection(raw []byte, section string) ([]byte, error) {
	path, ok := parseSectionPath(section)
	if !ok {
		return []byte{}, nil
	}
	if len(path) == 0 {
		return raw, nil
	}
	part, ok := findPart(raw, path)
	if !ok {
		return []byte{}, nil
	}
	hdr, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(part.header))).ReadMIMEHeader()
	switch strings.ToLower(strings.TrimSpace(hdr.Get("Content-Transfer-Encoding"))) {
	case "", "7bit", "8bit", "binary":
		return part.body, nil
	case "base64":
		// Keep only the alphabet (padding included goes too), as lenient readers do; a lone
		// trailing character holds no full byte.
		clean := bytes.Map(func(r rune) rune {
			if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '/' {
				return r
			}
			return -1
		}, part.body)
		if len(clean)%4 == 1 {
			clean = clean[:len(clean)-1]
		}
		out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
		n, _ := base64.RawStdEncoding.Decode(out, clean)
		return out[:n], nil
	case "quoted-printable":
		out, _ := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(part.body)))
		return out, nil
	default:
		return nil, errUnknownCTE
	}
}

// base64NULParts re-encodes as base64 every leaf part whose body holds NUL, which no IMAP4rev1
// literal can carry: BODY[...] must stay sendable and match BODYSTRUCTURE, and BINARY[...] decodes
// it back without loss (RFC 3516 4.4, 6). Other bytes are kept as they are.
func base64NULParts(raw []byte) []byte {
	if bytes.IndexByte(raw, 0) < 0 {
		return raw
	}
	type edit struct {
		start, end int
		repl       []byte
	}
	var edits []edit
	// Every entity is a reslice of raw, so its offset is the capacity it lost.
	offset := func(sub []byte) int { return cap(raw) - cap(sub) }
	var walk func(e mimeEntity)
	walk = func(e mimeEntity) {
		mt, params := e.mediaType()
		switch {
		case strings.HasPrefix(mt, "multipart/"):
			for _, child := range splitMultipart(e.body, params["boundary"]) {
				ce := splitEntity(child)
				ce.inDigest = mt == "multipart/digest"
				walk(ce)
			}
		case mt == "message/rfc822":
			walk(splitEntity(e.body))
		case bytes.IndexByte(e.body, 0) >= 0 && len(e.header) > 0:
			hdr := filterHeaderFields(e.header, []string{"Content-Transfer-Encoding"}, false)
			repl := append(hdr[:len(hdr)-2:len(hdr)-2], "Content-Transfer-Encoding: base64\r\n\r\n"...)
			enc := base64.StdEncoding.EncodeToString(e.body)
			for len(enc) > 76 {
				repl = append(append(repl, enc[:76]...), '\r', '\n')
				enc = enc[76:]
			}
			repl = append(append(repl, enc...), '\r', '\n')
			start := offset(e.header)
			edits = append(edits, edit{start, start + len(e.header) + len(e.body), repl})
		}
	}
	walk(splitEntity(raw))
	var out []byte
	last := 0
	for _, ed := range edits {
		out = append(append(out, raw[last:ed.start]...), ed.repl...)
		last = ed.end
	}
	return append(out, raw[last:]...)
}
