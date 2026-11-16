// IMAP BINARY (RFC 3516): FETCH BINARY[part] decodes the part's Content-Transfer-Encoding.
package imap

import (
	"bytes"
	"encoding/base64"
	"errors"

	"github.com/BeaverMail/beavermaild/mimetree"
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
	part, ok := findPart(mimetree.Parse(raw), path)
	if !ok {
		return []byte{}, nil
	}
	out, ok := mimetree.Decode(part.MIME.Get("Content-Transfer-Encoding"), part.Body)
	if !ok {
		return nil, errUnknownCTE
	}
	return out, nil
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
	var walk func(p *mimetree.Part)
	walk = func(p *mimetree.Part) {
		if len(p.Children) > 0 {
			for _, c := range p.Children {
				walk(c)
			}
			return
		}
		if bytes.IndexByte(p.Body, 0) < 0 || len(p.Header) == 0 {
			return
		}
		hdr := filterHeaderFields(p.Header, []string{"Content-Transfer-Encoding"}, false)
		repl := append(hdr[:len(hdr)-2:len(hdr)-2], "Content-Transfer-Encoding: base64\r\n\r\n"...)
		enc := base64.StdEncoding.EncodeToString(p.Body)
		for len(enc) > 76 {
			repl = append(append(repl, enc[:76]...), '\r', '\n')
			enc = enc[76:]
		}
		repl = append(append(repl, enc...), '\r', '\n')
		start := offset(p.Header)
		edits = append(edits, edit{start, start + len(p.Header) + len(p.Body), repl})
	}
	walk(mimetree.Parse(raw))
	var out []byte
	last := 0
	for _, ed := range edits {
		out = append(append(out, raw[last:ed.start]...), ed.repl...)
		last = ed.end
	}
	return append(out, raw[last:]...)
}
