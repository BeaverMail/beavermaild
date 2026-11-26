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

// binarySection returns BINARY[section] of raw; see binaryParts.section.
func binarySection(raw []byte, section string) ([]byte, error) {
	return (&binaryParts{raw: raw}).section(section)
}

// binaryParts answers the BINARY sections of one message. The tree is parsed once and each leaf
// decoded once, however many times a FETCH names it: leaves do not overlap, so all the decoded
// data of one response stays under the message size (a FETCH repeating BINARY[1] used to decode
// it anew each time and hold every copy, as in CVE-2026-107581).
type binaryParts struct {
	raw     []byte
	root    *mimetree.Part
	decoded map[*mimetree.Part][]byte
}

// section returns BINARY[section]: the whole message as stored for an empty section, else the
// part's body decoded from base64 or quoted-printable. Multiparts and message/rfc822 parts are
// returned as stored, never decoded: BINARY is for leaf parts (RFC 9051 6.4.5) and a composite
// may not be encoded (RFC 2045 6.4); decoding one would also overlap its decoded leaves. A
// missing part is empty, as for BODY.
func (b *binaryParts) section(section string) ([]byte, error) {
	path, ok := parseSectionPath(section)
	if !ok {
		return []byte{}, nil
	}
	if len(path) == 0 {
		return b.raw, nil
	}
	if b.root == nil {
		b.root, b.decoded = mimetree.Parse(b.raw), map[*mimetree.Part][]byte{}
	}
	part, ok := findPart(b.root, path)
	if !ok {
		return []byte{}, nil
	}
	if len(part.Children) > 0 || part.IsMultipart() || part.Type == "message/rfc822" {
		return part.Body, nil
	}
	if out, ok := b.decoded[part]; ok {
		return out, nil
	}
	out, ok := mimetree.Decode(part.MIME.Get("Content-Transfer-Encoding"), part.Body)
	if !ok {
		return nil, errUnknownCTE
	}
	b.decoded[part] = out
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
