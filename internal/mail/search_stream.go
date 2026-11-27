package mail

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/htmlindex"
)

// RawLoader opens the RFC 5322 bytes of a message for SEARCH, SORT and THREAD; the caller closes
// it. Criteria read only what they need (the header block, or the text in chunks), so a large
// message is never held in memory.
type RawLoader func(Message) (io.ReadCloser, error)

// BytesLoader adapts a loader of in-memory messages.
func BytesLoader(load func(Message) ([]byte, error)) RawLoader {
	return func(m Message) (io.ReadCloser, error) {
		raw, err := load(m)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
}

// maxSearchHeader caps the header block read for header criteria, SORT and THREAD: fields past
// it are not seen, so a message with a huge header cannot be pulled into memory.
const maxSearchHeader = 256 << 10

// loadHeader returns m's header block, ending with its empty line, capped at maxSearchHeader.
func loadHeader(load RawLoader, m Message) ([]byte, bool) {
	r, err := load(m)
	if err != nil {
		return nil, false
	}
	defer r.Close()
	return readHeader(bufio.NewReader(r), maxSearchHeader), true
}

// readHeader consumes br through the empty line that ends the header block and returns at most
// limit bytes of it; a truncated block is cut at a line end and closed with an empty line.
func readHeader(br *bufio.Reader, limit int) []byte {
	var h []byte
	truncated, lineStart := false, true
	for {
		frag, err := br.ReadSlice('\n')
		blank := lineStart && (string(frag) == "\r\n" || string(frag) == "\n")
		if !truncated && len(h)+len(frag) <= limit {
			h = append(h, frag...)
		} else if !truncated {
			truncated = true
			h = append(h[:bytes.LastIndexByte(h, '\n')+1], "\r\n"...)
		}
		if blank || err != nil && err != bufio.ErrBufferFull {
			return h
		}
		lineStart = err == nil
	}
}

// openContains reports whether m contains needle (only its body when body is set), reading it
// once, as a stream. Text is compared as RFC 5255 4.6 says: transfer encodings and RFC 2047 words
// removed, charsets converted to UTF-8, then i;unicode-casemap (i;octet where that fails). TEXT
// also covers the header fields of the message and of its parts.
func openContains(load RawLoader, m Message, needle needle, body bool) bool {
	r, err := load(m)
	if err != nil {
		return false
	}
	defer r.Close()
	br := bufio.NewReader(r)
	hdr := parseHeaderBlock(readHeader(br, maxSearchHeader))
	return entityContains(hdr, br, needle, !body, 0)
}

// parseHeaderBlock parses a header block read by readHeader.
func parseHeaderBlock(raw []byte) textproto.MIMEHeader {
	hdr, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(raw))).ReadMIMEHeader()
	return hdr
}

// fieldsContain reports whether a header field, as "Name: value" with encoded words decoded,
// holds needle.
func fieldsContain(hdr textproto.MIMEHeader, needle needle) bool {
	for name, values := range hdr {
		for _, v := range values {
			if headerContains(name+": "+v, needle) {
				return true
			}
		}
	}
	return false
}

// maxSearchMIMEDepth bounds the MIME levels the walk enters, like the IMAP walks.
const maxSearchMIMEDepth = 100

// entityContains walks the entity with header hdr and body r as a stream and reports whether the
// decoded text of a leaf holds needle; with headers set, its header fields and those of every
// part and attached message count too.
func entityContains(hdr textproto.MIMEHeader, r io.Reader, needle needle, headers bool, depth int) bool {
	if headers && fieldsContain(hdr, needle) {
		return true
	}
	if depth >= maxSearchMIMEDepth {
		return false
	}
	mt, params, _ := mime.ParseMediaType(hdr.Get("Content-Type"))
	switch {
	case strings.HasPrefix(mt, "multipart/") && params["boundary"] != "":
		mr := multipart.NewReader(r, params["boundary"])
		for {
			p, err := mr.NextRawPart() // raw: the walk decodes, once
			if err != nil {
				return false
			}
			if entityContains(p.Header, p, needle, headers, depth+1) {
				return true
			}
		}
	case mt == "message/rfc822":
		br := bufio.NewReader(r)
		inner := parseHeaderBlock(readHeader(br, maxSearchHeader))
		return entityContains(inner, br, needle, headers, depth+1)
	}
	switch strings.ToLower(strings.TrimSpace(hdr.Get("Content-Transfer-Encoding"))) {
	case "base64":
		r = base64.NewDecoder(base64.RawStdEncoding, base64Alphabet{r})
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	}
	text, convertible := charsetReader(r, params["charset"])
	found, _ := readerContains(text, needle, convertible)
	return found
}

// charsetReader converts a part's text to UTF-8 (RFC 5255 4.6 b); UTF-8 and US-ASCII (also when
// no charset is named) pass as they are. convertible is false for a charset no decoder knows: the
// text is then compared as octets (4.6 c).
func charsetReader(r io.Reader, charset string) (_ io.Reader, convertible bool) {
	switch cs := strings.ToLower(strings.TrimSpace(charset)); cs {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return r, true
	default:
		e, err := htmlindex.Get(cs)
		if err != nil || e == encoding.Replacement {
			return r, false
		}
		return e.NewDecoder().Reader(r), true
	}
}

// base64Alphabet passes only the base64 alphabet: RFC 2045 6.8 says every other character, padding
// included here, is ignored. Go's decoder stopped at the first one and the rest of the part was
// never searched.
type base64Alphabet struct{ r io.Reader }

func (a base64Alphabet) Read(p []byte) (int, error) {
	for {
		n, err := a.r.Read(p)
		k := 0
		for _, c := range p[:n] {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
				p[k] = c
				k++
			}
		}
		if k > 0 || err != nil {
			return k, err
		}
	}
}
