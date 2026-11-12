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
	"unicode/utf8"
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

// searchChunk is how much of a message TEXT and BODY lowercase and scan at a time.
var searchChunk = 64 << 10

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
// chunk by chunk. RFC 3501 6.4.4 compares decoded text: the raw bytes are scanned first, then,
// if they did not match, the text of base64 and quoted-printable parts and, for TEXT, the RFC 2047
// words of the header.
func openContains(load RawLoader, m Message, needle string, body bool) bool {
	r, err := load(m)
	if err != nil {
		return false
	}
	br := bufio.NewReader(r)
	if body {
		readHeader(br, 0)
	}
	found := readerContains(br, needle)
	r.Close()
	if found {
		return true
	}
	if r, err = load(m); err != nil {
		return false
	}
	defer r.Close()
	tp := textproto.NewReader(bufio.NewReader(r))
	hdr, err := tp.ReadMIMEHeader()
	if err != nil && len(hdr) == 0 {
		return false
	}
	if !body {
		for _, values := range hdr {
			for _, v := range values {
				if strings.Contains(v, "=?") && headerContains(v, needle) {
					return true
				}
			}
		}
	}
	return decodedPartsContain(hdr, tp.R, needle, 0)
}

// maxSearchMIMEDepth bounds the MIME levels the decoded pass enters, like the IMAP walks.
const maxSearchMIMEDepth = 100

// decodedPartsContain walks the entity with header hdr and body r as a stream and reports whether
// the decoded text of a base64 or quoted-printable leaf holds needle. Other leaves were covered by
// the raw pass. shortcut: decoded bytes are matched as they are, without charset conversion, so a
// UTF-8 needle finds UTF-8 and US-ASCII parts only; convert when a charset library is allowed.
func decodedPartsContain(hdr textproto.MIMEHeader, r io.Reader, needle string, depth int) bool {
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
			if decodedPartsContain(p.Header, p, needle, depth+1) {
				return true
			}
		}
	case mt == "message/rfc822":
		tp := textproto.NewReader(bufio.NewReader(r))
		inner, err := tp.ReadMIMEHeader()
		if err != nil && len(inner) == 0 {
			return false
		}
		return decodedPartsContain(inner, tp.R, needle, depth+1)
	}
	switch strings.ToLower(strings.TrimSpace(hdr.Get("Content-Transfer-Encoding"))) {
	case "base64":
		return readerContains(base64.NewDecoder(base64.StdEncoding, r), needle) // skips CR/LF
	case "quoted-printable":
		return readerContains(quotedprintable.NewReader(r), needle)
	}
	return false
}

// readerContains is rawContains over a stream. Chunks are cut on rune starts, so lowercasing them
// one by one gives the bytes lowercasing the whole stream would, and each chunk carries the tail
// of the previous one, long enough for any match crossing the cut.
func readerContains(r io.Reader, needle string) bool {
	n := bytes.ToLower([]byte(needle))
	// A lowered byte comes from at most utf8.UTFMax raw bytes; the extra rune covers the cut.
	keep := utf8.UTFMax*len(n) + utf8.UTFMax
	// The carried tail is at most keep bytes plus a rune held back at the cut: searchChunk new
	// bytes always fit after it.
	buf := make([]byte, keep+utf8.UTFMax+searchChunk)
	have := 0
	for {
		k, err := io.ReadFull(r, buf[have:])
		have += k
		end := have
		if err == nil {
			end = completeRunes(buf[:have])
		}
		if bytes.Contains(bytes.ToLower(buf[:end]), n) {
			return true
		}
		if err != nil {
			return false
		}
		start := max(0, end-keep)
		for start < end && !utf8.RuneStart(buf[start]) {
			start++
		}
		have = copy(buf, buf[start:have])
	}
}

// completeRunes returns the length of b without a rune cut off at its end.
func completeRunes(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return i
			}
			break
		}
	}
	return len(b)
}
