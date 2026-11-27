package mail

import "io"

// CRLF returns b in the RFC 5322 wire form for sending: bare CR handled as in BareCR, then every
// bare LF turned into CRLF. Messages received with DATA are stored with LF line endings; anything
// signed or sent must be CRLF, or a BDAT peer such as Exim folds the bare LFs into the previous
// header. A bare CR must never leave (RFC 5321 2.3.8): receivers that take it as a line end can be
// made to see an early end of data (SMTP smuggling, CVE-2023-51764 class).
func CRLF(b []byte) []byte {
	return wireForm(BareCR(b))
}

// BareCR returns b with no CR left except before LF, as Exim does (receive.c): in the header
// block a bare CR becomes LF SP, a folded continuation, so it can neither end the header nor start
// a forged field; in the body it becomes LF, a line end. Turning it into CRLF everywhere made
// "\r\r\n" an empty line, which inside the header ended it early.
func BareCR(b []byte) []byte {
	bare := false
	for i, c := range b {
		if c == '\r' && (i+1 == len(b) || b[i+1] != '\n') {
			bare = true
			break
		}
	}
	if !bare {
		return b
	}
	out := make([]byte, 0, len(b)+len(b)/64+1)
	inHeader, lineStart := true, true
	for i, c := range b {
		if c == '\r' && (i+1 == len(b) || b[i+1] != '\n') {
			if inHeader {
				out = append(out, '\n', ' ')
				lineStart = false
				continue
			}
			c = '\n'
		}
		if c == '\n' {
			if inHeader && lineStart {
				inHeader = false // the empty line ending the header block
			}
			lineStart = true
		} else if c != '\r' {
			lineStart = false
		}
		out = append(out, c)
	}
	return out
}

// BareCRWriter applies BareCR to a stream: what it writes to w is BareCR of everything written to
// it, whatever the chunks. Close flushes a CR held back at the end.
type BareCRWriter struct {
	w                   io.Writer
	inHeader, lineStart bool
	cr                  bool // a CR not yet known to be bare
	crlf                bool // also every bare LF becomes CRLF: the output is CRLF of the input
	last                byte // last byte written out
	out                 []byte
}

// NewBareCRWriter returns a BareCRWriter writing to w.
func NewBareCRWriter(w io.Writer) *BareCRWriter {
	return &BareCRWriter{w: w, inHeader: true, lineStart: true}
}

// NewCRLFWriter returns a writer applying CRLF to a stream: what it writes to w is CRLF of everything
// written to it. Close flushes a CR held back at the end.
func NewCRLFWriter(w io.Writer) *BareCRWriter {
	return &BareCRWriter{w: w, inHeader: true, lineStart: true, crlf: true}
}

func (b *BareCRWriter) Write(p []byte) (int, error) {
	b.out = b.out[:0]
	for _, c := range p {
		if b.cr {
			b.cr = false
			if c == '\n' {
				b.put('\r') // CRLF: the CR stays
			} else {
				b.bare()
			}
		}
		if c == '\r' {
			b.cr = true
			continue
		}
		b.put(c)
	}
	if _, err := b.w.Write(b.out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close ends the stream: a CR at the very end is bare.
func (b *BareCRWriter) Close() error {
	if !b.cr {
		return nil
	}
	b.cr = false
	b.out = b.out[:0]
	b.bare()
	_, err := b.w.Write(b.out)
	return err
}

// bare writes a bare CR as BareCR does: LF SP in the header, LF in the body.
func (b *BareCRWriter) bare() {
	if b.inHeader {
		if b.crlf {
			b.out = append(b.out, '\r')
		}
		b.out = append(b.out, '\n', ' ')
		b.lineStart, b.last = false, ' '
		return
	}
	b.put('\n')
}

func (b *BareCRWriter) put(c byte) {
	if c == '\n' {
		if b.inHeader && b.lineStart {
			b.inHeader = false
		}
		b.lineStart = true
	} else if c != '\r' {
		b.lineStart = false
	}
	if b.crlf && c == '\n' && b.last != '\r' {
		b.out = append(b.out, '\r')
	}
	b.out = append(b.out, c)
	b.last = c
}
