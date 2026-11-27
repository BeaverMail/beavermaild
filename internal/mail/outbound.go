// Outbound messages streamed from the blob store to the next hop, never held whole in memory.
package mail

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// maxOutboundHeader bounds the header block an Outbound keeps (for DKIM h= and DSNs); inbound
// SMTP refuses larger ones already.
const maxOutboundHeader = 1 << 20

// MessageSigner hashes a message written to it in wire form; after Close, Signature is the
// signature header field to prepend, CRLF included. An alias, so dkimout implements
// OutboundSigner without importing this package.
type MessageSigner = interface {
	io.WriteCloser
	Signature() string
}

// Outbound is a message ready to send: its wire form (CRLF, see CRLF), with an optional signature
// field in front, read from its source each time it is written.
type Outbound struct {
	Size            int64 // octets on the wire, signature included
	EightBit        bool  // an octet outside US-ASCII anywhere (needs 8BITMIME)
	EightBitHeaders bool  // one in a header field at any MIME level (needs SMTPUTF8, Has8BitHeaders)
	MaxLine         int   // longest line, CR LF excluded (SMTP allows MaxLineOctets)

	prefix []byte // signature field, written before the message
	header []byte // wire-form header block, at most maxOutboundHeader octets
	open   func() (io.ReadCloser, error)
}

// OutboundBytes wraps a message held in memory (notifications, tests, the CLI).
func OutboundBytes(raw []byte) *Outbound {
	wire := CRLF(raw)
	o := &Outbound{
		Size:     int64(len(wire)),
		EightBit: Has8Bit(wire),
		MaxLine:  longestLine(wire),
		header:   extractHeaders(wire),
		open:     func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(wire)), nil },
	}
	o.EightBitHeaders = o.EightBit && Has8BitHeaders(wire)
	return o
}

// OpenOutbound prepares a queued message for sending in one pass over its blob: wire size, 8-bit
// flags and, when signer is not nil, the signature of signAs. Only the header block is kept.
func (q *Queue) OpenOutbound(ctx context.Context, msg storage.QueueMessage, signer OutboundSigner, signAs string) (*Outbound, error) {
	if !msg.HasBlob() {
		return nil, storage.ErrNotFound
	}
	return newOutbound(func() (io.ReadCloser, error) { return q.blobs.Open(ctx, msg.BlobHash) }, signer, signAs)
}

func newOutbound(open func() (io.ReadCloser, error), signer OutboundSigner, signAs string) (*Outbound, error) {
	o := &Outbound{open: open}
	src, err := open()
	if err != nil {
		return nil, err
	}
	header, err := readHeaderBlock(bufio.NewReader(src), maxOutboundHeader)
	src.Close()
	if err != nil {
		return nil, err
	}
	o.header = CRLF(header)

	var ms MessageSigner
	if signer != nil {
		if ms, err = signer.NewSigner(signAs, o.header); err != nil {
			return nil, err
		}
	}
	count := &wireCount{}
	var dst io.Writer = count
	if ms != nil {
		dst = io.MultiWriter(count, ms)
	}
	if _, err := o.WriteTo(dst); err != nil {
		return nil, err
	}
	if ms != nil {
		if err := ms.Close(); err != nil {
			return nil, err
		}
		o.prefix = []byte(ms.Signature())
	}
	o.Size = count.n + int64(len(o.prefix))
	o.EightBit = count.eightBit || Has8Bit(o.prefix)
	o.MaxLine = max(count.maxLine, longestLine(o.prefix))
	if o.EightBit {
		if src, err = open(); err != nil {
			return nil, err
		}
		o.EightBitHeaders = Has8BitHeadersFrom(src)
		src.Close()
	}
	return o, nil
}

// WriteTo writes the message as it goes on the wire: signature field, then the CRLF form.
func (o *Outbound) WriteTo(w io.Writer) (int64, error) {
	src, err := o.open()
	if err != nil {
		return 0, err
	}
	defer src.Close()
	cw := &countingWriter{w: w}
	if _, err := cw.Write(o.prefix); err != nil {
		return cw.n, err
	}
	wire := NewCRLFWriter(cw)
	if _, err := io.Copy(wire, src); err != nil {
		return cw.n, err
	}
	err = wire.Close()
	return cw.n, err
}

// Header is the wire-form header block, signature field included.
func (o *Outbound) Header() []byte {
	return append(append([]byte(nil), o.prefix...), o.header...)
}

// Bytes loads the whole wire form; callers bound Size first.
func (o *Outbound) Bytes() ([]byte, error) {
	var b bytes.Buffer
	b.Grow(int(o.Size))
	_, err := o.WriteTo(&b)
	return b.Bytes(), err
}

// readHeaderBlock returns the lines up to and including the first empty one (LF or CRLF), at most
// max octets of whole lines; a message without an empty line is all header.
func readHeaderBlock(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	lineLen := 0 // octets of the current line so far (a long line comes in several pieces)
	for {
		frag, err := r.ReadSlice('\n')
		if len(out)+len(frag) > max {
			return out[:len(out)-lineLen], nil
		}
		out = append(out, frag...)
		lineLen += len(frag)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("mail: read header: %w", err)
		}
		if lineLen == 1 || lineLen == 2 && out[len(out)-2] == '\r' {
			return out, nil
		}
		lineLen = 0
	}
}

// wireCount counts octets, notes any outside US-ASCII and the longest line.
type wireCount struct {
	n                int64
	eightBit         bool
	lineLen, maxLine int
}

func (c *wireCount) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	c.eightBit = c.eightBit || Has8Bit(p)
	for _, b := range p {
		switch b {
		case '\n':
			c.lineLen = 0
		case '\r':
		default:
			c.lineLen++
			c.maxLine = max(c.maxLine, c.lineLen)
		}
	}
	return len(p), nil
}

// longestLine is the longest line of b, CR LF excluded.
func longestLine(b []byte) int {
	c := &wireCount{}
	_, _ = c.Write(b)
	return c.maxLine
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
