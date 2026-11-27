// SMTP DATA phase limits, strict parsing, and outbound dot-stuffing.
package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

const (
	// DefaultMaxMessageBytes is the inbound DATA size cap when config leaves it unset.
	DefaultMaxMessageBytes = 10 * 1024 * 1024
	// DefaultMaxDATA_lineBytes is the RFC 5321 maximum line length excluding CRLF.
	DefaultMaxDATA_lineBytes = 998
)

var (
	// ErrMessageTooLarge is returned when DATA exceeds MaxMessageBytes.
	ErrMessageTooLarge = errors.New("smtp: message too large")
	// ErrLineTooLong is returned when a DATA line exceeds MaxLineBytes.
	ErrLineTooLong = errors.New("smtp: data line too long")
	// ErrBareLF is returned when a DATA line holds a bare LF or bare CR (SMTP smuggling,
	// CVE-2023-51764 class): the end of the message can no longer be trusted.
	ErrBareLF = errors.New("smtp: bare CR or LF in data")
	// ErrNUL is returned for a NUL octet in the message: 7bit and 8bit content have none (RFC 2045
	// 2.7, 2.8); it is binary data, which needs BINARYMIME (RFC 3030 3), not offered.
	ErrNUL = errors.New("smtp: NUL octet in data")
)

// DataLimits caps inbound SMTP DATA size and line length.
type DataLimits struct {
	MaxMessageBytes int
	MaxLineBytes    int
}

// withDefaults returns limits with package defaults for unset fields.
func (l DataLimits) withDefaults() DataLimits {
	if l.MaxMessageBytes <= 0 {
		l.MaxMessageBytes = DefaultMaxMessageBytes
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = DefaultMaxDATA_lineBytes
	}
	return l
}

// readDATA reads dot-stuffed message data until CRLF.CRLF, enforcing limits and strict CRLF lines,
// and writes the message to w with LF line ends, as it is stored. beforeRead, if non-nil, is called
// before each line read (idle read deadline refresh).
func readDATA(r *bufio.Reader, limits DataLimits, w io.Writer, beforeRead ...func()) error {
	limits = limits.withDefaults()
	var refresh func()
	if len(beforeRead) > 0 {
		refresh = beforeRead[0]
	}
	var buf []byte      // one line buffer for the whole message
	var size, lines int // stored with LF: the message size counts CRLF (RFC 1870 5), one more octet per line
	for {
		if refresh != nil {
			refresh()
		}
		line, tooLong, err := readLineBounded(r, limits.MaxLineBytes+2, buf)
		if line != nil {
			buf = line
		}
		if err != nil {
			return err
		}
		if tooLong {
			return ErrLineTooLong
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return ErrBareLF
		}
		content := line[:len(line)-2]
		if bytes.IndexByte(content, '\r') >= 0 {
			return ErrBareLF
		}
		if bytes.Equal(content, []byte(".")) {
			return nil
		}
		if bytes.IndexByte(content, 0) >= 0 {
			return ErrNUL
		}
		if len(content) > 0 && content[0] == '.' {
			content = content[1:]
		}
		size += len(content) + 1
		if lines++; size+lines > limits.MaxMessageBytes {
			return ErrMessageTooLarge
		}
		// The LF goes in place of the CR: content is a slice of line, which ends "\r\n".
		content = append(content, '\n')
		if _, err := w.Write(content); err != nil {
			return err
		}
	}
}

// readLineBounded reads through the next '\n' but keeps at most max bytes of it: a longer line is
// consumed to its end, reported with tooLong, and never buffered whole. The line is appended to
// buf[:0], so a caller reading many lines can reuse one buffer.
func readLineBounded(r *bufio.Reader, max int, buf []byte) (line []byte, tooLong bool, err error) {
	line = buf[:0]
	for {
		frag, err := r.ReadSlice('\n')
		if len(line)+len(frag) > max {
			tooLong = true
		} else {
			line = append(line, frag...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			line = nil
		}
		return line, tooLong, err
	}
}

// drainDATA discards the remainder of a failed DATA phase until the end marker. It reports false when
// it meets a bare CR or LF: the framing is then untrustworthy and the caller must hang up rather than
// resume reading commands after a "." the sender may not have meant (SMTP smuggling).
func drainDATA(r *bufio.Reader, limits DataLimits, beforeRead ...func()) (clean bool) {
	limits = limits.withDefaults()
	var refresh func()
	if len(beforeRead) > 0 {
		refresh = beforeRead[0]
	}
	var buf []byte
	for {
		if refresh != nil {
			refresh()
		}
		line, tooLong, err := readLineBounded(r, limits.MaxLineBytes+2, buf)
		if line != nil {
			buf = line
		}
		if err != nil {
			return false
		}
		if tooLong || len(line) < 2 || line[len(line)-2] != '\r' || bytes.IndexByte(line[:len(line)-2], '\r') >= 0 {
			return false
		}
		if bytes.Equal(line, []byte(".\r\n")) {
			return true
		}
	}
}

// writeDATABody sends msg dot-stuffed (RFC 5321 4.5.2), then the CRLF.CRLF terminator.
func writeDATABody(w io.Writer, msg *mail.Outbound) error {
	bw := bufio.NewWriterSize(w, 32<<10)
	d := &dotStuffer{w: bw, lineStart: true}
	if _, err := msg.WriteTo(d); err != nil {
		return err
	}
	if !d.lineStart { // a last line without its line end still needs one before the "."
		if _, err := bw.WriteString("\r\n"); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString(".\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

// dotStuffer doubles a "." that starts a line of the CRLF stream written to it.
type dotStuffer struct {
	w         io.Writer
	lineStart bool
}

func (d *dotStuffer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if d.lineStart && p[0] == '.' {
			if _, err := d.w.Write([]byte{'.'}); err != nil {
				return 0, err
			}
		}
		line := p
		if i := bytes.IndexByte(p, '\n'); i >= 0 {
			line = p[:i+1]
		}
		if _, err := d.w.Write(line); err != nil {
			return 0, err
		}
		d.lineStart = line[len(line)-1] == '\n'
		p = p[len(line):]
	}
	return n, nil
}

// dataErrorResponse maps readDATA errors to SMTP reply lines.
func dataErrorResponse(err error) string {
	switch {
	case errors.Is(err, ErrMessageTooLarge), errors.Is(err, errHeaderTooLarge):
		return replyMessageTooLarge
	case errors.Is(err, errSpoolWrite):
		return replyLocalError
	case errors.Is(err, ErrLineTooLong):
		return "552 5.3.4 Line length exceeds maximum permitted"
	case errors.Is(err, ErrBareLF):
		return replyBareCRLF
	case errors.Is(err, ErrNUL):
		return "554 5.6.0 NUL octet in message: binary content is not accepted"
	default:
		return fmt.Sprintf("554 5.6.0 %s", err.Error())
	}
}
