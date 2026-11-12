// SMTP DATA phase limits, strict parsing, and outbound dot-stuffing.
package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
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

// readDATA reads dot-stuffed message data until CRLF.CRLF, enforcing limits and strict CRLF lines.
// beforeRead, if non-nil, is called before each line read (idle read deadline refresh).
func readDATA(r *bufio.Reader, limits DataLimits, beforeRead ...func()) ([]byte, error) {
	limits = limits.withDefaults()
	var refresh func()
	if len(beforeRead) > 0 {
		refresh = beforeRead[0]
	}
	var buf bytes.Buffer
	for {
		if refresh != nil {
			refresh()
		}
		line, tooLong, err := readLineBounded(r, limits.MaxLineBytes+2)
		if err != nil {
			return nil, err
		}
		if tooLong {
			return nil, ErrLineTooLong
		}
		if len(line) < 2 || line[len(line)-2] != '\r' {
			return nil, ErrBareLF
		}
		content := line[:len(line)-2]
		if bytes.IndexByte(content, '\r') >= 0 {
			return nil, ErrBareLF
		}
		if bytes.Equal(content, []byte(".")) {
			break
		}
		if len(content) > 0 && content[0] == '.' {
			content = content[1:]
		}
		buf.Write(content)
		buf.WriteByte('\n')
		if buf.Len() > limits.MaxMessageBytes {
			return nil, ErrMessageTooLarge
		}
	}
	return buf.Bytes(), nil
}

// readLineBounded reads through the next '\n' but keeps at most max bytes of it: a longer line is
// consumed to its end, reported with tooLong, and never buffered whole.
func readLineBounded(r *bufio.Reader, max int) (line []byte, tooLong bool, err error) {
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
	for {
		if refresh != nil {
			refresh()
		}
		line, tooLong, err := readLineBounded(r, limits.MaxLineBytes+2)
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

// writeDATABody sends dot-stuffed DATA and the CRLF.CRLF terminator.
func writeDATABody(w io.Writer, data []byte) error {
	for len(data) > 0 {
		idx := bytes.IndexByte(data, '\n')
		var line []byte
		if idx < 0 {
			line = data
			data = nil
		} else {
			line = data[:idx]
			data = data[idx+1:]
		}
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if len(line) > 0 && line[0] == '.' {
			if _, err := w.Write([]byte(".")); err != nil {
				return err
			}
		}
		if _, err := w.Write(line); err != nil {
			return err
		}
		if _, err := w.Write([]byte("\r\n")); err != nil {
			return err
		}
	}
	_, err := w.Write([]byte(".\r\n"))
	return err
}

// dataErrorResponse maps readDATA errors to SMTP reply lines.
func dataErrorResponse(err error) string {
	switch {
	case errors.Is(err, ErrMessageTooLarge):
		return replyMessageTooLarge
	case errors.Is(err, ErrLineTooLong):
		return "552 5.3.4 Line length exceeds maximum permitted"
	case errors.Is(err, ErrBareLF):
		return replyBareCRLF
	default:
		return fmt.Sprintf("554 5.6.0 %s", err.Error())
	}
}
