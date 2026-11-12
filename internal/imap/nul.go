// NUL bytes in message data sent to clients.
package imap

import (
	"bytes"
	"io"
)

// maskNUL returns data with every NUL replaced by 0x80. A literal is CHAR8 (RFC 3501 9): NUL
// fits only a BINARY literal8, yet SMTP delivers messages holding it. Replacing keeps the
// length, so BODYSTRUCTURE sizes and partial offsets still match (Dovecot does the same).
func maskNUL(data []byte) []byte {
	if bytes.IndexByte(data, 0) < 0 {
		return data
	}
	out := bytes.Clone(data)
	for i, c := range out {
		if c == 0 {
			out[i] = 0x80
		}
	}
	return out
}

// nulMaskWriter applies maskNUL to a message streamed to the client.
type nulMaskWriter struct{ w io.Writer }

func (m nulMaskWriter) Write(p []byte) (int, error) {
	if _, err := m.w.Write(maskNUL(p)); err != nil {
		return 0, err
	}
	return len(p), nil
}
