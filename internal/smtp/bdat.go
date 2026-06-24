// SMTP BDAT (CHUNKING) binary message transfer.
package smtp

import (
	"bufio"
	"fmt"
	"io"
)

// readBDATChunk reads size raw bytes followed by the framing CRLF after a BDAT command.
func readBDATChunk(r *bufio.Reader, size int) ([]byte, error) {
	if size == 0 {
		crlf := make([]byte, 2)
		if _, err := io.ReadFull(r, crlf); err != nil {
			return nil, err
		}
		if crlf[0] != '\r' || crlf[1] != '\n' {
			return nil, fmt.Errorf("smtp: bdat missing crlf after chunk")
		}
		return nil, nil
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	crlf := make([]byte, 2)
	if _, err := io.ReadFull(r, crlf); err != nil {
		return nil, err
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return nil, fmt.Errorf("smtp: bdat missing crlf after chunk")
	}
	return buf, nil
}
