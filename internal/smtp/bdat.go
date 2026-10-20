// SMTP BDAT (CHUNKING) binary message transfer.
package smtp

import (
	"bufio"
	"io"
)

// readBDATChunk reads exactly size raw bytes after a BDAT command line (RFC 3030: no
// framing CRLF follows the chunk). beforeRead, if provided, refreshes the idle read deadline.
func readBDATChunk(r *bufio.Reader, size int, beforeRead ...func()) ([]byte, error) {
	if len(beforeRead) > 0 && beforeRead[0] != nil {
		beforeRead[0]()
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
