// SMTP BDAT (CHUNKING) binary message transfer.
package smtp

import (
	"bufio"
	"fmt"
	"io"
)

// readBDATChunk reads size raw bytes followed by the framing CRLF after a BDAT command.
// beforeRead, if provided, refreshes the idle read deadline before I/O.
func readBDATChunk(r *bufio.Reader, size int, beforeRead ...func()) ([]byte, error) {
	var refresh func()
	if len(beforeRead) > 0 {
		refresh = beforeRead[0]
	}
	if refresh != nil {
		refresh()
	}
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
	if refresh != nil {
		refresh()
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
