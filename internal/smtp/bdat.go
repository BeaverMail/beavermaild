// SMTP BDAT (CHUNKING) binary message transfer.
package smtp

import (
	"bufio"
	"io"
)

// copyBDATChunk copies a size-byte chunk from r to w in pieces of buf, renewing the deadline for
// every MiB, and returns how many bytes it took from r: when w fails mid-chunk, the caller discards
// exactly the rest, so the next command starts where the client put it. buf is the session's, so
// a message sent in many small chunks allocates nothing per chunk.
func copyBDATChunk(w io.Writer, r *bufio.Reader, size int64, beforeRead func(), buf []byte) (read int64, err error) {
	for read < size {
		if read%(1<<20) < int64(len(buf)) && beforeRead != nil {
			beforeRead()
		}
		n, err := io.ReadFull(r, buf[:min(int64(len(buf)), size-read)])
		read += int64(n)
		if err != nil {
			return read, err
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return read, err
		}
	}
	return read, nil
}

// discardBDATChunk reads and drops size bytes: a chunk the server will not keep still has to leave
// the stream (RFC 3030 2), never held in memory. The deadline is renewed for every MiB.
func discardBDATChunk(r *bufio.Reader, size int64, beforeRead func()) error {
	for size > 0 {
		if beforeRead != nil {
			beforeRead()
		}
		n := min(size, 1<<20)
		if _, err := io.CopyN(io.Discard, r, n); err != nil {
			return err
		}
		size -= n
	}
	return nil
}
