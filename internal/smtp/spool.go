package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxHeaderBytes bounds the header block of an incoming message, the only part held in memory
// (Exim's header_maxsize is 1 MiB too); a larger one is refused like a message too large.
const maxHeaderBytes = 1 << 20

// errHeaderTooLarge reports a header block past maxHeaderBytes.
var errHeaderTooLarge = errors.New("smtp: message header too large")

// errSpoolWrite wraps a failure to write the spool file (a full disk): a local error, answered 451
// and logged, never shown to the client (it names a file).
var errSpoolWrite = errors.New("smtp: spool write")

// spool holds one incoming message while it is received and checked: the header block in memory,
// so the checks and the fields added on top work on it alone, and the body in a file, so a message
// costs no more memory than its header however large or slow it is.
type spool struct {
	header    []byte // through the empty line ending it; the whole message when it has none
	inBody    bool
	lineStart bool // header: at the start of a line (a CR keeps it, as in BareCR)
	file      *os.File
	w         *bufio.Writer
	bodyN     int64
	maxLine   int // BDAT: longest line allowed, CR LF excluded, and no NUL; 0 for no check (DATA checks itself)
	lineLen   int // octets of the current line so far
}

// newSpool opens a spool whose body file is created by create (in the blob store's directory, so
// one left by a crash is removed by its GC).
func newSpool(create func() (*os.File, error)) (*spool, error) {
	f, err := create()
	if err != nil {
		return nil, err
	}
	return &spool{lineStart: true, file: f, w: bufio.NewWriterSize(f, 64<<10)}, nil
}

// Write takes the next bytes of the message as stored (line ends as they will be kept).
func (sp *spool) Write(p []byte) (int, error) {
	n := len(p)
	if sp.maxLine > 0 {
		for _, c := range p {
			switch c {
			case '\n':
				sp.lineLen = 0
			case '\r':
			case 0:
				return 0, ErrNUL
			default:
				if sp.lineLen++; sp.lineLen > sp.maxLine {
					return 0, ErrLineTooLong
				}
			}
		}
	}
	if !sp.inBody {
		end := len(p)
		for i, c := range p {
			if c == '\n' {
				if sp.lineStart {
					end, sp.inBody = i+1, true
					break
				}
				sp.lineStart = true
			} else if c != '\r' {
				sp.lineStart = false
			}
		}
		if len(sp.header)+end > maxHeaderBytes {
			return 0, errHeaderTooLarge
		}
		sp.header = append(sp.header, p[:end]...)
		p = p[end:]
	}
	if len(p) > 0 {
		if _, err := sp.w.Write(p); err != nil {
			return 0, fmt.Errorf("%w: %w", errSpoolWrite, err)
		}
		sp.bodyN += int64(len(p))
	}
	return n, nil
}

// size is the number of octets received so far.
func (sp *spool) size() int64 { return int64(len(sp.header)) + sp.bodyN }

// message reads the message with header in place of the received one: the checks and the
// fields added on top change only the header.
func (sp *spool) message(header []byte) (io.Reader, error) {
	if err := sp.w.Flush(); err != nil {
		return nil, fmt.Errorf("%w: %w", errSpoolWrite, err)
	}
	return io.MultiReader(bytes.NewReader(header), io.NewSectionReader(sp.file, 0, sp.bodyN)), nil
}

// close drops the spool.
func (sp *spool) close() {
	_ = sp.file.Close()
	_ = os.Remove(sp.file.Name())
}
