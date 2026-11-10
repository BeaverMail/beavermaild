package imap

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

// TestClientGone checks which session errors are logged as a client leaving (DEBUG) rather than a
// server failure (WARN).
func TestClientGone(t *testing.T) {
	for _, tc := range []struct {
		err  error
		gone bool
	}{
		{io.EOF, true},
		{fmt.Errorf("read: %w", io.EOF), true},
		{net.ErrClosed, true},
		{os.ErrDeadlineExceeded, true},
		{&net.OpError{Op: "read", Err: errors.New("connection reset by peer")}, true},
		{errors.New("mail: too much write contention"), false},
		{errors.New("storage: not found"), false},
	} {
		if got := clientGone(tc.err); got != tc.gone {
			t.Errorf("clientGone(%v) = %v, want %v", tc.err, got, tc.gone)
		}
	}
}
