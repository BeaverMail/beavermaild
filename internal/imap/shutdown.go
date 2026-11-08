// Orderly shutdown: sessions say BYE and close TLS cleanly instead of being cut off.
package imap

import (
	"errors"
	"time"
)

// drainTimeout bounds how long Serve waits for sessions to close on shutdown.
const drainTimeout = 5 * time.Second

// errShuttingDown ends a session after it has sent BYE.
var errShuttingDown = errors.New("imap: server shutting down")
