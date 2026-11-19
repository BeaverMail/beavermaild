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

// errByeSent ends a session the server closed on purpose after BYE (autologout, selected mailbox
// deleted): not a failure to log.
var errByeSent = errors.New("imap: session closed after BYE")
