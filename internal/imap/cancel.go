// Cancellation of long-running commands (SEARCH, SORT, THREAD) when the client goes away.
package imap

import (
	"context"
	"errors"
	"net"
	"time"
)

var errClientGone = errors.New("imap: client disconnected during command")

// commandWatch cancels a command's context when the client disconnects or the server starts
// shutting down. The session reads nothing while such a command runs, so a goroutine can peek
// at the connection: EOF or a connection error means the client is gone; bytes mean it is still
// there (they stay buffered for the next command).
type commandWatch struct {
	ctx    context.Context
	cancel context.CancelCauseFunc
	quit   chan struct{}
	done   chan struct{}
	s      *session
}

// watchCommand starts watching; end must be called before the session uses the connection again.
func (s *session) watchCommand(parent context.Context) *commandWatch {
	ctx, cancel := context.WithCancelCause(parent)
	w := &commandWatch{ctx: ctx, cancel: cancel, quit: make(chan struct{}), done: make(chan struct{}), s: s}
	go w.run()
	return w
}

func (w *commandWatch) run() {
	defer close(w.done)
	_, err := w.s.r.Peek(1)
	select {
	case <-w.quit:
		return
	default:
	}
	if err == nil {
		return
	}
	if w.s.isStopping() {
		// Drain expired the read deadline.
		w.cancel(errShuttingDown)
		return
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		// Session idle timeout: the client may still be waiting for the reply.
		return
	}
	w.cancel(errClientGone)
}

// end stops the watcher and returns why the command was canceled, or nil if it was not.
func (w *commandWatch) end() error {
	canceled := w.ctx.Err() != nil
	close(w.quit)
	// Wake the pending Peek, then clear the deadline: the next readLine sets the session
	// timeout (or expires reads at once during shutdown).
	_ = w.s.conn.SetReadDeadline(time.Now())
	<-w.done
	_ = w.s.conn.SetReadDeadline(time.Time{})
	w.cancel(nil)
	if canceled {
		return context.Cause(w.ctx)
	}
	return nil
}

// abortCommand answers a canceled command: during shutdown the client gets a tagged NO and the
// session then says BYE; a client that is gone just has its session closed.
func (s *session) abortCommand(tag string, cause error) error {
	if errors.Is(cause, errShuttingDown) {
		return s.tagged(tag, "NO [UNAVAILABLE] server shutting down")
	}
	return cause
}
