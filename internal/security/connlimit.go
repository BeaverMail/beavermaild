// Concurrent connection limiting for inbound listeners.
package security

// ConnLimiter caps concurrent accepted connections (semaphore).
// A nil *ConnLimiter or Max<=0 means unlimited.
type ConnLimiter struct {
	ch chan struct{}
}

// NewConnLimiter returns a limiter with at most max concurrent holders.
// max <= 0 means unlimited (returns nil).
func NewConnLimiter(max int) *ConnLimiter {
	if max <= 0 {
		return nil
	}
	return &ConnLimiter{ch: make(chan struct{}, max)}
}

// Acquire reports whether a new connection may proceed. Caller must Release when done.
func (l *ConnLimiter) Acquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release frees one connection slot.
func (l *ConnLimiter) Release() {
	if l == nil {
		return
	}
	select {
	case <-l.ch:
	default:
	}
}
