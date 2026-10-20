// Package connset tracks live server sessions so shutdown can wake them and wait for them.
package connset

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Set holds open sessions keyed by any comparable handle (e.g. the session pointer).
type Set struct {
	Stopping atomic.Bool // sessions read this to answer with BYE/421 instead of waiting
	mu       sync.Mutex
	conns    map[any]net.Conn // raw conn: its read deadline also reaches a TLS conn wrapping it
}

// Add registers a session with its accepted connection.
func (s *Set) Add(key any, conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns == nil {
		s.conns = make(map[any]net.Conn)
	}
	s.conns[key] = conn
}

// Remove unregisters a finished session.
func (s *Set) Remove(key any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, key)
}

// Len returns the number of open sessions.
func (s *Set) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// Drain sets Stopping, expires every session's pending read so it notices at once, and
// waits up to timeout for all sessions to finish. Sessions write their own goodbye, so it
// never interleaves with a response in progress. Reports whether every session finished.
func (s *Set) Drain(timeout time.Duration) bool {
	s.Stopping.Store(true)
	s.mu.Lock()
	for _, conn := range s.conns {
		_ = conn.SetReadDeadline(time.Now())
	}
	s.mu.Unlock()
	// Polling, not a WaitGroup: a conn accepted while draining would be an Add racing Wait.
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if s.Len() == 0 {
			return true
		}
	}
	return s.Len() == 0
}
