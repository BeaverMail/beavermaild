package imap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func newWatchTestSession(t *testing.T) (*session, net.Conn) {
	t.Helper()
	server, client := net.Pipe()
	t.Cleanup(func() {
		_ = server.Close()
		_ = client.Close()
	})
	s := newSession(slog.New(slog.DiscardHandler), server, nil, nil, nil, false, false, nil, 0)
	return s, client
}

func waitDone(t *testing.T, ctx context.Context) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("context not canceled")
	}
}

func TestCommandWatchClientGone(t *testing.T) {
	t.Parallel()

	s, client := newWatchTestSession(t)
	w := s.watchCommand(context.Background())
	_ = client.Close()
	waitDone(t, w.ctx)
	if cause := w.end(); !errors.Is(cause, errClientGone) {
		t.Fatalf("cause %v", cause)
	}
}

func TestCommandWatchPipelinedBytesKept(t *testing.T) {
	t.Parallel()

	s, client := newWatchTestSession(t)
	w := s.watchCommand(context.Background())
	go func() { _, _ = client.Write([]byte("a2 NOOP\r\n")) }()
	// Wait until the watcher has buffered the byte and exited.
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher still running")
	}
	if cause := w.end(); cause != nil {
		t.Fatalf("cause %v", cause)
	}
	line, err := s.readLine()
	if err != nil || line != "a2 NOOP" {
		t.Fatalf("line %q err %v", line, err)
	}
}

func TestCommandWatchEndWithoutEvents(t *testing.T) {
	t.Parallel()

	s, client := newWatchTestSession(t)
	w := s.watchCommand(context.Background())
	if cause := w.end(); cause != nil {
		t.Fatalf("cause %v", cause)
	}
	// The deadline used to wake the watcher must not break the next read.
	go func() { _, _ = client.Write([]byte("a3 NOOP\r\n")) }()
	if line, err := s.readLine(); err != nil || line != "a3 NOOP" {
		t.Fatalf("line %q err %v", line, err)
	}
}

func TestCommandWatchShutdown(t *testing.T) {
	t.Parallel()

	s, _ := newWatchTestSession(t)
	var stopping atomic.Bool
	s.stopping = &stopping
	w := s.watchCommand(context.Background())
	// What connset.Drain does.
	stopping.Store(true)
	_ = s.conn.SetReadDeadline(time.Now())
	waitDone(t, w.ctx)
	cause := w.end()
	if !errors.Is(cause, errShuttingDown) {
		t.Fatalf("cause %v", cause)
	}
}
