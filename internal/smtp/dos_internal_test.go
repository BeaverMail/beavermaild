package smtp

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/security"
)

// The null MX answer of a sender domain is cached: a repeated sender costs one DNS query.
func TestIsNullMXCached(t *testing.T) {
	t.Parallel()
	for range 3 {
		if !isNullMX(context.Background(), "cache.nullmx.test") {
			t.Fatal("null MX not detected")
		}
		if isNullMX(context.Background(), "cache-ok.example.org") {
			t.Fatal("ordinary domain taken for null MX")
		}
	}
	mxLookupsMu.Lock()
	defer mxLookupsMu.Unlock()
	if mxLookups["cache.nullmx.test"] != 1 || mxLookups["cache-ok.example.org"] != 1 {
		t.Fatalf("lookups %d and %d, want 1 each", mxLookups["cache.nullmx.test"], mxLookups["cache-ok.example.org"])
	}
}

// fromConn is one end of a pipe that reports a chosen remote address.
type fromConn struct {
	net.Conn
	remote net.Addr
}

func (c fromConn) RemoteAddr() net.Addr { return c.remote }

// One address cannot take every inbound slot: past MaxConnectionsPerIP it gets 421 and is closed.
func TestInboundConnectionsPerIP(t *testing.T) {
	t.Parallel()
	s := NewServer(slog.New(slog.DiscardHandler), "", nil, nil, nil, "", "", Options{MaxConnectionsPerIP: 1})
	lim := security.NewConnLimiter(10)
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 40000}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	first, firstPeer := net.Pipe()
	defer firstPeer.Close()
	lim.Acquire()
	go s.serveConn(ctx, fromConn{first, remote}, false, false, lim)
	r := bufio.NewReader(firstPeer)
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "220") {
		t.Fatalf("first: %q", line)
	}

	second, secondPeer := net.Pipe()
	defer secondPeer.Close()
	lim.Acquire()
	go s.serveConn(ctx, fromConn{second, remote}, false, false, lim)
	if line, _ := bufio.NewReader(secondPeer).ReadString('\n'); !strings.HasPrefix(line, "421 4.7.0 Too many connections from your address") {
		t.Fatalf("second from the same address: %q", line)
	}
}
