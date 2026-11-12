package smtp

import (
	"bufio"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// RFC 5321 5.1 and RFC 7505 on canned DNS answers.
func TestMXTargets(t *testing.T) {
	t.Parallel()
	notFound := &net.DNSError{Err: "no such host", IsNotFound: true}
	hasAddr := func() error { return nil }
	noAddr := func() error { return notFound }

	if _, err := mxTargets("example.com", []*net.MX{{Host: ".", Pref: 0}}, nil, hasAddr); !errors.Is(err, errNullMX) || !deliveryPermanent(err) {
		t.Fatalf("null MX: %v, want permanent errNullMX", err)
	}
	if got, err := mxTargets("a-only.example", nil, notFound, hasAddr); err != nil || !slices.Equal(got, []string{"a-only.example:25"}) {
		t.Fatalf("implicit MX: %v, %v", got, err)
	}
	if _, err := mxTargets("nxdomain.example", nil, notFound, noAddr); err == nil || !deliveryPermanent(err) {
		t.Fatalf("no MX and no address: %v, want permanent", err)
	}
	if _, err := mxTargets("x.example", nil, &net.DNSError{Err: "timeout", IsTimeout: true}, hasAddr); err == nil || deliveryPermanent(err) {
		t.Fatalf("DNS timeout: %v, want temporary", err)
	}
	// Equal preferences may come in any order, but never ahead of a lower preference.
	for range 20 {
		got, err := mxTargets("x.example", []*net.MX{{Host: "c.", Pref: 20}, {Host: "a.", Pref: 10}, {Host: "b.", Pref: 10}}, nil, hasAddr)
		if err != nil || len(got) != 3 || got[2] != "c:25" || !slices.Contains(got[:2], "a:25") || !slices.Contains(got[:2], "b:25") {
			t.Fatalf("order %v, %v", got, err)
		}
	}
}

// A DATA line far over the limit is rejected without being buffered, and the reader stays usable.
func TestReadDATAHugeLineBounded(t *testing.T) {
	t.Parallel()
	r := bufio.NewReader(strings.NewReader(strings.Repeat("a", 4<<20) + "\r\nnext\r\n"))
	if _, err := readDATA(r, DataLimits{}); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err %v", err)
	}
	if rest, _ := r.ReadString('\n'); rest != "next\r\n" {
		t.Fatalf("reader left at %q", rest)
	}
}

type ipv6Conn struct{ net.Conn }

func (ipv6Conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 2525}
}

// RFC 5321 4.1.3: an IPv6 address literal carries the "IPv6:" tag.
func TestReceivedFieldIPv6(t *testing.T) {
	t.Parallel()
	s := &session{conn: ipv6Conn{}, hostname: "mx.example.net", heloDomain: "client.example", filterTxnID: "id1"}
	if got := s.receivedField(time.Now()); !strings.Contains(got, "(unknown [IPv6:2001:db8::1])") {
		t.Fatalf("got %q", got)
	}
}

// RFC 5321 4.5.3.2: the timeout is per operation, so a slow but steady peer never trips it.
func TestTimeoutConnPerOperation(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	tc := &timeoutConn{Conn: client, d: 100 * time.Millisecond}
	go func() {
		for range 5 { // 5 x 60ms: well past one timeout in total, never past it between reads
			time.Sleep(60 * time.Millisecond)
			_, _ = server.Write([]byte("x"))
		}
	}()
	buf := make([]byte, 1)
	for i := range 5 {
		if _, err := tc.Read(buf); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if _, err := tc.Read(buf); err == nil {
		t.Fatal("idle peer: want a timeout")
	}
}
