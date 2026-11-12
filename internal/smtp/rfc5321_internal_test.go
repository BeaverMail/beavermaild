package smtp

import (
	"bufio"
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
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

// RFC 5321 4.5.3.2: the timer runs per command. A reply that arrives in time passes; a server that
// dribbles a reply byte by byte cannot stretch it (the queue worker is sequential), and the next
// command gets a fresh timer.
func TestTimeoutConnPerCommand(t *testing.T) {
	t.Parallel()
	server, client := net.Pipe()
	defer server.Close()
	tc := &timeoutConn{Conn: client, d: 200 * time.Millisecond}
	go func() {
		buf := make([]byte, 64)
		_, _ = server.Read(buf) // command 1
		_, _ = server.Write([]byte("250 ok\r\n"))
		_, _ = server.Read(buf) // command 2: dribble the reply, 80ms a byte
		for _, b := range []byte("250 slow reply\r\n") {
			time.Sleep(80 * time.Millisecond)
			if _, err := server.Write([]byte{b}); err != nil {
				return
			}
		}
	}()
	r := bufio.NewReader(tc)
	if _, err := tc.Write([]byte("NOOP\r\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := r.ReadString('\n'); err != nil || line != "250 ok\r\n" {
		t.Fatalf("command 1: %q, %v", line, err)
	}
	if _, err := tc.Write([]byte("NOOP\r\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ReadString('\n'); err == nil {
		t.Fatal("dribbled reply: want a timeout")
	}
}

// The postmaster fallback scans every account: one session looks it up once per tenant, however many
// RCPT TO:<postmaster@...> it sends (DoS guard, see .specs/security.md).
func TestPostmasterLookupCachedPerSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	dir := directory.NewLocal(store)
	admin, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	s := &session{dir: dir}
	first, err := s.resolvePostmaster(ctx, 0)
	if err != nil || len(first) != 1 || first[0].ID != admin.ID {
		t.Fatalf("first lookup %+v, %v", first, err)
	}
	if err := dir.SetAccountRole(ctx, admin.ID, directory.RoleUser); err != nil {
		t.Fatal(err)
	}
	// A fresh lookup would now find no admin; the session must answer from its cache.
	if again, err := s.resolvePostmaster(ctx, 0); err != nil || len(again) != 1 {
		t.Fatalf("second lookup scanned again: %+v, %v", again, err)
	}
	if _, err := dir.ResolvePostmaster(ctx, 0); !errors.Is(err, directory.ErrNotFound) {
		t.Fatalf("directory still has an admin: %v", err)
	}
}

// The queue gets the authenticated sender as DKIM identity, and nothing for an unauthenticated session.
func TestBuildEnvelopeSignAs(t *testing.T) {
	t.Parallel()
	s := &session{principal: directory.Principal{AccountID: 7, LocalPart: "alice", DomainName: "example.net"}}
	if got := s.buildEnvelopeDSN(nil).SignAs; got != "alice@example.net" {
		t.Fatalf("SignAs %q", got)
	}
	if got := (&session{}).buildEnvelopeDSN(nil).SignAs; got != "" {
		t.Fatalf("unauthenticated SignAs %q", got)
	}
}
