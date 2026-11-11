package imap_test

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestIMAPURLAuth checks GENURLAUTH, URLFETCH (plain and RFC 5524 extended) and RESETKEY (RFC 4467).
func TestIMAPURLAuth(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	msg := "From: a@example.com\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n"
	if _, err := inbox.Deliver(ctx, accID, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	expectPrefix(t, r, "* OK")
	send(t, c, "l1 LOGIN alice@localhost beaver")
	expectPrefix(t, r, "l1 OK")

	base := "imap://alice%40localhost@localhost/INBOX/;uid=1"
	send(t, c, `g1 GENURLAUTH "`+base+`;urlauth=user+alice%40localhost" INTERNAL "`+base+`/;section=1;urlauth=authuser" internal`)
	line, _ := r.ReadString('\n')
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) != 4 || f[1] != "GENURLAUTH" || !strings.Contains(f[2], ";urlauth=user+alice%40localhost:INTERNAL:") {
		t.Fatalf("GENURLAUTH: %q", line)
	}
	expectPrefix(t, r, "g1 OK")
	u1, u2 := strings.Trim(f[2], `"`), strings.Trim(f[3], `"`)
	tampered := u1[:len(u1)-1] + map[bool]string{true: "1", false: "0"}[strings.HasSuffix(u1, "0")]

	send(t, c, `f1 URLFETCH "`+u1+`" "`+tampered+`" ("`+u2+`" BODYPARTSTRUCTURE BINARY)`)
	expectPrefix(t, r, `* URLFETCH "`+u1+`" {`+strconv.Itoa(len(msg))+"}")
	for line := ""; !strings.HasPrefix(line, "aGVsbG8="); {
		line, _ = r.ReadString('\n')
	}
	line, _ = r.ReadString('\n')
	want := ` "` + tampered + `" NIL "` + u2 + `" (BODYPARTSTRUCTURE ("TEXT" "PLAIN"`
	if !strings.HasPrefix(line, want) || !strings.HasSuffix(line, "(BINARY {5}\r\n") {
		t.Fatalf("URLFETCH: %q", line)
	}
	expectPrefix(t, r, "hello)")
	expectPrefix(t, r, "f1 OK")

	// Bad requests: another user's URL, a URL without access, an unknown mechanism.
	send(t, c, `g2 GENURLAUTH "imap://bob%40localhost@localhost/INBOX/;uid=1;urlauth=authuser" INTERNAL`)
	expectPrefix(t, r, "g2 BAD")
	send(t, c, `g3 GENURLAUTH "`+base+`" INTERNAL`)
	expectPrefix(t, r, "g3 BAD")
	send(t, c, `g4 GENURLAUTH "`+base+`;urlauth=authuser" XSAMPLE`)
	expectPrefix(t, r, "g4 BAD")

	send(t, c, "k1 RESETKEY INBOX")
	expectPrefix(t, r, "k1 OK [URLMECH INTERNAL]")
	send(t, c, `f2 URLFETCH "`+u1+`"`)
	expectPrefix(t, r, `* URLFETCH "`+u1+`" NIL`)
	expectPrefix(t, r, "f2 OK")
	send(t, c, "k2 RESETKEY Nope")
	expectPrefix(t, r, "k2 NO")
}
