package imap_test

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/imap"
	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/storage/sqlite"
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

// RFC 4467 BASE.7.4, RFC 5524: a URL whose section names no part is invalid (NIL, in both forms);
// "(url)" without a known parameter is answered as unextended; an unknown parameter atom is not a
// syntax error. RFC 4469 4.1: CATENATE refuses such a URL with BADURL, whose text has no "]".
func TestIMAPURLFetchEdgeCases(t *testing.T) {
	t.Parallel()
	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	msg := "From: a@example.com\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
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
	send(t, c, `g1 GENURLAUTH "`+base+`;urlauth=authuser" INTERNAL "`+base+`/;section=9;urlauth=authuser" INTERNAL`)
	line, _ := r.ReadString('\n')
	f := strings.Fields(strings.TrimSpace(line))
	expectPrefix(t, r, "g1 OK")
	whole, missing := strings.Trim(f[2], `"`), strings.Trim(f[3], `"`)

	send(t, c, `f1 URLFETCH "`+missing+`" ("`+missing+`" BODYPARTSTRUCTURE BODY)`)
	if line, _ = r.ReadString('\n'); line != `* URLFETCH "`+missing+`" NIL "`+missing+`" NIL`+"\r\n" {
		t.Fatalf("missing part: %q", line)
	}
	expectPrefix(t, r, "f1 OK")
	for _, args := range []string{`("` + whole + `")`, `("` + whole + `" X-FUTURE)`} {
		send(t, c, "f2 URLFETCH "+args)
		expectPrefix(t, r, `* URLFETCH "`+whole+`" {`+strconv.Itoa(len(msg))+"}")
		for line := ""; !strings.HasPrefix(line, "hello"); {
			line, _ = r.ReadString('\n')
		}
		expectPrefix(t, r, "")
		expectPrefix(t, r, "f2 OK")
	}

	send(t, c, `a1 APPEND INBOX CATENATE (URL "/INBOX/;UID=1/;SECTION=9]")`)
	expectPrefix(t, r, "a1 NO [BADURL /INBOX/;UID=1/;SECTION=9] ")
}

// Known URLAUTH flaws (Cyrus): CVE-2026-47085, a token forged for a mailbox that has no key yet
// (signed with an empty key); CVE-2026-47087, a URL still honored once its owner lost access (here:
// the account is disabled); CVE-2015-8077 class, PARTIAL offsets near the integer limits. Each URL
// must give NIL, never data or a crash.
func TestIMAPURLAuthKnownFlaws(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := sqlite.Open(ctx, "file:"+t.TempDir()+"/store.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	dir := directory.NewLocal(store)
	alice, err := directory.SeedDev(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	dom, err := dir.LookupDomain(ctx, "localhost")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dir.CreateAccount(ctx, dom.ID, "bob", "bob-secret-1"); err != nil {
		t.Fatal(err)
	}
	inbox := mail.NewInbox(store, blob.NewFS(t.TempDir()+"/blobs"))
	if _, err := inbox.Deliver(ctx, alice.ID, []byte("Subject: s\r\n\r\nsecret\r\n")); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := imap.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, imap.Options{})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)
	login := func(user, pass string) (net.Conn, *bufio.Reader) {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		r := bufio.NewReader(c)
		expectPrefix(t, r, "* OK")
		send(t, c, "l1 LOGIN "+user+" "+pass)
		expectPrefix(t, r, "l1 OK")
		return c, r
	}
	fetchNIL := func(c net.Conn, r *bufio.Reader, u string) {
		t.Helper()
		send(t, c, `f URLFETCH "`+u+`"`)
		if line, _ := r.ReadString('\n'); line != `* URLFETCH "`+u+`" NIL`+"\r\n" {
			t.Fatalf("URLFETCH %s: %q, want NIL", u, line)
		}
		expectPrefix(t, r, "f OK")
	}
	a, ra := login("alice@localhost", "beaver")
	b, rb := login("bob@localhost", "bob-secret-1")

	// CVE-2026-47085: Drafts never had a key; an empty-key HMAC must not pass.
	rump := "imap://alice%40localhost@localhost/Drafts/;uid=1;urlauth=authuser"
	mac := hmac.New(sha256.New, nil)
	mac.Write([]byte(rump))
	fetchNIL(b, rb, rump+":INTERNAL:"+hex.EncodeToString(mac.Sum(nil)))

	// CVE-2015-8077 class: offsets past the integer limits are refused, not wrapped.
	base := "imap://alice%40localhost@localhost/INBOX/;uid=1"
	for _, partial := range []string{"/;PARTIAL=9223372036854775807.9223372036854775807", "/;PARTIAL=99999999999999999999"} {
		send(t, a, `g GENURLAUTH "`+base+partial+`;urlauth=authuser" INTERNAL`)
		line, _ := ra.ReadString('\n')
		if strings.HasPrefix(line, "g BAD") {
			continue // refused at generation: the offset does not parse
		}
		expectPrefix(t, ra, "g OK")
		send(t, b, `f URLFETCH `+strings.Fields(line)[2])
		got, _ := rb.ReadString('\n')
		if strings.Contains(got, "{") && !strings.HasSuffix(got, "{0}\r\n") {
			t.Fatalf("PARTIAL %s: %q", partial, got)
		}
		for !strings.HasPrefix(got, "f ") {
			got, _ = rb.ReadString('\n')
		}
	}

	// CVE-2026-47087: bob reads alice's authuser URL until alice's account is disabled.
	send(t, a, `g GENURLAUTH "`+base+`;urlauth=authuser" INTERNAL`)
	line, _ := ra.ReadString('\n')
	expectPrefix(t, ra, "g OK")
	u := strings.Trim(strings.Fields(line)[2], `"`)
	send(t, b, `f URLFETCH "`+u+`"`)
	expectPrefix(t, rb, `* URLFETCH "`+u+`" {`)
	for line := ""; !strings.HasPrefix(line, "f OK"); {
		line, _ = rb.ReadString('\n')
	}
	if err := dir.SetActive(ctx, alice.ID, false); err != nil {
		t.Fatal(err)
	}
	fetchNIL(b, rb, u)
}
