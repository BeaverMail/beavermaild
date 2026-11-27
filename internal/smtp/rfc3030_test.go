package smtp_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// RFC 5321 4.5.3.1.6 holds for BDAT as for DATA: without BINARYMIME (not offered) the content is
// lines of at most 998 octets. A longer one, also across two chunks, refuses the message with the
// 552 DATA gives; the rest of the chunk is read and dropped, a chunk already pipelined after it gets
// 503 and the session goes on (RFC 3030 2). Before: accepted, stored and relayed as is.
func TestRFC3030BDATLineLength(t *testing.T) {
	t.Parallel()
	conn, r := spoolServer(t)
	head := "From: a@example.org\r\nSubject: long\r\n\r\n"
	for _, tc := range []struct {
		name   string
		chunks []string
	}{
		{"one chunk", []string{head + strings.Repeat("x", 999) + "\r\nmore\r\n"}},
		{"across chunks", []string{head + strings.Repeat("x", 600), strings.Repeat("x", 600) + "\r\n"}},
		{"header line", []string{"Subject: " + strings.Repeat("s", 1000) + "\r\n\r\nbody\r\n"}},
	} {
		send(t, conn, "MAIL FROM:<x@example.org>")
		expect(t, r, "250")
		send(t, conn, "RCPT TO:<alice@localhost>")
		expect(t, r, "250")
		var wire string
		for _, c := range tc.chunks {
			wire += fmt.Sprintf("BDAT %d\r\n%s", len(c), c)
		}
		wire += "BDAT 0 LAST\r\n"
		if _, err := conn.Write([]byte(wire)); err != nil {
			t.Fatal(err)
		}
		for range len(tc.chunks) - 1 {
			expect(t, r, "250")
		}
		expect(t, r, "552 5.3.4 Line length")
		expect(t, r, "503")
		send(t, conn, "NOOP")
		expect(t, r, "250")
	}
	// 998 octets is the limit, not over it.
	send(t, conn, "MAIL FROM:<x@example.org>")
	expect(t, r, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, r, "250")
	msg := head + strings.Repeat("x", 998) + "\r\n"
	if _, err := fmt.Fprintf(conn, "BDAT %d LAST\r\n%s", len(msg), msg); err != nil {
		t.Fatal(err)
	}
	expect(t, r, "250")
}

// A message sent in many small chunks allocates nothing per chunk. Before: a 32 KiB buffer per
// chunk, so 4000 one-octet chunks allocated 129 MB (10 MB that way: about 320 GB).
func TestRFC3030SmallChunksAllocate(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector allocates for every operation: allocations do not measure the code")
	}
	conn, r := spoolServer(t)
	send(t, conn, "MAIL FROM:<x@example.org>")
	expect(t, r, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, r, "250")
	msg := "From: a@example.org\r\nSubject: tiny\r\n\r\n" + strings.Repeat(strings.Repeat("t", 78)+"\r\n", 50)
	var wire strings.Builder
	for i := range len(msg) - 1 {
		fmt.Fprintf(&wire, "BDAT 1\r\n%c", msg[i])
	}
	fmt.Fprintf(&wire, "BDAT 1 LAST\r\n%c", msg[len(msg)-1])
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := conn.Write([]byte(wire.String())); err != nil {
		t.Fatal(err)
	}
	for range len(msg) {
		line, err := r.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "250") {
			t.Fatalf("%q %v", line, err)
		}
	}
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 16<<20 { // about 2 MB now
		t.Errorf("%d one-octet chunks allocated %d MB", len(msg), grew>>20)
	}
}

// RFC 5321 4.5.3.1.6, RFC 3030 3: the client never sends a line over 998 octets (a message
// received with BDAT before the limit, or stored by APPEND). It fails for good before connecting,
// as Exim's message_linelength_limit does.
func TestClientRefusesLongLines(t *testing.T) {
	t.Parallel()
	closed := "127.0.0.1:1" // nothing listens: an error other than ErrLineTooLong means it dialed
	err := smtp.Send(context.Background(), closed, "a@example.org", "b@example.net",
		[]byte("Subject: x\r\n\r\n"+strings.Repeat("x", 999)+"\r\n"), smtp.ClientOptions{})
	var de *smtp.DeliveryError
	if !errors.Is(err, mail.ErrLineTooLong) || !errors.As(err, &de) || !de.Permanent {
		t.Fatalf("999-octet line: %v", err)
	}
	if mail.SMTPStatusFromError(err) != "5.6.0" {
		t.Fatalf("status %s", mail.SMTPStatusFromError(err))
	}
	err = smtp.Send(context.Background(), closed, "a@example.org", "b@example.net",
		[]byte("Subject: x\r\n\r\n"+strings.Repeat("x", 998)+"\r\n"), smtp.ClientOptions{})
	if errors.Is(err, mail.ErrLineTooLong) {
		t.Fatal("998-octet line refused")
	}
}
