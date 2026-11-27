package smtp_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

// RFC 2045 2.7, 2.8: 7bit and 8bit content hold no NUL; it is binary data, which needs BINARYMIME
// (RFC 3030 3, RFC 6152 3), not offered. A NUL refuses the message, by DATA (read to its end) or
// BDAT (the chunk dropped, a pipelined chunk 503), and the session goes on. Before: accepted,
// stored and relayed as is.
func TestRFC6152NULRefused(t *testing.T) {
	t.Parallel()
	conn, r := spoolServer(t)
	msg := "From: a@example.org\r\nSubject: nul\r\n\r\na\x00b\r\n"
	send(t, conn, "MAIL FROM:<x@example.org>")
	expect(t, r, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, r, "250")
	send(t, conn, "DATA")
	expect(t, r, "354")
	if _, err := conn.Write([]byte(msg + "more\r\n.\r\n")); err != nil {
		t.Fatal(err)
	}
	expect(t, r, "554 5.6.0")
	send(t, conn, "NOOP")
	expect(t, r, "250")

	send(t, conn, "MAIL FROM:<x@example.org>")
	expect(t, r, "250")
	send(t, conn, "RCPT TO:<alice@localhost>")
	expect(t, r, "250")
	if _, err := fmt.Fprintf(conn, "BDAT %d\r\n%sBDAT 0 LAST\r\n", len(msg), msg); err != nil {
		t.Fatal(err)
	}
	expect(t, r, "554 5.6.0")
	expect(t, r, "503")
	send(t, conn, "NOOP")
	expect(t, r, "250")
}

// RFC 6152 2: BODY needs a value, 7BIT or 8BITMIME. "BODY=" was taken as no BODY (7BIT); "BODY"
// alone got 555, the reply for an unknown parameter.
func TestRFC6152BodyValueRequired(t *testing.T) {
	t.Parallel()
	conn, r := spoolServer(t)
	for _, arg := range []string{"BODY=", "BODY"} {
		send(t, conn, "MAIL FROM:<x@example.org> "+arg)
		expect(t, r, "501")
	}
	send(t, conn, "MAIL FROM:<x@example.org> BODY=8BITMIME")
	expect(t, r, "250")
}

// The client never sends a NUL (a message stored by APPEND, or received before this check): it
// fails for good before connecting, status 5.6.0.
func TestClientRefusesNUL(t *testing.T) {
	t.Parallel()
	err := smtp.Send(context.Background(), "127.0.0.1:1", "a@example.org", "b@example.net",
		[]byte("Subject: x\r\n\r\na\x00b\r\n"), smtp.ClientOptions{})
	var de *smtp.DeliveryError
	if !errors.Is(err, mail.ErrNUL) || !errors.As(err, &de) || !de.Permanent || mail.SMTPStatusFromError(err) != "5.6.0" {
		t.Fatalf("NUL: %v", err)
	}
}
