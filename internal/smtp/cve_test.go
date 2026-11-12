package smtp_test

// Regression tests for published MTA vulnerabilities and attack classes (see .specs/security.md).
// Each test names the CVE or class it guards against; a failure means BeaverMail is exposed again.

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/log"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
	"github.com/BeaverMail/beavermaild/internal/tlsload/tlstest"
)

// readAll collects everything the server sends until it closes or goes quiet.
func readAll(conn net.Conn) string {
	var out strings.Builder
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			return out.String()
		}
	}
}

// SMTP smuggling, CVE-2023-51764 (Postfix), CVE-2023-51765 (Sendmail), CVE-2023-51766 (Exim): a message
// whose body holds a fake end-of-data built from bare CR/LF, followed by a second transaction. A
// receiver that ends DATA there runs the second transaction as if the (trusted) sending server had
// sent it. Neither the smuggled sender nor its message may ever be accepted.
func TestCVE_2023_51764_SMTPSmugglingInbound(t *testing.T) {
	t.Parallel()
	const smuggled = "MAIL FROM:<ceo@victim.example>\r\nRCPT TO:<alice@localhost>\r\nDATA\r\nSubject: smuggled\r\n\r\nforged\r\n.\r\n"
	// prefix puts the smuggling behind another DATA error (overlong line, oversized message), whose
	// recovery path must not resynchronise on the fake end either.
	type variant struct{ name, prefix, end string }
	var variants []variant
	for _, end := range []string{"\n.\n", "\n.\r\n", "\r.\r\n", "\r\n.\r", "\r.\n", "\r\n.\n", "\n.\r", "\r.\r", "\r\n\x00.\r\n"} {
		name := strings.NewReplacer("\r", `\r`, "\n", `\n`, "\x00", `\0`).Replace(end)
		variants = append(variants, variant{name, "", end},
			variant{"long line " + name, strings.Repeat("x", 2000), end},
			variant{"oversize " + name, strings.Repeat("y\r\n", 12<<20/3), end})
	}
	for _, v := range variants {
		prefix, end := v.prefix, v.end
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			conn, read, inbox, dir := rfcDial(t, true)
			send(t, conn, "MAIL FROM:<sender@example.org>")
			expect(t, read, "250 ")
			send(t, conn, "RCPT TO:<alice@localhost>")
			expect(t, read, "250 ")
			send(t, conn, "DATA")
			expect(t, read, "354")
			if _, err := io.WriteString(conn, "Subject: hi\r\n\r\n"+prefix+"body"+end+smuggled); err != nil {
				t.Fatal(err)
			}
			_, _ = io.WriteString(conn, "QUIT\r\n")
			replies := readAll(conn) + drain(read)

			ctx := context.Background()
			acc, _, err := dir.ResolveEmail(ctx, "alice@localhost")
			if err != nil {
				t.Fatal(err)
			}
			msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range msgs {
				raw, err := inbox.LoadRaw(ctx, m.Meta)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), "Return-Path: <ceo@victim.example>") {
					t.Fatalf("smuggled message delivered; replies %q", replies)
				}
			}
		})
	}
}

// drain returns whatever the buffered reader still holds.
func drain(r *bufio.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, int64(r.Buffered())))
	return string(b)
}

// STARTTLS command injection, CVE-2011-0411 (Postfix) and the 2011 family (Exim, Cyrus, Courier...):
// plaintext commands pipelined after STARTTLS must be thrown away, never run inside the TLS session.
func TestCVE_2011_0411_STARTTLSInjection(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, inbox, dir := openSMTPTestStore(t, ctx)
	certFile, keyFile := tlstest.WritePEM(t, t.TempDir(), []string{"localhost"})
	certs, err := tlsload.Load(certFile, keyFile, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := smtp.NewServer(log.New("error"), ln.Addr().String(), dir, inbox, nil, "", "", smtp.Options{Certs: certs})
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = srv.ServeListener(sctx, ln) }()
	time.Sleep(20 * time.Millisecond)
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := bufio.NewReader(conn)
	expect(t, read, "220")
	send(t, conn, "EHLO attacker.example")
	readEHLO(t, read, "STARTTLS")
	// One write: STARTTLS plus an injected command the attacker hopes runs after the handshake.
	if _, err := io.WriteString(conn, "STARTTLS\r\nRSET\r\nNOOP injected\r\n"); err != nil {
		t.Fatal(err)
	}
	expect(t, read, "220")
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	tread := bufio.NewReader(tlsConn)
	send(t, tlsConn, "EHLO client.example")
	// The first reply inside TLS must answer our EHLO, not the injected RSET/NOOP.
	expect(t, tread, "250-")
}

// Recipient flooding: Exim CVE-2020-28017 (integer overflow on a huge RCPT count) and RFC 5321 7.8
// address harvesting. A transaction takes a bounded number of recipients, and a client that mostly
// probes unknown addresses is cut off.
func TestRecipientFloodLimits(t *testing.T) {
	t.Parallel()
	t.Run("too many recipients", func(t *testing.T) {
		t.Parallel()
		conn, read, _, _ := rfcDial(t, true)
		send(t, conn, "MAIL FROM:<sender@example.org>")
		expect(t, read, "250 ")
		for i := range smtp.MaxRecipients {
			send(t, conn, "RCPT TO:<alice@localhost>")
			if line, _ := read.ReadString('\n'); !strings.HasPrefix(line, "250 ") {
				t.Fatalf("RCPT %d: %q", i+1, line)
			}
		}
		send(t, conn, "RCPT TO:<alice@localhost>")
		expect(t, read, "452 4.5.3")
	})
	t.Run("harvesting", func(t *testing.T) {
		t.Parallel()
		conn, read, _, _ := rfcDial(t, true)
		send(t, conn, "MAIL FROM:<sender@example.org>")
		expect(t, read, "250 ")
		var last string
		for range smtp.MaxBadRecipients + 5 {
			send(t, conn, "RCPT TO:<guess@localhost>")
			if last, _ = read.ReadString('\n'); !strings.HasPrefix(last, "550 ") {
				break
			}
		}
		if !strings.HasPrefix(last, "421 ") {
			t.Fatalf("after %d unknown recipients: %q, want 421 and close", smtp.MaxBadRecipients, last)
		}
		if _, err := read.ReadString('\n'); err == nil {
			t.Fatal("connection still open")
		}
	})
}

// Command flooding (Exim smtp_max_unknown_commands): a client that only sends garbage is cut off.
func TestUnknownCommandFlood(t *testing.T) {
	t.Parallel()
	conn, read, _, _ := rfcDial(t, true)
	var last string
	for range smtp.MaxUnknownCommands + 5 {
		send(t, conn, "XGARBAGE")
		if last, _ = read.ReadString('\n'); !strings.HasPrefix(last, "500 ") {
			break
		}
	}
	if !strings.HasPrefix(last, "421 ") {
		t.Fatalf("after %d unknown commands: %q, want 421", smtp.MaxUnknownCommands, last)
	}
}

// SMTP smuggling through BDAT (RFC 3030 2: after a failed BDAT the server MUST accept and discard
// its data before replying). A chunk left unread by an early refusal (sender refused in the same
// pipelined group, no transaction, chunk over the size limit) was parsed as commands: a relay
// forwarding attacker-controlled content would run the attacker's transaction as its own.
func TestSMTPSmugglingThroughBDAT(t *testing.T) {
	t.Parallel()
	const smuggled = "RSET\r\nMAIL FROM:<ceo@victim.example>\r\nRCPT TO:<alice@localhost>\r\nDATA\r\nSubject: smuggled\r\n\r\nforged\r\n.\r\n"
	for name, group := range map[string]string{
		"failed MAIL in group": "MAIL FROM:<not an address>\r\nRCPT TO:<alice@localhost>\r\nBDAT %d LAST\r\n" + smuggled,
		"no transaction":       "BDAT %d LAST\r\n" + smuggled,
		"over the size limit":  "MAIL FROM:<sender@example.org>\r\nRCPT TO:<alice@localhost>\r\nBDAT %d LAST\r\n" + smuggled,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			conn, read, inbox, dir := rfcDial(t, true)
			size := len(smuggled)
			if name == "over the size limit" {
				size = 20 << 20 // past the 10 MiB default: discarded, padding follows the payload
			}
			payload := fmt.Sprintf(group, size)
			if pad := size - len(smuggled); pad > 0 {
				payload += strings.Repeat("x", pad)
			}
			go func() { _, _ = io.WriteString(conn, payload+"NOOP\r\nQUIT\r\n") }()
			replies := readAll(conn) + drain(read)
			if !strings.Contains(replies, "\r\n250 2.0.0 Ok\r\n221") {
				t.Fatalf("session out of step after the chunk: %q", replies)
			}

			ctx := context.Background()
			acc, _, err := dir.ResolveEmail(ctx, "alice@localhost")
			if err != nil {
				t.Fatal(err)
			}
			msgs, err := inbox.List(ctx, acc.ID, mail.InboxMailboxID)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range msgs {
				raw, _ := inbox.LoadRaw(ctx, m.Meta)
				if strings.Contains(string(raw), "ceo@victim.example") {
					t.Fatalf("smuggled message delivered; replies %q", replies)
				}
			}
		})
	}
}
