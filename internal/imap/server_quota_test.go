package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestIMAPQuotaGet(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	inbox.SetQuotaDefaults(mail.QuotaDefaults{StorageBytes: 4096, Messages: 100})
	if _, err := inbox.Deliver(ctx, accID, []byte("From: a@b\r\n\r\nquota\r\n")); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	read := bufio.NewReader(conn)

	expectPrefix(t, read, "* OK")
	send(t, conn, "q1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "q1 OK")
	send(t, conn, "q2 CAPABILITY")
	line, _ := read.ReadString('\n')
	if !strings.Contains(line, "QUOTA") {
		t.Fatalf("caps %q", line)
	}
	expectPrefix(t, read, "q2 OK")

	send(t, conn, "q3 GETQUOTAROOT INBOX")
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "QUOTAROOT INBOX") || !strings.Contains(line, `""`) {
		t.Fatalf("quotaroot %q", line)
	}
	expectPrefix(t, read, "q3 OK")

	send(t, conn, `q4 GETQUOTA ""`)
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "QUOTA") || !strings.Contains(line, "STORAGE") {
		t.Fatalf("quota %q", line)
	}
	expectPrefix(t, read, "q4 OK")
}
