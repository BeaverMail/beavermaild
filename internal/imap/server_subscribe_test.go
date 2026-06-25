package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPSubscribeLsub(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	created, err := inbox.CreateMailbox(ctx, accID, "Work")
	if err != nil {
		t.Fatal(err)
	}
	if created.Subscribed {
		t.Fatal("custom folder starts unsubscribed")
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "u1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "u1 OK")

	send(t, conn, `u2 LSUB "" "*"`)
	var lsubCount int
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "* LSUB") {
			lsubCount++
			if strings.Contains(line, "Work") {
				t.Fatalf("work not subscribed yet: %q", line)
			}
			continue
		}
		if strings.HasPrefix(line, "u2 OK") {
			break
		}
	}
	if lsubCount < 4 {
		t.Fatalf("expected system folders in LSUB, got %d", lsubCount)
	}

	send(t, conn, "u3 SUBSCRIBE Work")
	expectPrefix(t, read, "u3 OK")
	send(t, conn, `u4 LSUB "" "Work"`)
	line, err := read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, "Work") {
		t.Fatalf("subscribed work %q", line)
	}
	expectPrefix(t, read, "u4 OK")

	send(t, conn, "u5 UNSUBSCRIBE INBOX")
	expectPrefix(t, read, "u5 OK")
	send(t, conn, `u6 LSUB "" "INBOX"`)
	for {
		line, err = read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "* LSUB") {
			t.Fatalf("inbox unsubscribed: %q", line)
		}
		if strings.HasPrefix(line, "u6 OK") {
			break
		}
	}

	send(t, conn, `u7 LIST "" "*"`)
	listCount := 0
	for {
		line, err = read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "* LIST") {
			listCount++
			continue
		}
		if strings.HasPrefix(line, "u7 OK") {
			break
		}
	}
	if listCount < 5 {
		t.Fatalf("LIST still shows all folders, got %d", listCount)
	}
}
