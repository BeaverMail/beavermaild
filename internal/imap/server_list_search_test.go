package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestIMAPListPatternAndSpecialUse(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	raw := []byte("From: smoke@example.com\r\nSubject: list test\r\n\r\nbody\r\n")
	if _, err := inbox.Deliver(ctx, accID, raw); err != nil {
		t.Fatal(err)
	}

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "l1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "l1 OK")
	send(t, conn, "l2 CAPABILITY")
	line, _ := read.ReadString('\n')
	if !strings.Contains(line, "SPECIAL-USE") {
		t.Fatalf("caps %q", line)
	}
	expectPrefix(t, read, "l2 OK")

	send(t, conn, `l3 LIST "" "Sent"`)
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(line, `\Sent`) || !strings.Contains(line, "Sent") {
		t.Fatalf("sent list %q", line)
	}
	expectPrefix(t, read, "l3 OK")

	send(t, conn, `l4 LIST "" "NoSuch*"`)
	line, err = read.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(line, "* LIST") {
		t.Fatalf("unexpected list %q", line)
	}
	if !strings.HasPrefix(line, "l4 OK") {
		expectPrefix(t, read, "l4 OK")
	}

	send(t, conn, "l5 SELECT INBOX")
	expectPrefix(t, read, "* FLAGS")
	expectPrefix(t, read, "* 1 EXISTS")
	expectPrefix(t, read, "* 1 RECENT")
	expectSelectOK(t, read)
	expectPrefix(t, read, "l5 OK")

	send(t, conn, `l6 SEARCH SUBJECT list`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l6 OK")
	send(t, conn, `l7 SEARCH FROM smoke@example.com`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l7 OK")
	send(t, conn, `l8 SEARCH SINCE 01-Jan-2020`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l8 OK")
	send(t, conn, `l9 SEARCH TEXT list`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l9 OK")
	send(t, conn, `l10 SEARCH BODY body`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l10 OK")
	send(t, conn, `l11 SEARCH LARGER 10`)
	expectPrefix(t, read, "* SEARCH 1")
	expectPrefix(t, read, "l11 OK")
}

func TestIMAPListEmptyPatternReturnsDelimiter(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "d1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "d1 OK")

	for _, tc := range []struct{ cmd, want string }{
		{`d2 LIST "" ""`, `* LIST (\Noselect) "/" ""`},
		{`d3 LIST "Archive/2024" ""`, `* LIST (\Noselect) "/" "Archive/"`},
	} {
		send(t, conn, tc.cmd)
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.TrimRight(line, "\r\n"); got != tc.want {
			t.Fatalf("%s: got %q, want %q", tc.cmd, got, tc.want)
		}
		expectPrefix(t, read, strings.Fields(tc.cmd)[0]+" OK")
	}
}

func TestIMAPListJoinsReferenceAndPattern(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "r1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "r1 OK")
	send(t, conn, "r2 CREATE Archive/2024")
	expectPrefix(t, read, "r2 OK")

	for _, tc := range []struct{ cmd, want string }{
		{`r3 LIST "Archive/" "%"`, `"Archive/2024"`},
		{`r4 LIST "" "Archive/*"`, `"Archive/2024"`},
		{`r5 LIST "Archive" "%"`, ``},
	} {
		tag := strings.Fields(tc.cmd)[0]
		send(t, conn, tc.cmd)
		var got []string
		for {
			line, err := read.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(line, tag+" ") {
				if !strings.HasPrefix(line, tag+" OK") {
					t.Fatalf("%s: %q", tc.cmd, line)
				}
				break
			}
			got = append(got, strings.TrimRight(line, "\r\n"))
		}
		if tc.want == "" {
			if len(got) != 0 {
				t.Fatalf("%s: unexpected %q", tc.cmd, got)
			}
			continue
		}
		if len(got) != 1 || !strings.HasSuffix(got[0], tc.want) {
			t.Fatalf("%s: got %q, want one line ending %s", tc.cmd, got, tc.want)
		}
	}
}

func TestIMAPCreateUnderInbox(t *testing.T) {
	t.Parallel()

	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	read := bufio.NewReader(conn)
	expectPrefix(t, read, "* OK")
	send(t, conn, "c1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "c1 OK")
	send(t, conn, "c2 CREATE INBOX/Lists")
	expectPrefix(t, read, "c2 OK")

	send(t, conn, `c3 LIST "" "INBOX*"`)
	got := map[string]string{}
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "c3 ") {
			if !strings.HasPrefix(line, "c3 OK") {
				t.Fatalf("list: %q", line)
			}
			break
		}
		line = strings.TrimRight(line, "\r\n")
		got[line[strings.LastIndexByte(line, ' ')+1:]] = line
	}
	if !strings.Contains(got["INBOX"], `\HasChildren`) {
		t.Fatalf("INBOX should have children: %q", got)
	}
	if _, ok := got[`"INBOX/Lists"`]; !ok {
		t.Fatalf("INBOX/Lists missing: %q", got)
	}

	send(t, conn, "c4 SELECT INBOX/Lists")
	for {
		line, err := read.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "c4 ") {
			if !strings.HasPrefix(line, "c4 OK") {
				t.Fatalf("select: %q", line)
			}
			break
		}
	}
}
