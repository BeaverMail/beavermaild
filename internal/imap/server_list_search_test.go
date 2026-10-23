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
		// CREATE Archive/2024 also created Archive (RFC 3501 §6.3.3); "Archive%" matches it.
		{`r5 LIST "Archive" "%"`, `"Archive"`},
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

func TestIMAPListExtended(t *testing.T) {
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
	send(t, conn, "x1 LOGIN alice@localhost beaver")
	expectPrefix(t, read, "x1 OK")
	// RFC 5258 §5 example tree: Fruit exists but is not subscribed.
	for i, c := range []string{
		"CREATE Fruit/Banana", "CREATE Vegetable", "CREATE Vegetable/Broccoli",
		"UNSUBSCRIBE Fruit", "SUBSCRIBE Fruit/Banana", "SUBSCRIBE Vegetable", "SUBSCRIBE Vegetable/Broccoli",
	} {
		tag := "s" + string(rune('a'+i))
		send(t, conn, tag+" "+c)
		expectPrefix(t, read, tag+" OK")
	}

	list := func(tag, args string) map[string]string {
		t.Helper()
		send(t, conn, tag+" "+args)
		got := map[string]string{}
		for {
			line, err := read.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, tag+" ") {
				if !strings.HasPrefix(line, tag+" OK") {
					t.Fatalf("%s: %q", args, line)
				}
				return got
			}
			rest := line[strings.Index(line, `"/" `)+4:]
			name, _, _ := strings.Cut(rest, " ")
			if strings.HasPrefix(rest, `"`) {
				name = rest[1 : 1+strings.IndexByte(rest[1:], '"')]
			}
			got[name] = line
		}
	}

	got := list("x2", `LIST (SUBSCRIBED RECURSIVEMATCH) "" "%"`)
	if l := got["Fruit"]; strings.Contains(l, `\Subscribed`) || !strings.HasSuffix(l, `("CHILDINFO" ("SUBSCRIBED"))`) {
		t.Fatalf("Fruit: %q", got)
	}
	if l := got["Vegetable"]; !strings.Contains(l, `\Subscribed`) || !strings.HasSuffix(l, `("CHILDINFO" ("SUBSCRIBED"))`) {
		t.Fatalf("Vegetable: %q", got)
	}

	got = list("x3", `LIST (SUBSCRIBED RECURSIVEMATCH) "" "*"`)
	if _, ok := got["Fruit"]; ok {
		t.Fatalf("Fruit has no unmatched subscribed child under *: %q", got)
	}
	for name, l := range got {
		if strings.Contains(l, "CHILDINFO") {
			t.Fatalf("%s: unexpected CHILDINFO %q", name, l)
		}
	}
	if _, ok := got["Vegetable/Broccoli"]; !ok {
		t.Fatalf("Broccoli missing: %q", got)
	}

	got = list("x4", `LIST "" ("INBOX" "Vegetable" "Nope")`)
	if len(got) != 2 || got["INBOX"] == "" || got["Vegetable"] == "" {
		t.Fatalf("multiple patterns: %q", got)
	}

	got = list("x5", `LIST (SPECIAL-USE) "" "*" RETURN (SPECIAL-USE)`)
	if len(got) != 3 || !strings.Contains(got["Sent"], `\Sent`) || !strings.Contains(got["Trash"], `\Trash`) || !strings.Contains(got["Drafts"], `\Drafts`) {
		t.Fatalf("special-use selection: %q", got)
	}

	// Deleting a parent leaves its child: the parent is then listed but not selectable.
	send(t, conn, "sz DELETE Fruit")
	expectPrefix(t, read, "sz OK")
	got = list("x6", `LIST "" "%"`)
	if !strings.Contains(got["Fruit"], `\Noselect`) || strings.Contains(got["Fruit"], `\NonExistent`) {
		t.Fatalf("plain LIST missing parent: %q", got)
	}
	got = list("x6b", `LIST () "" "%"`)
	if !strings.Contains(got["Fruit"], `\NonExistent`) {
		t.Fatalf("extended LIST missing parent: %q", got)
	}

	// RFC 3501 §6.3.9: LSUB "%" returns an unsubscribed parent of a subscribed child as \Noselect.
	send(t, conn, "sy CREATE Tools/Hammer")
	expectPrefix(t, read, "sy OK")
	send(t, conn, "sx UNSUBSCRIBE Tools")
	expectPrefix(t, read, "sx OK")
	got = list("x6c", `LSUB "" "%"`)
	if l := got["Tools"]; !strings.Contains(l, `\Noselect`) || strings.Contains(l, `\Subscribed`) {
		t.Fatalf("LSUB parent: %q", got)
	}
	if _, ok := got["Tools/Hammer"]; ok {
		t.Fatalf("LSUB %% returned child: %q", got)
	}
	got = list("x6d", `LSUB "" "*"`)
	if _, ok := got["Tools"]; ok {
		t.Fatalf("LSUB * returned unsubscribed parent: %q", got)
	}
	if _, ok := got["Tools/Hammer"]; !ok {
		t.Fatalf("LSUB * missing child: %q", got)
	}

	for _, bad := range []string{`x7 LIST (BOGUS) "" "*"`, `x8 LIST (RECURSIVEMATCH) "" "*"`, `x9 LSUB "" ("*")`} {
		send(t, conn, bad)
		expectPrefix(t, read, strings.Fields(bad)[0]+" BAD")
	}
}
