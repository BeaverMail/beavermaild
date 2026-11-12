package imap_test

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type literalClient struct {
	t *testing.T
	c net.Conn
	r *bufio.Reader
}

func dialLiteral(t *testing.T, addr string) *literalClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	lc := &literalClient{t: t, c: c, r: bufio.NewReader(c)}
	lc.line("* OK")
	return lc
}

func (lc *literalClient) write(s string) {
	lc.t.Helper()
	if _, err := lc.c.Write([]byte(s)); err != nil {
		lc.t.Fatal(err)
	}
}

// line reads one line and fails unless it starts with prefix.
func (lc *literalClient) line(prefix string) string {
	lc.t.Helper()
	l, err := lc.r.ReadString('\n')
	if err != nil {
		lc.t.Fatalf("want %q: %v", prefix, err)
	}
	if !strings.HasPrefix(l, prefix) {
		lc.t.Fatalf("line %q want prefix %q", l, prefix)
	}
	return l
}

// until reads up to the tagged reply of tag and returns the lines before it and that reply.
func (lc *literalClient) until(tag string) (untagged []string, reply string) {
	lc.t.Helper()
	for {
		l, err := lc.r.ReadString('\n')
		if err != nil {
			lc.t.Fatalf("waiting for %s: %v (after %q)", tag, err, untagged)
		}
		if strings.HasPrefix(l, tag+" ") {
			return untagged, l
		}
		untagged = append(untagged, l)
	}
}

// lit is a non-synchronizing literal (RFC 7888).
func lit(s string) string { return "{" + strconv.Itoa(len(s)) + "+}\r\n" + s }

// RFC 3501 4.3 / 9: a string argument may be a literal in every command. Only SEARCH, SORT and
// THREAD used to read them: elsewhere the literal bytes ran as the next command, before login too.
func TestLiteralBytesNeverRunAsCommands(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	// Before login: an unknown command and LOGIN both swallow their literals.
	lc := dialLiteral(t, ln.Addr().String())
	lc.write("a1 XFOO " + lit("z1 LOGIN alice@localhost beaver\r\n") + "\r\n")
	if _, reply := lc.until("a1"); !strings.HasPrefix(reply, "a1 BAD") {
		t.Fatalf("unknown command: %q", reply)
	}
	lc.write("a2 NOOP\r\n")
	if pre, reply := lc.until("a2"); len(pre) != 0 || !strings.HasPrefix(reply, "a2 OK") {
		t.Fatalf("smuggled command answered: %q %q", pre, reply)
	}

	lc.write("l1 LOGIN alice@localhost beaver\r\n")
	lc.line("l1 OK")
	lc.write("c1 CREATE " + lit("z1 CREATE pwned") + "\r\n")
	if pre, reply := lc.until("c1"); len(pre) != 0 || !strings.HasPrefix(reply, "c1 OK") {
		t.Fatalf("CREATE with literal: %q %q", pre, reply)
	}
	lc.write(`l2 LIST "" *` + "\r\n")
	list, _ := lc.until("l2")
	joined := strings.Join(list, "")
	if !strings.Contains(joined, `"z1 CREATE pwned"`) || strings.Contains(joined, `"pwned"`) {
		t.Fatalf("LIST after literal CREATE: %q", list)
	}
}

// Every command naming a mailbox takes it as a literal; quoted strings resolve \" and \\, and LIST
// and STATUS quote them back the same way.
func TestMailboxArgumentsAsLiteralsAndEscapes(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	lc := dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN alice@localhost beaver\r\n")
	lc.line("l1 OK")

	name := `my "box\x`
	quoted := `"my \"box\\x"`
	msg := "From: a@example.org\r\n\r\nz\r\n"
	steps := []struct{ tag, cmd, want string }{
		{"c1", "CREATE " + lit(name), "OK"},
		{"c2", "CREATE " + quoted, "NO"}, // same name, other form
		{"s1", "STATUS " + lit(name) + " (MESSAGES)", "OK"},
		{"a1", "APPEND " + lit(name) + " (\\Seen) " + lit(msg), "OK"},
		{"x1", "EXAMINE " + quoted, "OK"},
		{"x2", "SELECT " + lit(name), "OK"},
		{"p1", "COPY 1 " + lit(name), "OK"},
		{"u1", "SUBSCRIBE " + lit(name), "OK"},
		{"u2", "UNSUBSCRIBE " + quoted, "OK"},
		{"q1", "GETQUOTAROOT " + lit(name), "OK"},
		{"r1", "RENAME " + lit(name) + " " + lit(name+" 2"), "OK"},
		{"d1", "DELETE " + quoted, "NO"}, // renamed away
	}
	var statusLine string
	for _, st := range steps {
		lc.write(st.tag + " " + st.cmd + "\r\n")
		pre, reply := lc.until(st.tag)
		if !strings.HasPrefix(reply, st.tag+" "+st.want) {
			t.Fatalf("%s: %q (want %s)", st.cmd, reply, st.want)
		}
		if st.tag == "s1" {
			statusLine = strings.Join(pre, "")
		}
	}
	if !strings.Contains(statusLine, "* STATUS "+quoted+" (MESSAGES 0)") {
		t.Fatalf("STATUS name not quoted back: %q", statusLine)
	}
	lc.write("l2 LIST " + lit("") + " " + lit("my*") + "\r\n")
	list, reply := lc.until("l2")
	if !strings.HasPrefix(reply, "l2 OK") || len(list) != 1 || !strings.HasSuffix(list[0], `"my \"box\\x 2"`+"\r\n") {
		t.Fatalf("LIST: %q %q", list, reply)
	}
}

// LOGIN with a literal password, synchronizing and not: passwords with " or \ or 8-bit bytes
// are sent this way, and the server used to compare the password with the text "{6}".
func TestLoginWithLiteralPassword(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	lc := dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN {15}\r\n")
	lc.line("+ ")
	lc.write("alice@localhost {6}\r\n")
	lc.line("+ ")
	lc.write("beaver\r\n")
	lc.line("l1 OK")

	lc = dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN " + lit("alice@localhost") + " " + lit("beaver") + "\r\n")
	lc.line("l1 OK")
}

// Before login a literal may only carry a user name and a password: a larger one is refused
// before upload (synchronizing) or ends the connection (non-synchronizing, already on its way).
func TestPreAuthLiteralCap(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()

	lc := dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN alice {100000}\r\n")
	lc.line("l1 BAD")
	lc.write("n1 NOOP\r\n")
	lc.line("n1 OK")

	lc = dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN alice {100000+}\r\n")
	go func() { _, _ = lc.c.Write([]byte(strings.Repeat("a", 100000))) }()
	lc.line("* BYE [TOOBIG]")
	if _, err := io.ReadAll(lc.r); err != nil && !strings.Contains(err.Error(), "reset") {
		t.Fatalf("connection not closed: %v", err)
	}
}

// NUL fits no plain literal (RFC 3501 9 CHAR8; RFC 3516 4.3): APPEND refuses it outside a
// literal8, and a stored message holding NUL (SMTP delivers them) is sent with NUL masked, the
// literal length unchanged, on the streamed and the in-memory FETCH paths alike.
func TestNULNeverInPlainLiterals(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	lc := dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN alice@localhost beaver\r\n")
	lc.line("l1 OK")

	msg := "X-Bad: a\x00b\r\nSubject: nul\r\n\r\nbody\r\n"
	lc.write("a1 APPEND INBOX " + lit(msg) + "\r\n")
	lc.line("a1 BAD")
	lc.write("a2 APPEND INBOX {" + strconv.Itoa(len(msg)) + "}\r\n")
	lc.line("+ ")
	lc.write(msg + "\r\n")
	lc.line("a2 BAD")
	lc.write("n1 NOOP\r\n")
	lc.line("n1 OK")

	lc.write("a3 APPEND INBOX ~{" + strconv.Itoa(len(msg)) + "+}\r\n" + msg + "\r\n")
	lc.until("a3")
	lc.write("s1 SELECT INBOX\r\n")
	lc.until("s1")
	for _, item := range []string{"BODY.PEEK[]", "BODY.PEEK[HEADER]", "RFC822.HEADER", "BODY.PEEK[]<0.12>"} {
		lc.write("f1 FETCH 1 " + item + "\r\n")
		head := lc.line("* 1 FETCH")
		i := strings.LastIndexByte(head, '{')
		n, err := strconv.Atoi(strings.TrimSuffix(head[i+1:], "}\r\n"))
		if err != nil || strings.Contains(head, "~{") {
			t.Fatalf("%s: response %q", item, head)
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(lc.r, data); err != nil {
			t.Fatal(err)
		}
		if strings.IndexByte(string(data), 0) >= 0 || !strings.Contains(string(data), "a\x80b") {
			t.Fatalf("%s: literal %q", item, data)
		}
		lc.until("f1")
	}
}
