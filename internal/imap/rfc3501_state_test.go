package imap_test

import (
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// RFC 3501 2.2.1, 6.1.1, 6.2, 6.2.2 and RFC 4616 2: login commands only before login, capabilities
// that match the state, PLAIN as base64 of three fields, authzid only for oneself.
func TestLoginStateAndPLAIN(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	lc := dialLiteral(t, ln.Addr().String())

	for _, st := range []struct{ send, want string }{
		{"lonelytag", "lonelytag BAD"},        // 2.2.1: a tag alone is answered
		{"a1 AUTHENTICATE CRAM-MD5", "a1 NO"}, // 6.2.2: unsupported mechanism
		{"a2 AUTHENTICATE PLAIN " + b64("bob@localhost\x00alice@localhost\x00beaver"), "a2 NO [AUTHORIZATIONFAILED]"},
		{"a3 AUTHENTICATE PLAIN !!!notbase64", "a3 BAD"},                        // 6.2.2: base64
		{"a4 AUTHENTICATE PLAIN " + b64("alice@localhost\x00beaver"), "a4 BAD"}, // RFC 4616: three fields
	} {
		lc.write(st.send + "\r\n")
		lc.line(st.want)
	}
	lc.write("a5 AUTHENTICATE PLAIN\r\n")
	lc.line("+ ")
	lc.write("*\r\n")
	lc.line("a5 BAD") // 6.2.2: "*" cancels with BAD

	lc.write("c1 CAPABILITY\r\n")
	if caps := lc.line("* CAPABILITY"); !strings.Contains(caps, "AUTH=PLAIN") {
		t.Fatalf("pre-login capabilities: %q", caps)
	}
	lc.line("c1 OK")
	lc.write("a6 AUTHENTICATE PLAIN " + b64("alice@localhost\x00alice@localhost\x00beaver") + "\r\n")
	lc.line("a6 OK") // authzid naming oneself is fine

	lc.write("c2 CAPABILITY\r\n")
	if caps := lc.line("* CAPABILITY"); strings.Contains(caps, " AUTH=") || strings.Contains(caps, "STARTTLS") || strings.Contains(caps, "SASL-IR") {
		t.Fatalf("login capabilities offered after login: %q", caps)
	}
	lc.line("c2 OK")
	for _, cmd := range []string{"l1 LOGIN alice@localhost beaver", "l2 AUTHENTICATE PLAIN " + b64("\x00alice@localhost\x00beaver"), "l3 STARTTLS"} {
		lc.write(cmd + "\r\n")
		lc.line(cmd[:2] + " BAD")
	}
}

// RFC 3501 9 (seq-number, section-part, date-day-fixed), 6.3.5, 6.3.11, 7.1 and RFC 4315 3.
// seq-number is BAD past EXISTS for COPY, FETCH and STORE (and MOVE), the commands its note names.
func TestRFC3501MessagesAndMailboxes(t *testing.T) {
	t.Parallel()
	_, _, _, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	lc := dialLiteral(t, ln.Addr().String())
	lc.write("l1 LOGIN alice@localhost beaver\r\n")
	lc.line("l1 OK")
	msg := "From: a@example.org\r\n\r\nz\r\n"

	steps := []struct{ cmd, want string }{
		{"CREATE Box", "OK"},
		{"SELECT Box", "OK"},
		{"FETCH 1:* FLAGS", "BAD"}, // "*" in an empty mailbox
		{`APPEND Box ($Label NonJunk \Seen) " 5-Nov-2026 10:00:00 +0000" ` + lit(msg), "OK"},
		{"APPEND Box {0+}\r\n", "NO"},
		{"APPEND Box (\\Bogus) " + lit(msg), "BAD"},
		{"NOOP", "OK"},
		{"FETCH 9 FLAGS", "BAD"},
		{"STORE 9 +FLAGS (\\Seen)", "BAD"},
		{"COPY 9 INBOX", "BAD"},
		{"SEARCH 9", "OK"}, // in SEARCH a sequence set is a key: no such message matches nothing
		{"FETCH 1 BODY.PEEK[0]", "BAD"},
		{"FETCH 1 BODY.PEEK[1.MIME.X]", "BAD"},
		{"UID COPY 999 INBOX", "OK COPY completed"}, // no message: no COPYUID with empty sets
		{"CREATE Box/a/b", "OK"},
		{"RENAME Box Moved/Deeper", "OK"},
		{"EXAMINE Moved/Deeper", "OK"},
	}
	var fetchFlags, examine string
	for i, st := range steps {
		tag := "t" + strconv.Itoa(i)
		lc.write(tag + " " + st.cmd + "\r\n")
		pre, reply := lc.until(tag)
		if !strings.HasPrefix(reply, tag+" "+st.want) {
			t.Fatalf("%s: %q, want %s", st.cmd, reply, st.want)
		}
		if st.cmd == "NOOP" {
			lc.write("f1 FETCH 1 (FLAGS INTERNALDATE)\r\n")
			fp, _ := lc.until("f1")
			fetchFlags = strings.Join(fp, "")
		}
		if strings.HasPrefix(st.cmd, "EXAMINE") {
			examine = strings.Join(pre, "")
		}
	}
	if !strings.Contains(fetchFlags, "$Label") || !strings.Contains(fetchFlags, "NonJunk") || !strings.Contains(fetchFlags, `05-Nov-2026`) {
		t.Fatalf("APPEND flags or date lost: %q", fetchFlags)
	}
	if !strings.Contains(examine, "[PERMANENTFLAGS ()]") {
		t.Fatalf("read-only mailbox offers permanent flags: %q", examine)
	}
	lc.write(`l2 LIST "" "Moved*"` + "\r\n")
	list, _ := lc.until("l2")
	if got := strings.Join(list, ""); !strings.Contains(got, `"Moved/Deeper/a/b"`) || !strings.Contains(got, `(\HasChildren) "/" "Moved"`+"\r\n") {
		t.Fatalf("RENAME did not take the children or create the superior: %q", list)
	}
}
