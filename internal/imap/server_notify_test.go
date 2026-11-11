package imap_test

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

// TestIMAPNotify checks RFC 5465: argument checks, initial STATUS, and events pushed while the
// client sends nothing: STATUS for a watched mailbox, EXISTS and FETCH for the selected one, LIST
// for a mailbox created elsewhere, and none for the session's own CREATE.
func TestIMAPNotify(t *testing.T) {
	t.Parallel()

	ctx, accID, inbox, ln, cleanup := startIMAPTestServer(t)
	defer cleanup()
	if _, err := inbox.CreateMailbox(ctx, accID, "Watch", false); err != nil {
		t.Fatal(err)
	}
	watch, err := inbox.ResolveMailbox(ctx, accID, "Watch")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inbox.Append(ctx, accID, watch.ID, []byte("Subject: w1\r\n\r\nw\r\n"), 0, 0); err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	r := bufio.NewReader(c)
	until := func(tag string) ([]string, string) {
		var lines []string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			line = strings.TrimRight(line, "\r\n")
			if strings.HasPrefix(line, tag+" ") {
				return lines, line
			}
			lines = append(lines, line)
		}
	}
	readLine := func() string {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	expectPrefix(t, r, "* OK")
	send(t, c, "l1 LOGIN alice@localhost beaver")
	until("l1")
	send(t, c, "s1 SELECT INBOX")
	until("s1")

	for cmd, want := range map[string]string{
		"b1 NOTIFY SET (personal (MessageNew))":                 "b1 BAD", // MessageNew needs MessageExpunge
		"b2 NOTIFY SET (personal (FlagChange))":                 "b2 BAD",
		"b3 NOTIFY SET (selected (MailboxName))":                "b3 BAD", // selected takes message events only
		"b4 NOTIFY SET (personal (AnnotationChange))":           "b4 NO [BADEVENT (",
		"b5 NOTIFY SET (selected NONE) (selected-delayed NONE)": "b5 BAD",
		"b6 NOTIFY GET": "b6 BAD",
	} {
		tag, _, _ := strings.Cut(cmd, " ")
		send(t, c, cmd)
		if _, tagged := until(tag); !strings.HasPrefix(tagged, want) {
			t.Errorf("%s: %q, want %q", cmd, tagged, want)
		}
	}

	send(t, c, "n1 NOTIFY SET STATUS (selected (MessageNew (UID) MessageExpunge FlagChange)) "+
		"(mailboxes Watch (MessageNew MessageExpunge)) (personal (MailboxName SubscriptionChange))")
	lines, tagged := until("n1")
	if !strings.HasPrefix(tagged, "n1 OK") || len(lines) != 1 || !strings.HasPrefix(lines[0], `* STATUS "Watch" (MESSAGES 1 UIDNEXT 2 UIDVALIDITY `) {
		t.Fatalf("notify set status: %q %q", lines, tagged)
	}

	// Pushed without any command from the client.
	if _, err := inbox.Append(ctx, accID, watch.ID, []byte("Subject: w2\r\n\r\nw\r\n"), 0, 0); err != nil {
		t.Fatal(err)
	}
	if line := readLine(); line != `* STATUS "Watch" (MESSAGES 2 UIDNEXT 3)` {
		t.Fatalf("watched mailbox: %q", line)
	}
	if _, err := inbox.Deliver(ctx, accID, []byte("Subject: in\r\n\r\nnew\r\n")); err != nil {
		t.Fatal(err)
	}
	var got []string
	for len(got) < 2 {
		if line := readLine(); !strings.HasSuffix(line, " RECENT") {
			got = append(got, line)
		}
	}
	if got[0] != "* 1 EXISTS" || got[1] != "* 1 FETCH (UID 1)" {
		t.Fatalf("selected mailbox: %q", got)
	}
	if _, err := inbox.CreateMailbox(ctx, accID, "Elsewhere", false); err != nil {
		t.Fatal(err)
	}
	if line := readLine(); !strings.HasPrefix(line, "* LIST (") || !strings.HasSuffix(line, `"/" "Elsewhere"`) {
		t.Fatalf("mailbox created elsewhere: %q", line)
	}

	// The session's own CREATE is not reported back to it.
	send(t, c, "c1 CREATE Own")
	until("c1")
	time.Sleep(1500 * time.Millisecond) // more than one poll
	send(t, c, "c2 NOOP")
	if lines, _ := until("c2"); len(lines) != 0 {
		t.Fatalf("own CREATE reported: %q", lines)
	}
	send(t, c, "c3 NOTIFY NONE")
	until("c3")
}
