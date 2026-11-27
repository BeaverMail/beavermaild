package mail

import (
	"bytes"
	netmail "net/mail"
	"strings"
	"testing"
)

func TestParseNotify(t *testing.T) {
	t.Parallel()

	flags, ok := ParseNotify("FAILURE,DELAY,SUCCESS")
	if !ok || flags&(NotifyFailure|NotifyDelay|NotifySuccess) != NotifyFailure|NotifyDelay|NotifySuccess {
		t.Fatalf("flags=%v", flags)
	}
	flags, ok = ParseNotify("NEVER")
	if !ok || flags != NotifyNever {
		t.Fatalf("never=%v", flags)
	}
	if _, ok := ParseNotify("BOGUS"); ok {
		t.Fatal("bogus notify")
	}
}

func TestBuildDSNMultipart(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@b\r\nTo: c@d\r\nSubject: hi\r\n\r\nbody\r\n")
	msg := BuildDSN(DSNBuildOpts{
		ReturnPath:  "sender@example.com",
		FinalRcpt:   "bad@example.org",
		Orcpt:       "rfc822;bad@example.org",
		Envid:       "env-1",
		Ret:         RetFull,
		Action:      DSNActionFailed,
		Status:      "5.1.1",
		Diagnostic:  "550 user unknown",
		QueueID:     42,
		OriginalRaw: raw,
	})
	s := string(msg)
	for _, want := range []string{
		"multipart/report",
		"message/delivery-status",
		"Action: failed",
		"Status: 5.1.1",
		"Original-Envelope-Id: env-1",
		"Final-Recipient: rfc822; bad@example.org",
		"550 user unknown",
		"From: a@b",
		"body",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in:\n%s", want, s)
		}
	}
}

func TestBuildDSNRetHdrs(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@b\r\nTo: c@d\r\nSubject: hi\r\n\r\nsecret body\r\n")
	msg := BuildDSN(DSNBuildOpts{
		ReturnPath:  "sender@example.com",
		FinalRcpt:   "bad@example.org",
		Ret:         RetHdrs,
		Action:      DSNActionFailed,
		OriginalRaw: raw,
	})
	s := string(msg)
	if !strings.Contains(s, "From: a@b") {
		t.Fatal("missing headers")
	}
	if strings.Contains(s, "secret body") {
		t.Fatal("body leaked with RET=HDRS")
	}
}

func TestShouldSendDSN(t *testing.T) {
	t.Parallel()

	if ShouldSendDSN("", NotifyFailure, DSNActionFailed, true, true) {
		t.Fatal("empty return path")
	}
	if ShouldSendDSN("a@b", NotifyNever, DSNActionFailed, true, true) {
		t.Fatal("never")
	}
	if ShouldSendDSN("a@b", NotifyFailure, DSNActionFailed, false, false) {
		t.Fatal("no route")
	}
	if !ShouldSendDSN("a@b", NotifyFailure, DSNActionFailed, true, false) {
		t.Fatal("local ok")
	}
}

// No value can add lines to a notification: the diagnostic is the remote server's reply, and a
// line break in it (or a bare CR, kept by the reply reader inside a line) used to forge fields
// such as Final-Recipient in the message/delivery-status part.
func TestBuildDSNNoFieldInjection(t *testing.T) {
	out := string(BuildDSN(DSNBuildOpts{
		ReturnPath: "a@example.org\r\nBcc: x@example.org", FinalRcpt: "b@example.net",
		Envid: "e\nX-Env: 1", Orcpt: "rfc822;c@example.net\rX-Orcpt: 1", Action: DSNActionFailed,
		Diagnostic: "550 no such user\rX-Injected: diag\nFinal-Recipient: rfc822; forged@example.org",
	}))
	for _, forged := range []string{"\nFinal-Recipient: rfc822; forged", "\nX-Injected", "\nBcc:", "\nX-Env", "\nX-Orcpt", "\rX-"} {
		if strings.Contains(out, forged) {
			t.Fatalf("injected %q in:\n%s", forged, out)
		}
	}
}

// RFC 3461 6.2/6.3, RFC 3464 2.1, RFC 6522 4: the server's own name in Reporting-MTA ("dns" only
// for a dotted name) and From; ENVID and ORCPT decoded from xtext; RET=FULL returns the whole
// message only with a failure, other notifications carry the header as text/rfc822-headers.
func TestBuildDSNFormat(t *testing.T) {
	raw := []byte("Subject: s\r\n\r\nsecret body\r\n")
	base := DSNBuildOpts{ReturnPath: "a@example.org", FinalRcpt: "b@example.net", Envid: "id+2B1+20x",
		Orcpt: "rfc822;B+40example.net", Ret: RetFull, OriginalRaw: raw, Hostname: "mx.example.net"}

	failed := base
	failed.Action = DSNActionFailed
	out := string(BuildDSN(failed))
	for _, want := range []string{"From: Mail Delivery System <MAILER-DAEMON@mx.example.net>", "Reporting-MTA: dns; mx.example.net\r\n",
		"Original-Envelope-Id: id+1 x\r\n", "Original-Recipient: rfc822;B@example.net\r\n", "Content-Type: message/rfc822", "secret body"} {
		if !strings.Contains(out, want) {
			t.Errorf("failed DSN lacks %q:\n%s", want, out)
		}
	}
	for _, action := range []DSNAction{DSNActionDelivered, DSNActionDelayed, DSNActionRelayed} {
		ok := base
		ok.Action = action
		out := string(BuildDSN(ok))
		if strings.Contains(out, "secret body") || !strings.Contains(out, "Content-Type: text/rfc822-headers\r\n\r\nSubject: s") {
			t.Errorf("%s DSN with RET=FULL must carry only the header:\n%s", action, out)
		}
	}
	local := base
	local.Action, local.Hostname = DSNActionFailed, "mailhost"
	if out := string(BuildDSN(local)); !strings.Contains(out, "Reporting-MTA: x-local-hostname; mailhost\r\n") {
		t.Errorf("undotted host reported as dns:\n%s", out)
	}
}

// RFC 5322 3.6: Date and From are required in every message we generate; Message-ID SHOULD be there.
func TestGeneratedMessagesHaveRequiredFields(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string][]byte{
		"dsn":    BuildDSN(DSNBuildOpts{ReturnPath: "a@example.com", FinalRcpt: "b@example.org", Action: DSNActionFailed, Status: "5.1.1", Hostname: "mx.example.net"}),
		"simple": BuildSimpleMessage("a@example.com", "b@example.org", "hi"),
	} {
		msg, err := netmail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := msg.Header.Date(); err != nil {
			t.Errorf("%s: Date: %v", name, err)
		}
		if _, err := msg.Header.AddressList("From"); err != nil {
			t.Errorf("%s: From: %v", name, err)
		}
		if id := msg.Header.Get("Message-Id"); !strings.HasPrefix(id, "<") || !strings.Contains(id, "@") {
			t.Errorf("%s: Message-ID %q", name, id)
		}
	}
}

// A notification must itself be sendable: no line over 998 octets (RFC 5321 4.5.3.1.6), even with
// a remote reply as long as the client accepts (4096 octets a line) and ENVID, ORCPT at their
// RFC 3461 4 maximum. Otherwise the client refuses it (ErrLineTooLong) and the bounce is lost.
func TestDSNLinesFitSMTP(t *testing.T) {
	raw := []byte("From: a@example.org\r\nSubject: " + strings.Repeat("s", 900) + "\r\n\r\nbody\r\n")
	for _, action := range []DSNAction{DSNActionFailed, DSNActionDelayed, DSNActionDelivered} {
		dsn := BuildDSN(DSNBuildOpts{
			ReturnPath: "a@example.org", FinalRcpt: "b@example.net",
			Orcpt: "rfc822;" + strings.Repeat("o", 490) + "@example.net",
			Envid: strings.Repeat("e", 100),
			Ret:   RetFull, Action: action, Status: "5.1.1",
			Diagnostic:  "550 5.1.1 " + strings.Repeat("d", 4086),
			OriginalRaw: raw, Hostname: "mx.example.net",
		})
		if n := longestLine(dsn); n > MaxLineOctets {
			t.Errorf("%s: line of %d octets", action, n)
		}
	}
	// The original has the lines that made it fail (ErrLineTooLong): returned as its header, in
	// base64 when the header itself has one.
	long := []byte("From: a@example.org\r\nSubject: " + strings.Repeat("s", 2000) + "\r\n\r\n" + strings.Repeat("b", 3000) + "\r\n")
	dsn := BuildDSN(DSNBuildOpts{ReturnPath: "a@example.org", FinalRcpt: "b@example.net", Ret: RetFull,
		Action: DSNActionFailed, Status: "5.6.0", Diagnostic: ErrLineTooLong.Error(), OriginalRaw: long, Hostname: "mx.example.net"})
	if n := longestLine(dsn); n > MaxLineOctets || !strings.Contains(string(dsn), "Content-Type: text/rfc822-headers\r\nContent-Transfer-Encoding: base64") {
		t.Errorf("original with long lines: longest line %d", n)
	}
}
