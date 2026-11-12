package mail

import (
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
