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
