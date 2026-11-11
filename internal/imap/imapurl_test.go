package imap

import "testing"

func TestParseIMAPURL(t *testing.T) {
	u, ok := parseIMAPURL("imap://bob%40example.org@Mail.Example.org/a/b%20c;UIDVALIDITY=5/;UID=7/;SECTION=1.HEADER/;PARTIAL=2.10;URLAUTH=user+bob:INTERNAL:0123")
	if !ok || u.user != "bob@example.org" || u.host != "mail.example.org" || u.mailbox != "a/b c" ||
		u.uidValidity != 5 || u.uid != 7 || u.section != "1.HEADER" || !u.partial || u.origin != 2 ||
		u.length != 10 || u.access != "user+bob" || u.mech != "INTERNAL" || u.token != "0123" {
		t.Fatalf("%+v %v", u, ok)
	}
	if u, ok := parseIMAPURL("/INBOX/;uid=3"); !ok || u.absolute || u.mailbox != "INBOX" || u.uid != 3 || u.length != -1 {
		t.Fatalf("%+v %v", u, ok)
	}
	if u, ok := parseIMAPURL("imap://alice@example.org:143/INBOX/;uid=1;urlauth=user+alice@example.org"); !ok || u.owner() != "alice@example.org" || u.access != "user+alice@example.org" {
		t.Fatalf("%+v %v", u, ok)
	}
	if u, _ := parseIMAPURL("imap://a@b%40c@host/INBOX/;uid=1"); u.user != "a@b@c" || u.host != "host" {
		t.Fatalf("%+v", u)
	}
	for _, bad := range []string{"INBOX/;UID=1", "/INBOX", "/INBOX/;UID=0", "/;UID=1", "/INBOX/;UID=1/;FOO=2", "/INBOX/;UID=1/;PARTIAL=x"} {
		if _, ok := parseIMAPURL(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestEncodeMUTF7(t *testing.T) {
	for in, want := range map[string]string{"INBOX": "INBOX", "a&b": "a&-b", "Entwürfe": "Entw&APw-rfe", "日本語": "&ZeVnLIqe-"} {
		if got := encodeMUTF7(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
