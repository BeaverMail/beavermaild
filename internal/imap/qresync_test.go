package imap

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestVanishedSet(t *testing.T) {
	var msgs []mail.Message
	for _, uid := range []uint32{2, 5, 6, 9} {
		msgs = append(msgs, mail.Message{UID: uid})
	}
	set := func(s string) *seqSet {
		ss, err := parseSeqSet(s)
		if err != nil {
			t.Fatal(err)
		}
		return &ss
	}
	for _, tc := range []struct {
		known  *seqSet
		maxUID uint32
		want   string
	}{
		{nil, 10, "1,3:4,7:8,10"},
		{set("3:7,1"), 10, "1,3:4,7"},
		{set("*"), 10, "10"},
		{set("1:4,3:6"), 10, "1,3:4"},
		{set("8:1"), 10, "1,3:4,7:8"},
		{set("11:20"), 10, ""},
		{nil, 0, ""},
		{nil, 9, "1,3:4,7:8"},
	} {
		if got := vanishedSet(tc.known, tc.maxUID, msgs); got != tc.want {
			t.Errorf("vanishedSet(%v, %d) = %q, want %q", tc.known, tc.maxUID, got, tc.want)
		}
	}
}

func TestParseChangedSinceVanished(t *testing.T) {
	for _, tc := range []struct {
		in             string
		items          string
		since          uint64
		vanished, ok   bool
		foundModifiers bool
	}{
		{"(FLAGS) (CHANGEDSINCE 7 VANISHED)", "(FLAGS)", 7, true, true, true},
		{"(FLAGS) (VANISHED CHANGEDSINCE 7)", "(FLAGS)", 7, true, true, true},
		{"FLAGS (CHANGEDSINCE 7)", "FLAGS", 7, false, true, true},
		{"(FLAGS UID)", "(FLAGS UID)", 0, false, true, false},
		{"(FLAGS) (VANISHED)", "", 0, false, false, true},
		{"(FLAGS) (CHANGEDSINCE x)", "", 0, false, false, true},
	} {
		items, since, vanished, found, ok := parseChangedSince(tc.in)
		if ok != tc.ok || found != tc.foundModifiers || (ok && (items != tc.items || since != tc.since || vanished != tc.vanished)) {
			t.Errorf("parseChangedSince(%q) = %q %d %v found=%v ok=%v", tc.in, items, since, vanished, found, ok)
		}
	}
}

func TestSelectMailboxArgQResync(t *testing.T) {
	name, qr, cs, err := selectMailboxArg(`"My Box" (QRESYNC (67890007 20050715194045000 41,43:211,214:541) CONDSTORE)`, true)
	if err != nil || name != "My Box" || qr == nil || qr.uidValidity != 67890007 || qr.modSeq != 20050715194045000 || qr.knownUIDs == nil || !cs {
		t.Fatalf("got %q %+v %v", name, qr, err)
	}
	// seq-match-data is accepted and ignored.
	if _, qr, _, err := selectMailboxArg(`INBOX (QRESYNC (1 5 1:9 (1:3 4:6)))`, true); err != nil || qr == nil || qr.modSeq != 5 {
		t.Fatalf("seq-match-data: %+v %v", qr, err)
	}
	if _, qr, cs, err := selectMailboxArg(`INBOX (CONDSTORE)`, true); err != nil || qr != nil || !cs {
		t.Fatalf("condstore: %+v %v", qr, err)
	}
	// QRESYNC before ENABLE QRESYNC, or malformed, is a syntax error.
	for _, bad := range []string{`INBOX (QRESYNC (1 5))`, `INBOX (BOGUS)`} {
		if _, _, _, err := selectMailboxArg(bad, false); err == nil {
			t.Errorf("%q accepted without QRESYNC enabled", bad)
		}
	}
	if _, _, _, err := selectMailboxArg(`INBOX (QRESYNC (0 5))`, true); err == nil {
		t.Error("uidvalidity 0 accepted")
	}
}
