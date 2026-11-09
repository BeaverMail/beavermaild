package imap

import (
	"slices"
	"testing"
)

func TestParseSeqSetExpand(t *testing.T) {
	t.Parallel()
	set, err := parseSeqSet("1,3:4")
	if err != nil {
		t.Fatal(err)
	}
	got := set.expandSeq(5)
	want := []uint32{1, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

// TestSeqSetReversedRanges checks 3:1 == 1:3 and *:4 == 4:* (RFC 3501 seq-range), and that a
// UID range past the largest UID still matches the last message.
func TestSeqSetReversedRanges(t *testing.T) {
	t.Parallel()
	for in, want := range map[string][]uint32{"3:1": {1, 2, 3}, "*:4": {4, 5}, "1,*": {1, 5}} {
		set, err := parseSeqSet(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := set.expandSeq(5); !slices.Equal(got, want) {
			t.Fatalf("%s: got %v want %v", in, got, want)
		}
	}
	set, err := parseSeqSet("9:*")
	if err != nil {
		t.Fatal(err)
	}
	if got := set.expandUID([]messageRef{{uid: 1}, {uid: 4}}); !slices.Equal(got, []int{1}) {
		t.Fatalf("9:* got %v", got)
	}
}

func TestExpandUID(t *testing.T) {
	t.Parallel()
	set, err := parseSeqSet("2,4")
	if err != nil {
		t.Fatal(err)
	}
	refs := []messageRef{{uid: 1}, {uid: 2}, {uid: 4}}
	got := set.expandUID(refs)
	want := []int{1, 2}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestParseStatusArg(t *testing.T) {
	t.Parallel()
	name, fields, ok := parseStatusArg(`INBOX (MESSAGES UNSEEN)`)
	if !ok || name != "INBOX" || len(fields) != 2 {
		t.Fatalf("parse %q %v %v", name, fields, ok)
	}
	_, fields, ok = parseStatusArg(`"Sent" (UIDNEXT MESSAGES UNSEEN RECENT)`)
	if !ok || len(fields) != 4 {
		t.Fatalf("recent fields %v ok=%v", fields, ok)
	}
}
