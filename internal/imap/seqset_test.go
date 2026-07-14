package imap

import "testing"

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
