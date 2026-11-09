package imap

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestParseSortArg(t *testing.T) {
	t.Parallel()

	crits, search, ok := parseSortArg(`(DATE SUBJECT) UNSEEN`)
	if !ok || search != "UNSEEN" || len(crits) != 2 || crits[0] != (mail.SortCriterion{Key: mail.SortDate}) ||
		crits[1] != (mail.SortCriterion{Key: mail.SortSubject}) {
		t.Fatalf("parse %+v search=%q ok=%v", crits, search, ok)
	}

	// REVERSE applies to the next key only.
	crits, search, ok = parseSortArg(`(ARRIVAL REVERSE SIZE)`)
	if !ok || search != "ALL" || len(crits) != 2 || crits[0].Reverse || !crits[1].Reverse {
		t.Fatalf("reverse %+v search=%q", crits, search)
	}
	if _, _, ok := parseSortArg(`(ARRIVAL REVERSE)`); ok {
		t.Fatal("trailing REVERSE accepted")
	}
}

func TestFormatSortAndThread(t *testing.T) {
	t.Parallel()

	if got := formatSort([]uint32{3, 1, 2}); got != "SORT 3 1 2" {
		t.Fatalf("sort %q", got)
	}
	if got := formatSort(nil); got != "SORT" {
		t.Fatalf("empty sort %q", got)
	}
	id := func(n uint32) uint32 { return n }
	leaf := func(n uint32, ch ...*mail.ThreadNode) *mail.ThreadNode { return &mail.ThreadNode{Seq: n, Children: ch} }
	threads := []*mail.ThreadNode{
		leaf(1, leaf(2, leaf(4)), leaf(3)),
		leaf(0, leaf(5), leaf(6)),
		leaf(7, leaf(8, leaf(9))),
	}
	if got := formatThread(threads, id); got != "THREAD (1 (2 4)(3))((5)(6))(7 8 9)" {
		t.Fatalf("thread %q", got)
	}
}

func TestParseThreadArg(t *testing.T) {
	t.Parallel()

	algo, search, ok := parseThreadArg(`REFERENCES UNSEEN`)
	if !ok || algo != "REFERENCES" || search != "UNSEEN" {
		t.Fatalf("parse %q %q ok=%v", algo, search, ok)
	}
}
