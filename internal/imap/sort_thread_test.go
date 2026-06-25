package imap

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestParseSortArg(t *testing.T) {
	t.Parallel()

	keys, rev, search, ok := parseSortArg(`(DATE SUBJECT) UNSEEN`)
	if !ok || rev || search != "UNSEEN" || len(keys) != 2 || keys[0] != mail.SortDate || keys[1] != mail.SortSubject {
		t.Fatalf("parse %+v rev=%v search=%q ok=%v", keys, rev, search, ok)
	}

	keys, rev, search, ok = parseSortArg(`(REVERSE ARRIVAL)`)
	if !ok || !rev || search != "ALL" || len(keys) != 1 || keys[0] != mail.SortArrival {
		t.Fatalf("reverse %+v rev=%v search=%q", keys, rev, search)
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
	if got := formatThread([][]uint32{{1, 2}, {5}}); got != "THREAD (1 2) (5)" {
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
