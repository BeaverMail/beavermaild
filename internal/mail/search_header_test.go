package mail_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

func TestMatchSearchFromSubject(t *testing.T) {
	t.Parallel()

	raw := []byte("From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: hello world\r\n\r\nbody\r\n")
	msgs := []mail.Message{{
		UID: 1,
		Meta: storage.EmailMeta{
			ReceivedAt: time.Date(2024, 3, 15, 12, 0, 0, 0, time.UTC).Unix(),
		},
	}}
	load := func(m mail.Message) ([]byte, error) { return raw, nil }

	found := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{From: "alice@example"}, load)
	if len(found) != 1 {
		t.Fatalf("from: %v", found)
	}
	found = mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{Subject: "hello"}, load)
	if len(found) != 1 {
		t.Fatalf("subject: %v", found)
	}
	found = mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{From: "nobody"}, load)
	if len(found) != 0 {
		t.Fatalf("from miss: %v", found)
	}
}

func TestMatchSearchSinceBeforeOn(t *testing.T) {
	t.Parallel()

	day := time.Date(2024, 3, 15, 18, 0, 0, 0, time.UTC)
	msgs := []mail.Message{{
		UID:  1,
		Meta: storage.EmailMeta{ReceivedAt: day.Unix()},
	}}
	since := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)
	before := time.Date(2024, 3, 16, 0, 0, 0, 0, time.UTC)
	on := time.Date(2024, 3, 15, 0, 0, 0, 0, time.UTC)

	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Since: &since}); len(n) != 1 {
		t.Fatalf("since %v", n)
	}
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Before: &before}); len(n) != 1 {
		t.Fatalf("before %v", n)
	}
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{On: &on}); len(n) != 1 {
		t.Fatalf("on %v", n)
	}
	early := time.Date(2024, 3, 16, 0, 0, 0, 0, time.UTC)
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Since: &early}); len(n) != 0 {
		t.Fatalf("since future %v", n)
	}
}

func TestMatchSearchHeaderCriterion(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@b.com\r\nMessage-ID: <needle@example.com>\r\n\r\nbody\r\n")
	msgs := []mail.Message{{UID: 1}}
	load := func(m mail.Message) ([]byte, error) { return raw, nil }

	found := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{
		Headers: []mail.HeaderCriterion{{Field: "Message-ID", Value: "needle@example"}},
	}, load)
	if len(found) != 1 {
		t.Fatalf("header search %v", found)
	}
}

// TestMatchSearchHeaderRepeatedAndEmpty checks a repeated field matches on any occurrence and an
// empty value matches only messages that have the field (RFC 3501 HEADER).
func TestMatchSearchHeaderRepeatedAndEmpty(t *testing.T) {
	t.Parallel()

	raws := [][]byte{
		[]byte("X-Extra: hello\r\nX-Extra: another\r\n\r\nbody\r\n"),
		[]byte("Subject: none\r\n\r\nbody\r\n"),
	}
	msgs := []mail.Message{{UID: 1}, {UID: 2}}
	load := func(m mail.Message) ([]byte, error) { return raws[m.UID-1], nil }
	for value, want := range map[string]int{"another": 1, "": 1, "missing": 0} {
		found := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{
			Headers: []mail.HeaderCriterion{{Field: "X-Extra", Value: value}},
		}, load)
		if len(found) != want {
			t.Fatalf("X-Extra %q: got %v want %d", value, found, want)
		}
	}
}

// TestSearchSentDateSenderZone follows imaptest search-date: SENT* use the Date header's own day,
// ignoring its time and zone (00:00 +0200 on the 25th is the 25th, not the 24th in UTC).
func TestSearchSentDateSenderZone(t *testing.T) {
	t.Parallel()

	dates := []string{
		"Sat, 24 Mar 2007 23:00:00 +0200",
		"Sun, 25 Mar 2007 00:00:00 +0200",
		"Sun, 25 Mar 2007 23:00:00 +0300",
		"Mon, 26 Mar 2007 00:00:00 +0300",
	}
	msgs := make([]mail.Message, len(dates))
	for i := range msgs {
		msgs[i] = mail.Message{UID: uint32(i + 1)}
	}
	load := func(m mail.Message) ([]byte, error) {
		return []byte("Date: " + dates[m.UID-1] + "\r\n\r\nx\r\n"), nil
	}
	day := func(d int) *time.Time { t := time.Date(2007, 3, d, 0, 0, 0, 0, time.UTC); return &t }
	for name, tc := range map[string]struct {
		c    mail.SearchCriteria
		want int
	}{
		"senton 25":     {mail.SearchCriteria{SentOn: day(25)}, 2},
		"sentbefore 25": {mail.SearchCriteria{SentBefore: day(25)}, 1},
		"sentsince 26":  {mail.SearchCriteria{SentSince: day(26)}, 1},
	} {
		if got := mail.MatchSearchWithLoader(msgs, tc.c, load); len(got) != tc.want {
			t.Errorf("%s: got %v want %d", name, got, tc.want)
		}
	}
}

// TestSearchFromCommentedAddress follows imaptest search-addresses: comments inside an address
// do not hide it, and a real name written as a comment still matches.
func TestSearchFromCommentedAddress(t *testing.T) {
	t.Parallel()

	froms := []string{
		"<user-from (comment)@ (comment) example.org>",
		"user-from@example.org (RealFrom)",
		"other@example.org",
	}
	msgs := []mail.Message{{UID: 1}, {UID: 2}, {UID: 3}}
	load := func(m mail.Message) ([]byte, error) { return []byte("From: " + froms[m.UID-1] + "\r\n\r\nx\r\n"), nil }
	if got := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{From: "user-from@example.org"}, load); len(got) != 2 {
		t.Fatalf("address: got %v", got)
	}
	if got := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{From: "realfrom"}, load); len(got) != 1 {
		t.Fatalf("real name in comment: got %v", got)
	}
}
