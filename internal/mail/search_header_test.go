package mail_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
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
		UID: 1,
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
