package mail_test

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
)

func TestMatchSearchTextBodyCCBCCSize(t *testing.T) {
	t.Parallel()

	raw := []byte("From: alice@example.com\r\nCc: carol@example.com\r\nBcc: hidden@example.com\r\nSubject: hello\r\n\r\nneedle in body\r\n")
	msgs := []mail.Message{{
		UID: 1,
		Meta: storage.EmailMeta{
			Size: uint32(len(raw)),
		},
	}}
	load := func(m mail.Message) ([]byte, error) { return raw, nil }

	if n := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{Text: "needle"}, load); len(n) != 1 {
		t.Fatalf("text body %v", n)
	}
	if n := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{Text: "hello"}, load); len(n) != 1 {
		t.Fatalf("text header %v", n)
	}
	if n := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{Body: "needle"}, load); len(n) != 1 {
		t.Fatalf("body hit %v", n)
	}
	if n := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{Body: "hello"}, load); len(n) != 0 {
		t.Fatalf("body header miss %v", n)
	}
	if n := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{CC: "carol@"}, load); len(n) != 1 {
		t.Fatalf("cc %v", n)
	}
	if n := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{BCC: "hidden@"}, load); len(n) != 1 {
		t.Fatalf("bcc %v", n)
	}

	larger := uint32(len(raw) - 1)
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Larger: &larger}); len(n) != 1 {
		t.Fatalf("larger %v", n)
	}
	larger = uint32(len(raw))
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Larger: &larger}); len(n) != 0 {
		t.Fatalf("larger equal %v", n)
	}
	smaller := uint32(len(raw) + 1)
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Smaller: &smaller}); len(n) != 1 {
		t.Fatalf("smaller %v", n)
	}
	smaller = uint32(len(raw))
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Smaller: &smaller}); len(n) != 0 {
		t.Fatalf("smaller equal %v", n)
	}
}
