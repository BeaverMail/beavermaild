package mail_test

import (
	"strings"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
)

func TestMatchSearchSentAndKeyword(t *testing.T) {
	t.Parallel()

	sentDay := time.Date(2024, 6, 10, 15, 0, 0, 0, time.UTC)
	raw := []byte("Date: Mon, 10 Jun 2024 15:00:00 +0000\r\nFrom: a@b.com\r\n\r\nbody\r\n")
	msgs := []mail.Message{{
		UID: 1,
		Meta: storage.EmailMeta{
			ReceivedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
			Keywords:   []string{"Flag_007"},
		},
	}, {
		UID: 2,
		Meta: storage.EmailMeta{Flags: mail.FlagSeen},
	}}
	load := func(m mail.Message) ([]byte, error) {
		if m.UID == 2 {
			return []byte("Date: Mon, 1 Jan 2020 00:00:00 +0000\r\n\r\n"), nil
		}
		return raw, nil
	}

	on := time.Date(2024, 6, 10, 0, 0, 0, 0, time.UTC)
	if n := mail.MatchSearchWithLoader(msgs, mail.SearchCriteria{SentOn: &on}, load); len(n) != 1 {
		t.Fatalf("senton %v", n)
	}
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Keyword: "Flag_007"}); len(n) != 1 {
		t.Fatalf("keyword %v", n)
	}
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Keyword: `\Seen`}); len(n) != 1 || n[0] != 2 {
		t.Fatalf("keyword seen %v", n)
	}
	if n := mail.MatchSearch(msgs, mail.SearchCriteria{Unkeyword: `\Seen`}); len(n) != 1 || n[0] != 1 {
		t.Fatalf("unkeyword %v", n)
	}
	_ = sentDay
}

func TestHasKeywordAndStoreKeywords(t *testing.T) {
	t.Parallel()

	meta := storage.EmailMeta{}
	mail.ApplyKeywords(&meta, []string{"Flag_007"}, nil)
	if !mail.HasKeyword(meta, "Flag_007") {
		t.Fatal("custom keyword")
	}
	mail.ApplyKeywords(&meta, []string{`\Seen`}, nil)
	if !mail.HasKeyword(meta, `\Seen`) {
		t.Fatal("system keyword")
	}
	got := mail.FormatMessageFlags(meta)
	if !strings.Contains(got, `\Seen`) || !strings.Contains(got, "Flag_007") {
		t.Fatalf("format %s", got)
	}
}
