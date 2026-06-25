package mail_test

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
)

func TestMatchSearchExprOrNot(t *testing.T) {
	t.Parallel()

	msgs := []mail.Message{
		{UID: 1, Meta: storage.EmailMeta{Flags: mail.FlagAnswered}},
		{UID: 2},
		{UID: 3, Meta: storage.EmailMeta{Flags: mail.FlagAnswered}},
	}
	rawAlice := []byte("From: alice@example.com\r\nSubject: hello\r\n\r\n")
	rawBob := []byte("From: bob@example.com\r\nSubject: world\r\n\r\n")
	rawCarol := []byte("From: carol@example.com\r\nSubject: other\r\n\r\n")
	load := func(m mail.Message) ([]byte, error) {
		switch m.UID {
		case 1:
			return rawAlice, nil
		case 2:
			return rawBob, nil
		default:
			return rawCarol, nil
		}
	}

	orExpr := mail.SearchExpr{
		Kind: mail.SearchExprOr,
		Or: [2]*mail.SearchExpr{
			{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{From: "alice"}},
			{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{Subject: "world"}},
		},
	}
	if n := mail.MatchSearchExprWithLoader(msgs, orExpr, load); len(n) != 2 || n[0] != 1 || n[1] != 2 {
		t.Fatalf("or %v", n)
	}

	notExpr := mail.SearchExpr{
		Kind: mail.SearchExprNot,
		Not: &mail.SearchExpr{
			Kind: mail.SearchExprAnd,
			And: []*mail.SearchExpr{
				{Kind: mail.SearchExprCrit, Crit: mail.SearchCriteria{From: "alice"}},
				{Kind: mail.SearchExprCrit, Crit: func() mail.SearchCriteria {
					v := true
					return mail.SearchCriteria{Answered: &v}
				}()},
			},
		},
	}
	if n := mail.MatchSearchExprWithLoader(msgs, notExpr, load); len(n) != 2 || n[0] != 2 || n[1] != 3 {
		t.Fatalf("not and %v", n)
	}
}
