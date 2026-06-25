package imap

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestParseSearchHeaderCriteria(t *testing.T) {
	t.Parallel()

	expr, ok := parseSearchExpr(`FROM "alice@example.com" SUBJECT hello`)
	if !ok {
		t.Fatal("parse failed")
	}
	crits := flatSearchCrits(expr)
	from, ok := findSearchCrit(crits, func(c mail.SearchCriteria) bool { return c.From != "" })
	if !ok || from.From != "alice@example.com" {
		t.Fatalf("from: %+v", crits)
	}
	subj, ok := findSearchCrit(crits, func(c mail.SearchCriteria) bool { return c.Subject != "" })
	if !ok || subj.Subject != "hello" {
		t.Fatalf("subject: %+v", crits)
	}

	expr, ok = parseSearchExpr("SINCE 15-Mar-2024")
	if !ok || expr.Kind != mail.SearchExprCrit || expr.Crit.Since == nil || expr.Crit.Since.Day() != 15 {
		t.Fatalf("since: %+v ok=%v", expr, ok)
	}

	expr, ok = parseSearchExpr(`HEADER Message-ID "<abc@example.com>"`)
	if !ok || expr.Crit.Headers == nil || expr.Crit.Headers[0].Field != "Message-ID" {
		t.Fatalf("header: %+v ok=%v", expr, ok)
	}

	expr, ok = parseSearchExpr(`TEXT needle LARGER 10 SMALLER 500 CC carol@ BCC hidden@`)
	crits = flatSearchCrits(expr)
	if !ok || len(crits) != 5 {
		t.Fatalf("advanced: %+v ok=%v", crits, ok)
	}

	expr, ok = parseSearchExpr(`BODY "in body"`)
	if !ok || expr.Crit.Body != "in body" {
		t.Fatalf("body: %+v ok=%v", expr, ok)
	}
	if _, ok := parseSearchExpr("FROM"); ok {
		t.Fatal("from without arg")
	}
}

func TestParseSearchOrNotParens(t *testing.T) {
	t.Parallel()

	expr, ok := parseSearchExpr(`OR FROM alice@example.com SUBJECT hello`)
	if !ok || expr.Kind != mail.SearchExprOr {
		t.Fatalf("or: %+v ok=%v", expr, ok)
	}
	if expr.Or[0].Crit.From != "alice@example.com" || expr.Or[1].Crit.Subject != "hello" {
		t.Fatalf("or children: %+v", expr)
	}

	expr, ok = parseSearchExpr(`NOT (FROM alice@example.com ANSWERED)`)
	if !ok || expr.Kind != mail.SearchExprNot || expr.Not == nil {
		t.Fatalf("not: %+v ok=%v", expr, ok)
	}
	inner := expr.Not
	if inner.Kind != mail.SearchExprAnd || len(inner.And) != 2 {
		t.Fatalf("not inner: %+v", inner)
	}

	expr, ok = parseSearchExpr(`FLAGGED SINCE 1-Feb-1994 NOT FROM Smith`)
	if !ok || expr.Kind != mail.SearchExprAnd || len(expr.And) != 3 {
		t.Fatalf("and mix: %+v ok=%v", expr, ok)
	}
	if expr.And[2].Kind != mail.SearchExprNot || expr.And[2].Not == nil || expr.And[2].Not.Crit.From != "Smith" {
		t.Fatalf("not tail: %+v", expr.And[2])
	}

	if _, ok := parseSearchExpr(`OR FROM a`); ok {
		t.Fatal("or missing second key")
	}
	if _, ok := parseSearchExpr(`(FROM a`); ok {
		t.Fatal("unclosed paren")
	}

	expr, ok = parseSearchExpr(`SENTSINCE 10-Jun-2024 KEYWORD Flag_007`)
	crits := flatSearchCrits(expr)
	if !ok || len(crits) != 2 {
		t.Fatalf("sent keyword: %+v ok=%v", crits, ok)
	}
}
