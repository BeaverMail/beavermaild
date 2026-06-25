package imap

import "testing"

func TestParseSearchHeaderCriteria(t *testing.T) {
	t.Parallel()

	c, ok := parseSearchCriteria(`FROM "alice@example.com" SUBJECT hello`)
	if !ok || c.From != "alice@example.com" || c.Subject != "hello" {
		t.Fatalf("header parse: %+v ok=%v", c, ok)
	}
	c, ok = parseSearchCriteria("SINCE 15-Mar-2024")
	if !ok || c.Since == nil || c.Since.Day() != 15 {
		t.Fatalf("since: %+v ok=%v", c, ok)
	}
	c, ok = parseSearchCriteria(`HEADER Message-ID "<abc@example.com>"`)
	if !ok || len(c.Headers) != 1 || c.Headers[0].Field != "Message-ID" {
		t.Fatalf("header: %+v ok=%v", c, ok)
	}
	if _, ok := parseSearchCriteria("FROM"); ok {
		t.Fatal("from without arg")
	}
}
