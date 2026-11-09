package imap

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestTokenizeSearchLiteralAndEscapes(t *testing.T) {
	t.Parallel()

	got := tokenizeSearchArg("SUBJECT {4}\r\nab c HEADER X \"q\\\"t\\\\\"")
	want := []string{"SUBJECT", "ab c", "HEADER", "X", `q"t\`}
	if len(got) != len(want) {
		t.Fatalf("tokens %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token %d = %q want %q", i, got[i], want[i])
		}
	}
	// A literal ending in whitespace keeps it.
	if got := tokenizeSearchArg("TEXT {3}\r\nab "); len(got) != 2 || got[1] != "ab " {
		t.Fatalf("trailing space literal %q", got)
	}
	if got := tokenizeSearchArg("TEXT {9}\r\nshort"); got != nil {
		t.Fatalf("short literal %q", got)
	}
}

func TestParseSearchCommandCharset(t *testing.T) {
	t.Parallel()

	if _, st := parseSearchCommand("CHARSET UTF-8 ALL"); st != searchParsed {
		t.Fatalf("utf-8 %v", st)
	}
	if _, st := parseSearchCommand("CHARSET Windows-1252 ALL"); st != searchBadCharset {
		t.Fatalf("bad charset %v", st)
	}
	if _, st := parseSearchCommand("CHARSET"); st != searchSyntaxError {
		t.Fatalf("missing charset %v", st)
	}
	if _, st := parseSortSearch("ALL"); st != searchParsed {
		t.Fatalf("sort without charset %v", st)
	}
	if _, st := parseSortSearch("ISO-8859-2 UNSEEN"); st != searchBadCharset {
		t.Fatalf("sort bad charset %v", st)
	}
	if _, st := parseSortSearch("UTF-8 FROM"); st != searchSyntaxError {
		t.Fatalf("sort bad program %v", st)
	}
}

func TestParseSearchSeqSetAndModSeq(t *testing.T) {
	t.Parallel()

	expr, ok := parseSearchExpr("1:3,7 UID 5:*")
	if !ok {
		t.Fatal("parse failed")
	}
	crits := flatSearchCrits(expr)
	if len(crits) != 2 || len(crits[0].Seqs) != 2 || crits[0].Seqs[1] != (mail.SeqRange{Lo: 7, Hi: 7}) ||
		crits[1].UIDs[0] != (mail.SeqRange{Lo: 5, Hi: 0}) {
		t.Fatalf("crits %+v", crits)
	}
	for _, bad := range []string{"0", "1:x", "MODSEQ", "MODSEQ x", `MODSEQ "/flags/\\Seen" bogus 5`} {
		if _, ok := parseSearchExpr(bad); ok {
			t.Fatalf("%q parsed", bad)
		}
	}
	expr, ok = parseSearchExpr(`MODSEQ "/flags/\\Draft" priv 620162338`)
	if !ok || !expr.UsesModSeq() || *expr.Crit.ModSeq != 620162338 {
		t.Fatalf("modseq %+v ok=%v", expr, ok)
	}
}

func TestLiteralMarker(t *testing.T) {
	t.Parallel()

	if n, nonSync, ok := literalMarker("a SEARCH TEXT {12}"); !ok || nonSync || n != 12 {
		t.Fatalf("sync %d %v %v", n, nonSync, ok)
	}
	if n, nonSync, ok := literalMarker("TEXT {3+}"); !ok || !nonSync || n != 3 {
		t.Fatalf("nonsync %d %v %v", n, nonSync, ok)
	}
	for _, line := range []string{"TEXT {}", "TEXT {x}", "TEXT }", "ALL"} {
		if _, _, ok := literalMarker(line); ok {
			t.Fatalf("%q matched", line)
		}
	}
}
