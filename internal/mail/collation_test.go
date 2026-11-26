package mail

import (
	"io"
	"slices"
	"strings"
	"testing"
)

func loaderOf(raw map[uint32]string) RawLoader {
	return func(m Message) (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(raw[m.UID])), nil }
}

// TestSortInvalidUTF8Last checks RFC 5255 4.6 (binding on SORT through RFC 5256 7): strings that
// cannot be converted to Unicode sort after all the others, by octet.
func TestSortInvalidUTF8Last(t *testing.T) {
	raw := map[uint32]string{
		1: "Subject: \xC0bad\r\n\r\n",
		2: "Subject: Ωmega\r\n\r\n",
		3: "Subject: alpha\r\n\r\n",
		4: "Subject: \x80worse\r\n\r\n",
	}
	msgs := []Message{{UID: 1}, {UID: 2}, {UID: 3}, {UID: 4}}
	got := SortMessages(msgs, []SortCriterion{{Key: SortSubject}}, SearchExpr{Crit: SearchCriteria{All: true}}, loaderOf(raw))
	if want := []uint32{3, 2, 4, 1}; !slices.Equal(got, want) {
		t.Fatalf("SORT SUBJECT = %v, want %v", got, want)
	}
}

// TestSearchUnicodeCasemap checks SEARCH under I18NLEVEL=1 (RFC 5255 4.2, 4.6): i;unicode-casemap
// (RFC 5051 2) on text converted to UTF-8, i;octet where conversion fails.
func TestSearchUnicodeCasemap(t *testing.T) {
	const latin1QP = "Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nun caf=E9\r\n"
	raw := map[uint32]string{
		1: "Subject: Ｆull width\r\n\r\nx\r\n",
		2: "Subject: café decomposed\r\n\r\nx\r\n",
		3: "Subject: ﬁle\r\n\r\nx\r\n",
		4: "Subject: q\r\n" + latin1QP,
		5: "Subject: e\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nun caf\xe9\r\n",
		6: "Subject: u\r\nContent-Type: text/plain; charset=x-unknown\r\n\r\nHello there\r\n",
		7: "Subject: m\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nGrüße\r\n" +
			"--b\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nna\xefve\r\n--b--\r\n",
		8: "Subject: t\r\n\r\ncut rune \xe2\x82", // CVE-2020-7046: truncated UTF-8 at the end
	}
	var msgs []Message
	for uid := range uint32(len(raw)) {
		msgs = append(msgs, Message{UID: uid + 1})
	}
	cases := []struct {
		name string
		c    SearchCriteria
		want []uint32
	}{
		{"full width is its compatibility form", SearchCriteria{Subject: "FULL WIDTH"}, []uint32{1}},
		{"decomposed accent equals composed", SearchCriteria{Subject: "CAFÉ"}, []uint32{2}},
		{"accent ignored on the needle side too", SearchCriteria{Subject: "cafe"}, []uint32{2}},
		// RFC 5051 titlecases, then decomposes: the ligature becomes lowercase "fi", not "FI".
		{"ligature decomposes after titlecasing", SearchCriteria{Subject: "FILE"}, nil},
		{"ligature matches its decomposition", SearchCriteria{Subject: "ﬁ"}, []uint32{3}},
		{"latin-1 quoted-printable body converted", SearchCriteria{Body: "CAFÉ"}, []uint32{4, 5}},
		{"latin-1 8bit body converted, TEXT", SearchCriteria{Text: "café"}, []uint32{2, 4, 5}},
		{"unknown charset is i;octet: exact", SearchCriteria{Body: "Hello"}, []uint32{6}},
		{"unknown charset is i;octet: no case folding", SearchCriteria{Body: "hello"}, nil},
		{"utf-8 part next to a latin-1 part", SearchCriteria{Body: "GRÜSSE"}, nil}, // ß has no simple titlecase
		{"utf-8 part next to a latin-1 part, ß kept", SearchCriteria{Body: "grüße"}, []uint32{7}},
		{"latin-1 part of a multipart", SearchCriteria{Body: "NAÏVE"}, []uint32{7}},
		{"truncated rune: i;octet, terminates", SearchCriteria{Body: "CUT"}, nil},
		{"truncated rune: exact octets match", SearchCriteria{Body: "cut rune"}, []uint32{8}},
	}
	for _, tc := range cases {
		if got := MatchSearchWithLoader(msgs, tc.c, loaderOf(raw)); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A long run of a character with a large decomposition (U+FDFA: 18 characters, 33 bytes) must not
// stop the scan: transform.Chain failed there with "short internal buffer" and the text after it
// was never searched.
func TestSearchAfterLargeDecompositions(t *testing.T) {
	text := strings.Repeat("\uFDFA", 1<<16) + " hidden word"
	if found, valid := readerContains(strings.NewReader(text), "HIDDEN WORD", true); !found || !valid {
		t.Fatalf("found=%v valid=%v", found, valid)
	}
	if found, _ := readerContains(strings.NewReader(strings.Repeat("\uFDFA", 3)), "\u0639\u0644\u064A\u0647", true); !found {
		t.Fatal("expansion of U+FDFA not matched")
	}
}

// TestCasemapRFC5051 checks the preparation of RFC 5051 2 on its own example (U+01C4 becomes
// U+0044 U+007A U+030C) and the ASCII fast path.
func TestCasemapRFC5051(t *testing.T) {
	for in, want := range map[string]string{
		"\u01C4": "Dz\u030C", "abc XYZ 019": "ABC XYZ 019", "\u00E9": "E\u0301", "\uFB01": "fi", "\u212A": "K",
	} {
		if got, ok := casemapKey(in); !ok || got != want {
			t.Errorf("casemapKey(%q) = %q, want %q", in, got, want)
		}
	}
}
