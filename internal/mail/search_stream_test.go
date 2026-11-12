package mail

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// readerContains must answer exactly what rawContains answers on the whole message, whatever the
// chunk size: matches across a cut, multi-byte runes split by a cut, case folding that changes the
// byte length (Kelvin sign, dotted I) and invalid UTF-8.
func TestReaderContainsMatchesRawContains(t *testing.T) {
	defer func(n int) { searchChunk = n }(searchChunk)
	texts := []string{
		"", "hello world", "HELLO\r\nWORLD", "Straße und STRASSE", "Kelvin KELVIN", "İstanbul ISTANBUL",
		"caf\xc3\xa9 CAF\xc3\x89", "bad \xff\xfe bytes \xe2\x82 cut", strings.Repeat("ab", 300) + "needle" + strings.Repeat("é", 200),
	}
	needles := []string{"world", "o\r\nw", "straße", "kelvin", "Kelvin", "istanbul", "i̇stanbul", "café", "\xff\xfe",
		"\xe2\x82", "\xbd", "needle", "éé", "aba", "zzz"}
	for _, size := range []int{1, 2, 3, 5, 7, 64, 64 << 10} {
		searchChunk = size
		for _, text := range texts {
			for _, n := range needles {
				want := rawContains([]byte(text), n)
				if got := readerContains(strings.NewReader(text), n); got != want {
					t.Errorf("chunk %d: readerContains(%q, %q) = %v, rawContains = %v", size, text, n, got, want)
				}
			}
		}
	}
}

// TEXT and BODY scan the message as a stream: a match at the end of 32 MiB is found without the
// message ever existing as one slice.
func TestSearchTextStreamsLargeMessage(t *testing.T) {
	body := io.MultiReader(strings.NewReader("Subject: x\r\n\r\n"), io.LimitReader(zeros{}, 32<<20), strings.NewReader("Needle\r\n"))
	if !readerContains(body, "needle") {
		t.Fatal("needle at the end of a large message not found")
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// countingReader counts the bytes a criterion pulls from the message.
type countingReader struct {
	r io.Reader
	n *int
}

func (c countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.n += n
	return n, err
}

func (countingReader) Close() error { return nil }

// Header criteria, SORT and THREAD read the header block only, never the body.
func TestHeaderCriteriaReadOnlyTheHeader(t *testing.T) {
	read := 0
	load := RawLoader(func(Message) (io.ReadCloser, error) {
		r := io.MultiReader(strings.NewReader("From: alice@example.org\r\nSubject: Hi\r\nDate: Mon, 2 Jan 2006 15:04:05 +0000\r\n\r\n"),
			io.LimitReader(zeros{}, 16<<20))
		return countingReader{r, &read}, nil
	})
	msgs := []Message{{UID: 1}}
	all := SearchExpr{Crit: SearchCriteria{All: true}}
	checks := map[string]func() bool{
		"SEARCH FROM": func() bool { return len(MatchSearchWithLoader(msgs, SearchCriteria{From: "alice"}, load)) == 1 },
		"SORT SUBJECT": func() bool {
			return len(SortMessages(msgs, []SortCriterion{{Key: SortSubject}}, all, load)) == 1
		},
		"THREAD": func() bool { return len(ThreadReferences(msgs, all, load)) == 1 },
	}
	for name, check := range checks {
		read = 0
		if !check() {
			t.Fatalf("%s: no match", name)
		}
		if read > 64<<10 {
			t.Fatalf("%s read %d bytes of a 16 MiB message", name, read)
		}
	}
}

// A header block over maxSearchHeader is cut at a line end; BODY still starts after the real end
// of the header.
func TestReadHeaderCapped(t *testing.T) {
	long := "X-Long: " + strings.Repeat("a", 100) + "\r\n"
	raw := "Subject: first\r\n" + strings.Repeat(long, 200) + "\r\nbody text\r\n"
	br := bufio.NewReader(strings.NewReader(raw))
	h := readHeader(br, 1000)
	if len(h) > 1000+2 || !bytes.HasPrefix(h, []byte("Subject: first\r\n")) || !bytes.HasSuffix(h, []byte("\n\r\n")) {
		t.Fatalf("capped header = %q", h)
	}
	if rest, _ := io.ReadAll(br); string(rest) != "body text\r\n" {
		t.Fatalf("body after capped header = %q", rest)
	}
	if !openContains(BytesLoader(func(Message) ([]byte, error) { return []byte(raw), nil }), Message{}, "BODY TEXT", true) {
		t.Fatal("BODY after a long header not found")
	}
}
