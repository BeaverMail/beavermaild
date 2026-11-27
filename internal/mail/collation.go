// Collation for SEARCH, SORT and THREAD: i;unicode-casemap (RFC 5051) as I18NLEVEL=1 requires
// (RFC 5255 4.2, 4.6; RFC 5256 7), with i;octet for text that is not valid UTF-8.
package mail

import (
	"bytes"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

// casemap is the i;unicode-casemap preparation of RFC 5051 2 as a transform: each character is
// titlecased, then replaced by its full decomposition (the decomposition of that one character,
// recursively: step 2b, which needs no reordering of diacriticals across characters). ASCII takes
// a fast path. One transform, not transform.Chain of a mapper and NFKD: Chain's fixed inner buffer
// fails ("short internal buffer") on a run of characters that decompose to many (U+FDFA gives 18)
// and the rest of the text went unsearched; full NFKD was also 30 times slower on such text.
// Invalid UTF-8 passes as it is (that text is compared as octets anyway).
type casemap struct{ cache map[rune]string }

// casemapCacheMax bounds the decompositions one transform remembers.
const casemapCacheMax = 4096

func newCasemap() *casemap { return &casemap{cache: map[rune]string{}} }

func (t *casemap) Reset() {}

func (t *casemap) fold(r rune) string {
	if d, ok := t.cache[r]; ok {
		return d
	}
	d := norm.NFKD.String(string(unicode.ToTitle(r)))
	if len(t.cache) < casemapCacheMax {
		t.cache[r] = d
	}
	return d
}

func (t *casemap) Transform(dst, src []byte, atEOF bool) (nDst, nSrc int, err error) {
	for nSrc < len(src) {
		if c := src[nSrc]; c < utf8.RuneSelf {
			if nDst == len(dst) {
				return nDst, nSrc, transform.ErrShortDst
			}
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			dst[nDst] = c
			nDst++
			nSrc++
			continue
		}
		r, size := utf8.DecodeRune(src[nSrc:])
		var out string
		if r == utf8.RuneError && size == 1 {
			if !atEOF && !utf8.FullRune(src[nSrc:]) {
				return nDst, nSrc, transform.ErrShortSrc
			}
			out = string(src[nSrc])
		} else {
			out = t.fold(r)
		}
		if nDst+len(out) > len(dst) {
			return nDst, nSrc, transform.ErrShortDst
		}
		nDst += copy(dst[nDst:], out)
		nSrc += size
	}
	return nDst, nSrc, nil
}

// casemapKey is the i;unicode-casemap form of s; ok is false when s is not valid UTF-8, so it
// cannot be converted (RFC 5051 2 step 1b).
func casemapKey(s string) (string, bool) {
	if !utf8.ValidString(s) {
		return s, false
	}
	k, _, _ := transform.String(newCasemap(), s)
	return k, true
}

// unicodeCasemap is the SORT and THREAD key of s. RFC 5255 4.6 orders the strings that fail
// conversion after all the others, by octet: they get a 0xFF prefix, a byte valid UTF-8 never has.
func unicodeCasemap(s string) string {
	if k, ok := casemapKey(s); ok {
		return k
	}
	return "\xff" + s
}

// needle is a SEARCH key with its i;unicode-casemap form (foldOK false for invalid UTF-8). It is
// folded once per command: folding per message costs the key's length times the messages
// (CVE-2026-107581 class).
type needle struct {
	raw, folded string
	foldOK      bool
}

func newNeedle(s string) needle {
	f, ok := casemapKey(s)
	return needle{raw: s, folded: f, foldOK: ok}
}

// textContains is the SEARCH substring operation (RFC 5255 4.6 c): i;unicode-casemap when both
// strings are valid UTF-8, else i;octet on the text as it is.
func textContains(haystack string, n needle) bool {
	h, okH := casemapKey(haystack)
	if !okH || !n.foldOK {
		return strings.Contains(haystack, n.raw)
	}
	return strings.Contains(h, n.folded)
}

// readerContains is textContains over a stream, never held in memory whole: the text is matched
// as octets and, through the casemap transform, as i;unicode-casemap; which answer counts is known
// once the end shows whether all of it was valid UTF-8 (reported as valid). convertible false (an
// unknown charset) means i;octet only.
func readerContains(r io.Reader, n needle, convertible bool) (found, valid bool) {
	oct := &octetScan{needle: []byte(n.raw), found: n.raw == ""}
	tee := io.TeeReader(r, oct)
	ok := n.foldOK
	if ok && convertible {
		var err error
		found, err = scanContains(transform.NewReader(tee, newCasemap()), []byte(n.folded))
		// A transform that fails is a failed conversion (4.6 c): i;octet decides.
		convertible = err == nil
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return false, false
	}
	if ok && convertible && oct.valid() {
		return found, true
	}
	return oct.found, oct.valid()
}

// searchChunk is how much text TEXT and BODY scan at a time.
var searchChunk = 64 << 10

// scanContains reports whether r holds n, reading searchChunk bytes at a time and carrying the
// last len(n)-1 bytes over each cut. err is a read error other than the end of r.
func scanContains(r io.Reader, n []byte) (bool, error) {
	keep := max(len(n)-1, 0)
	buf := make([]byte, keep+searchChunk)
	have := 0
	for {
		k, err := io.ReadFull(r, buf[have:])
		have += k
		if bytes.Contains(buf[:have], n) {
			return true, nil
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		have = copy(buf, buf[have-keep:have])
	}
}

// octetScan watches the bytes written to it: whether they hold needle as octets, and whether they
// are valid UTF-8 (a rune cut at the end of the stream is not).
type octetScan struct {
	needle           []byte
	found, invalid   bool
	tail, pending    []byte // last len(needle)-1 bytes; an incomplete rune at the end
	window, runesBuf []byte // reused scratch
}

func (o *octetScan) Write(p []byte) (int, error) {
	if !o.found {
		o.window = append(append(o.window[:0], o.tail...), p...)
		o.found = bytes.Contains(o.window, o.needle)
		o.tail = append(o.tail[:0], o.window[max(0, len(o.window)-len(o.needle)+1):]...)
	}
	if !o.invalid {
		o.runesBuf = append(append(o.runesBuf[:0], o.pending...), p...)
		end := completeRunes(o.runesBuf)
		o.invalid = !utf8.Valid(o.runesBuf[:end])
		o.pending = append(o.pending[:0], o.runesBuf[end:]...)
	}
	return len(p), nil
}

func (o *octetScan) valid() bool { return !o.invalid && len(o.pending) == 0 }

// completeRunes returns the length of b without a rune cut off at its end.
func completeRunes(b []byte) int {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return i
			}
			break
		}
	}
	return len(b)
}
