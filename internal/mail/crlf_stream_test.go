package mail

import (
	"bytes"
	"io"
	"math/rand/v2"
	"testing"
)

// BareCRWriter must write exactly BareCR of its input, and the CRLF writer exactly CRLF, however
// the input is cut into writes.
func TestBareCRWriterMatchesBareCR(t *testing.T) {
	testStreamMatches(t, NewBareCRWriter, BareCR)
	testStreamMatches(t, NewCRLFWriter, CRLF)
}

func testStreamMatches(t *testing.T, newWriter func(io.Writer) *BareCRWriter, ref func([]byte) []byte) {
	alphabet := []byte("\r\n a:")
	rng := rand.New(rand.NewPCG(1, 2))
	for range 20000 {
		in := make([]byte, rng.IntN(40))
		for i := range in {
			in[i] = alphabet[rng.IntN(len(alphabet))]
		}
		var out bytes.Buffer
		w := newWriter(&out)
		for rest := in; len(rest) > 0; {
			n := 1 + rng.IntN(len(rest))
			if _, err := w.Write(rest[:n]); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if want := ref(append([]byte(nil), in...)); !bytes.Equal(out.Bytes(), want) {
			t.Fatalf("stream(%q) = %q, want %q", in, out.Bytes(), want)
		}
	}
}
