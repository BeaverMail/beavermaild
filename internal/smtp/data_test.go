package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

func TestReadDATANormal(t *testing.T) {
	t.Parallel()
	raw := "Subject: hi\r\n\r\nbody\r\n"
	got, err := readDATABytes(bufio.NewReader(strings.NewReader(raw+".\r\n")), DataLimits{})
	if err != nil {
		t.Fatal(err)
	}
	want := "Subject: hi\n\nbody\n"
	if string(got) != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestReadDATAUnstuff(t *testing.T) {
	t.Parallel()
	raw := "..leading dot\r\n.\r\n"
	got, err := readDATABytes(bufio.NewReader(strings.NewReader(raw)), DataLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ".leading dot\n" {
		t.Fatalf("got %q", got)
	}
}

func TestReadDATABareLFRejected(t *testing.T) {
	t.Parallel()
	_, err := readDATABytes(bufio.NewReader(strings.NewReader("line\n.\n")), DataLimits{})
	if !errors.Is(err, ErrBareLF) {
		t.Fatalf("err %v", err)
	}
}

func TestReadDATALineTooLong(t *testing.T) {
	t.Parallel()
	line := strings.Repeat("a", 999)
	_, err := readDATABytes(bufio.NewReader(strings.NewReader(line+"\r\n.\r\n")), DataLimits{MaxLineBytes: 998})
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err %v", err)
	}
}

func TestReadDATAMessageTooLarge(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("x", 20) + "\r\n"
	_, err := readDATABytes(bufio.NewReader(strings.NewReader(body+".\r\n")), DataLimits{MaxMessageBytes: 10})
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err %v", err)
	}
}

func TestWriteDATABodyDotStuff(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeDATABody(&buf, mail.OutboundBytes([]byte(".dot\r\nplain\r\n"))); err != nil {
		t.Fatal(err)
	}
	want := "..dot\r\nplain\r\n.\r\n"
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
}

// readDATABytes is readDATA into memory, for the tests.
func readDATABytes(r *bufio.Reader, limits DataLimits) ([]byte, error) {
	var buf bytes.Buffer
	err := readDATA(r, limits, &buf)
	return buf.Bytes(), err
}

// writeDATABodyRef is the earlier in-memory writeDATABody, the reference for the streaming one.
func writeDATABodyRef(w io.Writer, data []byte) {
	for len(data) > 0 {
		idx := bytes.IndexByte(data, '\n')
		var line []byte
		if idx < 0 {
			line, data = data, nil
		} else {
			line, data = data[:idx], data[idx+1:]
		}
		if n := len(line); n > 0 && line[n-1] == '\r' {
			line = line[:n-1]
		}
		if len(line) > 0 && line[0] == '.' {
			_, _ = w.Write([]byte("."))
		}
		_, _ = w.Write(line)
		_, _ = w.Write([]byte("\r\n"))
	}
	_, _ = w.Write([]byte(".\r\n"))
}

// The streaming dot-stuffer sends what the in-memory one sent, however the stream is cut.
func TestDotStufferMatchesReference(t *testing.T) {
	alphabet := []byte(".\r\na")
	rng := rand.New(rand.NewPCG(3, 4))
	for range 20000 {
		in := make([]byte, rng.IntN(30))
		for i := range in {
			in[i] = alphabet[rng.IntN(len(alphabet))]
		}
		wire := mail.CRLF(in)
		var want, got bytes.Buffer
		writeDATABodyRef(&want, wire)
		if err := writeDATABody(&got, mail.OutboundBytes(in)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("%q: got %q, want %q", in, got.Bytes(), want.Bytes())
		}
		// Cut into random writes straight into the stuffer.
		got.Reset()
		d := &dotStuffer{w: &got, lineStart: true}
		for rest := wire; len(rest) > 0; {
			n := 1 + rng.IntN(len(rest))
			_, _ = d.Write(rest[:n])
			rest = rest[n:]
		}
		if !d.lineStart {
			got.WriteString("\r\n")
		}
		got.WriteString(".\r\n")
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("%q cut: got %q, want %q", in, got.Bytes(), want.Bytes())
		}
	}
}
