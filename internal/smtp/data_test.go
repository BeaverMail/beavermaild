package smtp

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestReadDATANormal(t *testing.T) {
	t.Parallel()
	raw := "Subject: hi\r\n\r\nbody\r\n"
	got, err := readDATA(bufio.NewReader(strings.NewReader(raw+".\r\n")), DataLimits{})
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
	got, err := readDATA(bufio.NewReader(strings.NewReader(raw)), DataLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != ".leading dot\n" {
		t.Fatalf("got %q", got)
	}
}

func TestReadDATABareLFRejected(t *testing.T) {
	t.Parallel()
	_, err := readDATA(bufio.NewReader(strings.NewReader("line\n.\n")), DataLimits{})
	if !errors.Is(err, ErrBareLF) {
		t.Fatalf("err %v", err)
	}
}

func TestReadDATALineTooLong(t *testing.T) {
	t.Parallel()
	line := strings.Repeat("a", 999)
	_, err := readDATA(bufio.NewReader(strings.NewReader(line+"\r\n.\r\n")), DataLimits{MaxLineBytes: 998})
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err %v", err)
	}
}

func TestReadDATAMessageTooLarge(t *testing.T) {
	t.Parallel()
	body := strings.Repeat("x", 20) + "\r\n"
	_, err := readDATA(bufio.NewReader(strings.NewReader(body+".\r\n")), DataLimits{MaxMessageBytes: 10})
	if !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err %v", err)
	}
}

func TestWriteDATABodyDotStuff(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	if err := writeDATABody(&buf, []byte(".dot\r\nplain\r\n")); err != nil {
		t.Fatal(err)
	}
	want := "..dot\r\nplain\r\n.\r\n"
	if buf.String() != want {
		t.Fatalf("got %q want %q", buf.String(), want)
	}
}
