package imap

import (
	"strings"
	"testing"
	"time"
)

func TestFormatBodyStructurePlain(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@b.com\r\nSubject: hi\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nhello\r\n")
	bs := formatBodyStructure(raw)
	if !strings.Contains(bs, `"TEXT" "PLAIN"`) || !strings.Contains(bs, "UTF-8") || !strings.Contains(bs, `"7BIT"`) {
		t.Fatalf("plain: %s", bs)
	}
}

func TestFormatBodyStructureMultipart(t *testing.T) {
	t.Parallel()

	raw := []byte("Content-Type: multipart/alternative; boundary=abc\r\n\r\n" +
		"--abc\r\nContent-Type: text/plain\r\n\r\nplain\r\n" +
		"--abc\r\nContent-Type: text/html\r\n\r\n<b>html</b>\r\n" +
		"--abc--\r\n")
	bs := formatBodyStructure(raw)
	if !strings.Contains(bs, `"ALTERNATIVE"`) || !strings.Contains(bs, `"HTML"`) {
		t.Fatalf("multipart: %s", bs)
	}
}

func TestFormatInternalDate(t *testing.T) {
	t.Parallel()

	day := time.Date(2024, 3, 15, 12, 30, 0, 0, time.UTC)
	got := formatInternalDate(day.Unix())
	want := `"15-Mar-2024 12:30:00 +0000"`
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestParseFetchBodyStructure(t *testing.T) {
	t.Parallel()

	_, items, ok := parseFetchArg(`1 (BODYSTRUCTURE INTERNALDATE UID)`)
	if !ok || !items.bodystructure || !items.internalDate || !items.uid {
		t.Fatalf("items %+v ok=%v", items, ok)
	}
}
