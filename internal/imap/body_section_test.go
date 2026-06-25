package imap

import (
	"strings"
	"testing"
)

func TestExtractBodySectionMultipart(t *testing.T) {
	t.Parallel()

	raw := []byte("Content-Type: multipart/mixed; boundary=abc\r\n\r\n" +
		"--abc\r\nContent-Type: text/plain\r\n\r\nhello plain\r\n" +
		"--abc\r\nContent-Type: application/octet-stream; name=f.bin\r\n\r\nBINDATA\r\n" +
		"--abc--\r\n")

	p1 := extractBodySection(raw, "1", nil)
	if !strings.Contains(string(p1), "text/plain") || !strings.Contains(string(p1), "hello plain") {
		t.Fatalf("part1 %q", p1)
	}
	p2 := extractBodySection(raw, "2", nil)
	if !strings.Contains(string(p2), "octet-stream") || !strings.Contains(string(p2), "BINDATA") {
		t.Fatalf("part2 %q", p2)
	}
	text := extractBodySection(raw, "1.TEXT", nil)
	if !strings.Contains(string(text), "hello plain") {
		t.Fatalf("text %q", text)
	}
}

func TestExtractBodySectionSimple(t *testing.T) {
	t.Parallel()

	raw := []byte("From: a@b.com\r\nSubject: hi\r\n\r\nbody\r\n")
	hdr := extractBodySection(raw, "HEADER", nil)
	if !strings.Contains(string(hdr), "Subject: hi") {
		t.Fatalf("hdr %q", hdr)
	}
	if string(extractBodySection(raw, "TEXT", nil)) != "body\r\n" {
		t.Fatal("text")
	}
	if string(extractBodySection(raw, "1.TEXT", nil)) != "body\r\n" {
		t.Fatal("1.text")
	}
}
