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

	// BODY[n] is the part content; the part's MIME header is BODY[n.MIME].
	if p1 := extractBodySection(raw, "1", nil); string(p1) != "hello plain" {
		t.Fatalf("part1 %q", p1)
	}
	if p2 := extractBodySection(raw, "2", nil); string(p2) != "BINDATA" {
		t.Fatalf("part2 %q", p2)
	}
	if m := extractBodySection(raw, "2.MIME", nil); string(m) != "Content-Type: application/octet-stream; name=f.bin\r\n\r\n" {
		t.Fatalf("part2 mime %q", m)
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

// TestExtractBodySectionMessageRFC822 follows the imaptest fetch-body-message-rfc822 cases: part
// numbers continue into an encapsulated message, HEADER/TEXT of a message/rfc822 part refer to the
// inner message, bytes are returned as stored (no quoted-printable decoding, header order kept).
func TestExtractBodySectionMessageRFC822(t *testing.T) {
	t.Parallel()

	inner := "From: sub@example.org\r\nSubject: submsg\r\n\r\nHello world\r\n"
	single := []byte("From: user@example.org\r\nContent-Type: message/rfc822\r\n\r\n" + inner)
	for section, want := range map[string]string{
		"1":                   inner,
		"1.1":                 "Hello world\r\n",
		"1.HEADER":            "From: sub@example.org\r\nSubject: submsg\r\n\r\n",
		"1.TEXT":              "Hello world\r\n",
		"1.HEADER.FIELDS.NOT": "From: sub@example.org\r\n\r\n",
	} {
		var fields []string
		if strings.Contains(section, "FIELDS") {
			fields = []string{"subject"}
		}
		if got := string(extractBodySection(single, section, fields)); got != want {
			t.Errorf("%s: got %q want %q", section, got, want)
		}
	}

	multi := []byte("Content-Type: multipart/mixed; boundary=\"x\"\r\n\r\npreamble\r\n" +
		"--x\r\nContent-Transfer-Encoding: quoted-printable\r\nContent-Type: text/plain\r\n\r\na=3Db\r\n" +
		"--x\r\nContent-Type: message/rfc822\r\n\r\n" +
		"Subject: in\r\nContent-Type: multipart/alternative; boundary=y\r\n\r\n" +
		"--y\r\nContent-Type: text/html\r\n\r\n<p>hi</p>\r\n--y\r\n\r\nplain\r\n--y--\r\n" +
		"\r\n--x--\r\nepilogue\r\n")
	for section, want := range map[string]string{
		"1":        "a=3Db",
		"1.MIME":   "Content-Transfer-Encoding: quoted-printable\r\nContent-Type: text/plain\r\n\r\n",
		"2.HEADER": "Subject: in\r\nContent-Type: multipart/alternative; boundary=y\r\n\r\n",
		"2.1":      "<p>hi</p>",
		"2.2":      "plain",
		"2.2.MIME": "\r\n",
		"3":        "",
	} {
		if got := string(extractBodySection(multi, section, nil)); got != want {
			t.Errorf("%s: got %q want %q", section, got, want)
		}
	}
}

// TestExtractBodySectionDigest: parts of multipart/digest without Content-Type are message/rfc822,
// so 1.1.HEADER and 1.1.TEXT are the header and body of the digested message (imaptest).
func TestExtractBodySectionDigest(t *testing.T) {
	t.Parallel()

	raw := []byte("Content-Type: message/rfc822\r\n\r\n" +
		"Subject: outer\r\nContent-Type: multipart/digest; boundary=\"foo\"\r\n\r\nprologue\r\n" +
		"--foo \r\n\r\nFrom: m1@example.com\r\n\r\nm1 body\r\n" +
		"--foo--\r\n")
	if got := string(extractBodySection(raw, "1.1.HEADER", nil)); got != "From: m1@example.com\r\n\r\n" {
		t.Fatalf("1.1.HEADER %q", got)
	}
	if got := string(extractBodySection(raw, "1.1.TEXT", nil)); got != "m1 body" {
		t.Fatalf("1.1.TEXT %q", got)
	}
	if bs := formatBodyStructure(raw); !strings.Contains(bs, `("MESSAGE" "RFC822"`) {
		t.Fatalf("digest child type: %s", bs)
	}
}
