package imap

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestBinarySection(t *testing.T) {
	raw := []byte("Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Transfer-Encoding: base64\r\n\r\nAGhp\r\nIQ==\r\n" + // "\x00hi!"
		"--b\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=3Db=\r\nc\r\n" +
		"--b\r\nContent-Transfer-Encoding: 7bit\r\n\r\nplain\r\n" +
		"--b\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin\r\n" +
		"--b--\r\n")
	for section, want := range map[string]string{"1": "\x00hi!", "2": "a=bc", "3": "plain", "9": ""} {
		got, err := binarySection(raw, section)
		if err != nil || string(got) != want {
			t.Errorf("BINARY[%s] = %q, %v; want %q", section, got, err, want)
		}
	}
	if got, err := binarySection(raw, ""); err != nil || string(got) != string(raw) {
		t.Errorf("BINARY[] = %q, %v", got, err)
	}
	if _, err := binarySection(raw, "4"); !errors.Is(err, errUnknownCTE) {
		t.Errorf("uuencode: %v", err)
	}
}

func TestBase64NULParts(t *testing.T) {
	single := "Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\n\x00\xe4\r\n"
	multi := "Content-Type: multipart/mixed; boundary=b\r\n\r\npreamble\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nkept \xe4\r\n" +
		"--b\r\nContent-Transfer-Encoding: binary\r\n\r\n\x00bin\r\n" +
		"--b--\r\nepilogue\r\n"
	for _, tc := range []struct {
		raw, section, body string
	}{
		{single, "1", "\x00\xe4\r\n"},
		{multi, "2", "\x00bin"},
	} {
		out := base64NULParts([]byte(tc.raw))
		if bytes.IndexByte(out, 0) >= 0 {
			t.Fatalf("NUL left in %q", out)
		}
		if got, err := binarySection(out, tc.section); err != nil || string(got) != tc.body {
			t.Errorf("BINARY[%s] = %q, %v; want %q", tc.section, got, err, tc.body)
		}
	}
	out := string(base64NULParts([]byte(multi)))
	for _, kept := range []string{"preamble\r\n", "kept \xe4\r\n", "--b--\r\nepilogue\r\n"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q lost from %q", kept, out)
		}
	}
	if string(base64NULParts([]byte("Subject: x\r\n\r\nno nul\r\n"))) != "Subject: x\r\n\r\nno nul\r\n" {
		t.Error("message without NUL changed")
	}
}
