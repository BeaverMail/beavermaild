package mail

import "testing"

func TestCRLF(t *testing.T) {
	for in, want := range map[string]string{
		"a\nb\n":            "a\r\nb\r\n",
		"a\r\nb\n\nc":       "a\r\nb\r\n\r\nc",
		"\nx":               "\r\nx",
		"already\r\nok\r\n": "already\r\nok\r\n",
		"":                  "",
	} {
		if got := string(CRLF([]byte(in))); got != want {
			t.Fatalf("CRLF(%q) = %q want %q", in, got, want)
		}
	}
}
