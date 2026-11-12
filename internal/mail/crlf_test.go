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

// Bare CR as Exim treats it: a folded continuation in the header (never an empty line that ends
// the header, never a new field), a line end in the body. "\r\r\n" used to become "\r\n\r\n".
func TestBareCR(t *testing.T) {
	for in, want := range map[string]string{
		"Subject: a\r\r\nX: y\r\n\r\nbody\r\n":         "Subject: a\r\n \r\nX: y\r\n\r\nbody\r\n",
		"Subject: a\rBcc: victim@example.org\r\n\r\nb": "Subject: a\r\n Bcc: victim@example.org\r\n\r\nb",
		"S: x\n\nbody\rmore\r\r\n":                     "S: x\r\n\r\nbody\r\nmore\r\n\r\n",
		"S: x\r\n\r\nend\r":                            "S: x\r\n\r\nend\r\n",
		"clean\r\n\r\nbody\r\n":                        "clean\r\n\r\nbody\r\n",
	} {
		if got := string(CRLF([]byte(in))); got != want {
			t.Errorf("CRLF(%q) = %q want %q", in, got, want)
		}
	}
	if got := string(BareCR([]byte("S: a\rb\n\nc\rd"))); got != "S: a\n b\n\nc\nd" {
		t.Errorf("BareCR = %q", got)
	}
}
