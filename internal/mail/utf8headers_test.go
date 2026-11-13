package mail

import "testing"

// RFC 6531 3.2: a message needs SMTPUTF8 when a header field holds UTF-8 at any MIME level; an
// 8-bit body alone needs only 8BITMIME.
func TestHas8BitHeaders(t *testing.T) {
	for raw, want := range map[string]bool{
		"Subject: caf\xc3\xa9\r\n\r\nbody\r\n":           true,
		"Subject: s\r\n\r\ncaf\xc3\xa9\r\n":              false,
		"Subject: s\r\nContent-Type: text/plain\r\n\r\n": false,
		"Subject: s\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain; name=\"caf\xc3\xa9.txt\"\r\n\r\nx\r\n--b--\r\n":       true,
		"Subject: s\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\ncaf\xc3\xa9\r\n--b--\r\n":                       false,
		"Subject: s\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: message/rfc822\r\n\r\nSubject: caf\xc3\xa9\r\n\r\nx\r\n--b--\r\n": true,
		"Subject: s\r\nContent-Type: message/global\r\n\r\nFrom: \xce\xb4@example.org\r\n\r\nx\r\n":                                                            true,
	} {
		if got := Has8BitHeaders([]byte(raw)); got != want {
			t.Errorf("%q: %v, want %v", raw, got, want)
		}
	}
}
