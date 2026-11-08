package smtp

import "testing"

// RFC 8601 §5: fields claiming our authserv-id are removed (with folding); others stay; body untouched.
func TestStripAndPrependAuthResults(t *testing.T) {
	t.Parallel()
	raw := "Authentication-Results: MX.example.net; spf=pass\r\n\tsmtp.mailfrom=forged@example.org\r\n" +
		"Authentication-Results: mx.google.com; dkim=pass header.d=example.org\r\n" +
		"Subject: hi\r\n\r\nAuthentication-Results: mx.example.net; body line stays\r\n"
	got := string(prependAuthResults([]byte(raw), "mx.example.net", "mx.example.net;\r\n\tspf=fail smtp.mailfrom=a@example.org"))
	want := "Authentication-Results: mx.example.net;\r\n\tspf=fail smtp.mailfrom=a@example.org\r\n" +
		"Authentication-Results: mx.google.com; dkim=pass header.d=example.org\r\n" +
		"Subject: hi\r\n\r\nAuthentication-Results: mx.example.net; body line stays\r\n"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}

	// LF-stored messages get LF folding, not mixed line endings.
	lf := string(prependAuthResults([]byte("Subject: hi\n\nbody\n"), "mx.example.net", "mx.example.net;\r\n\tspf=pass smtp.mailfrom=a@example.org"))
	if lf != "Authentication-Results: mx.example.net;\n\tspf=pass smtp.mailfrom=a@example.org\nSubject: hi\n\nbody\n" {
		t.Fatalf("lf %q", lf)
	}
}
