package smtp

import "testing"

// RFC 8601 §5: fields claiming our authserv-id are removed (with folding); others stay; body untouched.
func TestStripAuthResults(t *testing.T) {
	t.Parallel()
	raw := "Authentication-Results: MX.example.net; spf=pass\r\n\tsmtp.mailfrom=forged@example.org\r\n" +
		"Authentication-Results: mx.google.com; dkim=pass header.d=example.org\r\n" +
		"Subject: hi\r\n\r\nAuthentication-Results: mx.example.net; body line stays\r\n"
	got := string(prependHeader(stripAuthResults([]byte(raw), "mx.example.net"), "Authentication-Results", "mx.example.net;\r\n\tspf=fail smtp.mailfrom=example.org"))
	want := "Authentication-Results: mx.example.net;\r\n\tspf=fail smtp.mailfrom=example.org\r\n" +
		"Authentication-Results: mx.google.com; dkim=pass header.d=example.org\r\n" +
		"Subject: hi\r\n\r\nAuthentication-Results: mx.example.net; body line stays\r\n"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}

	// LF-stored messages get LF folding, not mixed line endings.
	lf := string(prependHeader([]byte("Subject: hi\n\nbody\n"), "Authentication-Results", "mx.example.net;\r\n\tspf=pass smtp.mailfrom=example.org"))
	if lf != "Authentication-Results: mx.example.net;\n\tspf=pass smtp.mailfrom=example.org\nSubject: hi\n\nbody\n" {
		t.Fatalf("lf %q", lf)
	}
}

// A5 (RFC 8601 audit): the authserv-id is recognized however the grammar lets a sender write it.
// Before, only the first line was looked at and a comment in front hid the id.
func TestStripAuthResultsForms(t *testing.T) {
	t.Parallel()
	for _, forged := range []string{
		"Authentication-Results:\r\n\tmx.example.net; dkim=pass header.d=bank.example\r\n",
		"Authentication-Results: (trusted) mx.example.net; dkim=pass header.d=bank.example\r\n",
		"Authentication-Results: (a (nested) one)\r\n mx.example.net 1; dkim=pass\r\n",
		"Authentication-Results: \"mx.example.net\"; dkim=pass\r\n",
		"Authentication-Results: mx.example.net.; dkim=pass\r\n", // review R2: absolute form
	} {
		got := string(stripAuthResults([]byte(forged+"Subject: hi\r\n\r\nbody\r\n"), "mx.example.net"))
		if got != "Subject: hi\r\n\r\nbody\r\n" {
			t.Errorf("kept %q", forged)
		}
	}
	other := "Authentication-Results: (mx.example.net) mx.google.com; dkim=pass\r\nSubject: hi\r\n\r\nx\r\n"
	if got := string(stripAuthResults([]byte(other), "mx.example.net")); got != other {
		t.Fatalf("another server's field dropped: %q", got)
	}
}
