package smtp

import "testing"

// Plugin headers must start on their own line after the last header, keeping one blank line before the body.
func TestAppendFilterHeaders(t *testing.T) {
	headers := map[string]string{"X-Spam-Score": "ham, score=1.40", "X-Spam-Result": "RCVD_COUNT_ZERO (0.10)"}
	for _, tc := range []struct{ in, want string }{
		{
			"Content-Type: multipart/alternative; boundary=\"b1\"\r\n\r\n--b1\r\n",
			"Content-Type: multipart/alternative; boundary=\"b1\"\r\nX-Spam-Result: RCVD_COUNT_ZERO (0.10)\r\nX-Spam-Score: ham, score=1.40\r\n\r\n--b1\r\n",
		},
		{
			"Subject: hi\n\nbody\n",
			"Subject: hi\nX-Spam-Result: RCVD_COUNT_ZERO (0.10)\r\nX-Spam-Score: ham, score=1.40\r\n\nbody\n",
		},
	} {
		if got := string(appendFilterHeaders([]byte(tc.in), headers)); got != tc.want {
			t.Fatalf("in %q\ngot  %q\nwant %q", tc.in, got, tc.want)
		}
	}
}
