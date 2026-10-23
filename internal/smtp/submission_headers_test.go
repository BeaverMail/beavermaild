package smtp

import (
	"bytes"
	netmail "net/mail"
	"strings"
	"testing"
	"time"
)

func TestCompleteSubmission(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	const valid = "From: alice@example.com\r\nDate: Thu, 01 Jan 2026 10:00:00 +0000\r\n" +
		"Message-ID: <abc@example.com>\r\nSubject: hi\r\n\r\nbody\r\n"

	if got := completeSubmission([]byte(valid), "mx.example.com", now); !bytes.Equal(got, []byte(valid)) {
		t.Fatalf("valid message changed:\n%s", got)
	}

	cases := map[string]string{
		"missing both": "From: alice@example.com\r\nSubject: hi\r\n\r\nbody\r\n",
		"malformed":    "From: alice@example.com\r\nDate: yesterday\r\nMessage-ID: not-an-id\r\nSubject: hi\r\n\r\nbody\r\n",
		"LF only":      "From: alice@example.com\nSubject: hi\n\nbody\n",
	}
	for name, in := range cases {
		got := completeSubmission([]byte(in), "mx.example.com", now)
		msg, err := netmail.ReadMessage(bytes.NewReader(got))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if ids := msg.Header["Message-Id"]; len(ids) != 1 || !msgIDRe.MatchString(ids[0]) || !strings.HasSuffix(ids[0], "@mx.example.com>") {
			t.Errorf("%s: Message-ID %q", name, ids)
		}
		if dates := msg.Header["Date"]; len(dates) != 1 || dates[0] != now.Format(time.RFC1123Z) {
			t.Errorf("%s: Date %q", name, dates)
		}
		if !bytes.HasSuffix(got, []byte("body\r\n")) && !bytes.HasSuffix(got, []byte("body\n")) {
			t.Errorf("%s: body changed:\n%s", name, got)
		}
		if strings.Contains(name, "LF") && bytes.Contains(got, []byte("\r\n")) {
			t.Errorf("%s: mixed line endings:\n%q", name, got)
		}
	}
}
