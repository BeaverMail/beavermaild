package smtp

import (
	"strings"
	"testing"
)

// RFC 6409 4.2, 5.1, 8: what a submission must look like before it leaves the MSA.
func TestCheckSubmissionHeaders(t *testing.T) {
	t.Parallel()
	hosted := func(d string) bool { return d == "localhost" }
	ok := []string{
		"From: Alice <alice@localhost>\r\nTo: bob@example.org\r\nSubject: x\r\n\r\nbody",
		"From: =?UTF-8?Q?J=C3=B6rg?= <j@example.org>\r\nTo: undisclosed-recipients:;\r\nBcc:\r\n\r\nbody",
		"From: a@example.org, b@example.org\r\nSender: a@example.org\r\n\r\nbody",
		"From: a@example.org\r\nCc: Friends: c@example.net, d@[192.0.2.1];\r\n\r\nbody",
		"From: a@xn--mnchen-3ya.example\r\nTo: b@münchen.example\r\n\r\nbody",
	}
	for _, m := range ok {
		if why := checkSubmissionHeaders([]byte(m), hosted); why != "" {
			t.Errorf("%q rejected: %s", m, why)
		}
	}
	bad := map[string]string{
		"To: bob@example.org\r\n\r\nbody":                                "missing From",
		"From: a@example.org\r\nFrom: b@example.org\r\n\r\nbody":         "2 From",
		"From: a@example.org\r\nSubject: x\r\nSubject: y\r\n\r\nbody":    "2 Subject",
		"From: a@example.org\r\nDate: x\r\nDate: y\r\n\r\nbody":          "2 Date",
		"From: a@example.org, b@example.org\r\n\r\nbody":                 "needs a Sender",
		"From: a@example.org\r\nSender: a@example.org, b@x.org\r\n\r\nb": "one mailbox",
		"From: a@example.org\r\nTo: bob@sales\r\n\r\nbody":               "not fully qualified in To",
		"From: alice@sales\r\n\r\nbody":                                  "not fully qualified in From",
		"From: a@example.org\r\nCc: broken\r\n\r\nbody":                  "invalid address in Cc",
		"From: a@example.org\r\nTo:\r\n\r\nbody":                         "invalid address in To",
		"From: undisclosed:;\r\n\r\nbody":                                "no mailbox in From",
		"From a@example.org\r\n\r\nbody":                                 "cannot be parsed",
	}
	for m, want := range bad {
		if why := checkSubmissionHeaders([]byte(m), hosted); !strings.Contains(why, want) {
			t.Errorf("%q: %q, want %q", m, why, want)
		}
	}
}
