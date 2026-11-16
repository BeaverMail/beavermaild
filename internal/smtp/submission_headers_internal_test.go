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

// RFC 5322 3.6, RFC 9989 4.4 and 11.5: on port 25 a From that DMARC cannot read, or that hides a
// second address, is refused, since MUAs read such fields their own way. The cases are those where
// the IMAP ENVELOPE showed a domain that DMARC never checked.
func TestCheckInboundHeaders(t *testing.T) {
	t.Parallel()
	ok := []string{
		"From: Alice <alice@example.org>\r\nSubject: x\r\n\r\nbody",
		"From : alice@example.org\r\nSubject\t: x\r\n\r\nbody",  // obsolete syntax, accepted (RFC 5322 4)
		"From: \"a@bank.example\"@attacker.example\r\n\r\nbody", // one mailbox; DMARC reads attacker.example
		"From: a@example.org\r\nTo: x@example.net\r\nTo-Do: y\r\nResent-From: b@example.net\r\n\r\nbody",
	}
	for _, m := range ok {
		if why := checkInboundHeaders([]byte(m)); why != "" {
			t.Errorf("%q rejected: %s", m, why)
		}
	}
	bad := map[string]string{
		"Subject: x\r\n\r\nbody": "missing From",
		"From: a@attacker.example\r\nfrom: b@bank.example\r\n\r\nbody":  "2 From",
		"From : a@bank.example\r\nFrom: b@attacker.example\r\n\r\nbody": "2 From", // obs-from (RFC 5322 4.5.2) is a From too
		"From: Bank <a@bank.example> junk\r\n\r\nbody":                  "invalid address",
		"From: Bank <a@bank.example>, junk\r\n\r\nbody":                 "invalid address",
		"From: Bank <a@bank.example>\r\n\tjunk\r\n\r\nbody":             "invalid address",
		"From: <a@attacker.example> <b@bank.example>\r\n\r\nbody":       "invalid address",
		"From: a@attacker.example\x00<b@bank.example>\r\n\r\nbody":      "invalid address",
		"From: a@bank.example;b@attacker.example\r\n\r\nbody":           "invalid address",
		"From: a@attacker.example, b@bank.example\r\n\r\nbody":          "exactly one mailbox",
		"From: grp: a@bank.example;, b@attacker.example\r\n\r\nbody":    "exactly one mailbox",
		"From: a@example.org\r\nSubject: x\r\nSubject: y\r\n\r\nbody":   "2 Subject",
		"From: a@example.org\r\nDate: x\r\nDATE: y\r\n\r\nbody":         "2 Date",
	}
	for m, want := range bad {
		if why := checkInboundHeaders([]byte(m)); !strings.Contains(why, want) {
			t.Errorf("%q: got %q, want %q", m, why, want)
		}
	}
}
