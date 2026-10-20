package mailauth

import "testing"

func TestAuthResults(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, mailFrom, helo string
		st                   SessionState
		want                 string
	}{
		{
			"all methods", "a@example.org", "mail.example.org",
			SessionState{SPFMailFrom: "pass", DKIM: "pass", DKIMDomain: "example.org", DMARC: "pass", FromDomain: "example.org", ARC: "none"},
			"mx.example.net;\r\n\tspf=pass smtp.mailfrom=a@example.org;\r\n\tdkim=pass header.d=example.org;\r\n\tdmarc=pass header.from=example.org;\r\n\tarc=none",
		},
		{
			"null sender uses helo, dmarc policy comment", "", "mail.example.org",
			SessionState{SPFEhlo: "softfail", DMARC: "fail", DMARCPolicy: "reject", FromDomain: "example.org"},
			"mx.example.net;\r\n\tspf=softfail smtp.helo=mail.example.org;\r\n\tdmarc=fail (p=reject) header.from=example.org",
		},
		{"nothing checked", "a@example.org", "h", SessionState{}, "mx.example.net; none"},
	} {
		if got := AuthResults("mx.example.net", tc.mailFrom, tc.helo, tc.st); got != tc.want {
			t.Fatalf("%s:\ngot  %q\nwant %q", tc.name, got, tc.want)
		}
	}
}
