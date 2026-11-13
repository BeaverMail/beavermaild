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
			"mx.example.net;\r\n\tspf=pass smtp.mailfrom=example.org;\r\n\tdkim=pass header.d=example.org;\r\n\tdmarc=pass header.from=example.org;\r\n\tarc=none",
		},
		{
			"null sender uses helo, dmarc policy comment", "", "mail.example.org",
			SessionState{SPFEhlo: "softfail", DMARC: "fail", DMARCPolicy: "reject", FromDomain: "example.org"},
			"mx.example.net;\r\n\tspf=softfail smtp.helo=mail.example.org;\r\n\tdmarc=fail (p=reject) header.from=example.org",
		},
		{"nothing checked", "a@example.org", "h", SessionState{}, "mx.example.net; none"},
		// A1: the HELO argument is the client's text; anything but a domain or an IP literal is left out.
		{
			"forged helo", "", "x;dkim=pass header.d=bank.example",
			SessionState{SPFEhlo: "none"}, "mx.example.net;\r\n\tspf=none",
		},
		{"helo literal", "", "[192.0.2.1]", SessionState{SPFEhlo: "none"}, "mx.example.net;\r\n\tspf=none smtp.helo=\"[192.0.2.1]\""},
		{"helo IPv6 literal", "", "[IPv6:2001:db8::1]", SessionState{SPFEhlo: "none"}, "mx.example.net;\r\n\tspf=none smtp.helo=\"[IPv6:2001:db8::1]\""},
		{"bad literal", "", "[x;y]", SessionState{SPFEhlo: "none"}, "mx.example.net;\r\n\tspf=none"},
		{"U-label helo", "", "München.example", SessionState{SPFEhlo: "pass"}, "mx.example.net;\r\n\tspf=pass smtp.helo=xn--mnchen-3ya.example"},
		// A3: arc has only none, pass and fail (RFC 8617 10.1).
		{"arc invalid", "", "", SessionState{ARC: "invalid"}, "mx.example.net;\r\n\tarc=fail"},
		{"arc temperror", "", "", SessionState{ARC: "temperror"}, "mx.example.net; none"},
		// Review: header.d comes from a d= tag, even of a failing signature; "evil(" opened a comment
		// that swallowed the DMARC result after it.
		{
			"forged d=", "", "", SessionState{DKIM: "permerror", DKIMDomain: "evil(", DMARC: "fail", DMARCPolicy: "reject", FromDomain: "bank.example"},
			"mx.example.net;\r\n\tdkim=permerror;\r\n\tdmarc=fail (p=reject) header.from=bank.example",
		},
		// Review R1: d=evil@bank.example (a failing signature) is not a domain; it was cut to bank.example.
		{"d= with @", "", "", SessionState{DKIM: "permerror", DKIMDomain: "evil@bank.example"}, "mx.example.net;\r\n\tdkim=permerror"},
		{
			"literal domains quoted", "a@[192.0.2.1]", "", SessionState{SPFMailFrom: "none", DMARC: "none", FromDomain: "[192.0.2.2]"},
			"mx.example.net;\r\n\tspf=none smtp.mailfrom=\"[192.0.2.1]\";\r\n\tdmarc=none header.from=\"[192.0.2.2]\"",
		},
	} {
		if got := AuthResults("mx.example.net", tc.mailFrom, tc.helo, tc.st); got != tc.want {
			t.Fatalf("%s:\ngot  %q\nwant %q", tc.name, got, tc.want)
		}
	}
}
