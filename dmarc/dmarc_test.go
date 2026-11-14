package dmarc

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// zone serves _dmarc TXT records; names not listed do not exist. Queried names are recorded.
type zone struct {
	txt     map[string][]string
	missing map[string]bool // NXDOMAIN for Exists
	fail    string          // a name answering SERVFAIL
	asked   []string
}

func (z *zone) resolver() Resolver {
	return Resolver{
		LookupTXT: func(_ context.Context, name string) ([]string, error) {
			z.asked = append(z.asked, name)
			if name == z.fail {
				return nil, &net.DNSError{Err: "server misbehaving", Name: name, IsTemporary: true}
			}
			if t, ok := z.txt[name]; ok {
				return t, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
		},
		Exists: func(_ context.Context, d string) (bool, error) { return !z.missing[d], nil },
	}
}

func eval(z *zone, author, spf string, dkim ...string) Result {
	return Evaluate(context.Background(), z.resolver(), author, spf, dkim)
}

func rec(s string) []string { return []string{s} }

// D1: a subdomain without its own record gets the Organizational Domain's policy (4.10.1); before,
// only _dmarc.<author> was queried and any invented subdomain escaped p=reject with "none".
func TestPolicyDiscoveryWalksUp(t *testing.T) {
	t.Parallel()
	z := &zone{txt: map[string][]string{"_dmarc.victim.example": rec("v=DMARC1; p=reject")}}
	if r := eval(z, "billing.victim.example", ""); r != (Result{Fail, "reject"}) {
		t.Fatalf("subdomain: %+v", r)
	}
	if r := eval(z, "other.example", ""); r.Result != None {
		t.Fatalf("no record anywhere: %+v", r)
	}
}

// D5: sp for existing subdomains, np for non-existent ones, p for the domain itself.
func TestSubdomainPolicies(t *testing.T) {
	t.Parallel()
	z := &zone{
		txt:     map[string][]string{"_dmarc.victim.example": rec("v=DMARC1; p=none; sp=quarantine; np=reject")},
		missing: map[string]bool{"ghost.victim.example": true},
	}
	for author, want := range map[string]string{
		"victim.example":       "none",
		"mail.victim.example":  "quarantine",
		"ghost.victim.example": "reject",
	} {
		if r := eval(z, author, ""); r != (Result{Fail, want}) {
			t.Errorf("%s: %+v, want %s", author, r, want)
		}
	}
	// np absent: sp applies to non-existent subdomains too.
	z.txt["_dmarc.victim.example"] = rec("v=DMARC1; p=none; sp=quarantine")
	if r := eval(z, "ghost.victim.example", ""); r.Policy != "quarantine" {
		t.Fatalf("np absent: %+v", r)
	}
}

// D2: relaxed alignment through the Organizational Domain found by the Tree Walk (4.10.2).
func TestAlignment(t *testing.T) {
	t.Parallel()
	z := &zone{txt: map[string][]string{
		"_dmarc.victim.example":   rec("v=DMARC1; p=reject"),
		"_dmarc.strict.example":   rec("v=DMARC1; p=reject; adkim=s; aspf=s"),
		"_dmarc.hosted.example":   rec("v=DMARC1; p=none; psd=y"),
		"_dmarc.a.hosted.example": rec("v=DMARC1; p=reject"),
	}}
	for _, tc := range []struct {
		author, spf, dkim, want string
	}{
		{"news.victim.example", "", "mail.victim.example", Pass},
		{"news.victim.example", "bounce.victim.example", "", Pass},
		{"victim.example", "", "attacker.example", Fail},
		{"news.victim.example", "", "mail.victim.example", Pass},
		{"strict.example", "", "mail.strict.example", Fail},
		{"strict.example", "strict.example", "", Pass},
		// psd=y: a.hosted.example and b.hosted.example are different organizations.
		{"a.hosted.example", "", "b.hosted.example", Fail},
		{"a.hosted.example", "", "x.a.hosted.example", Pass},
	} {
		var dkim []string
		if tc.dkim != "" {
			dkim = []string{tc.dkim}
		}
		if r := eval(z, tc.author, tc.spf, dkim...); r.Result != tc.want {
			t.Errorf("%s spf=%q dkim=%q: %+v, want %s", tc.author, tc.spf, tc.dkim, r, tc.want)
		}
	}
}

// 4.10.2: records at mail.example.com and example.com make example.com the Organizational Domain;
// psd=n stops the walk at the domain carrying it.
func TestOrgDomainSelection(t *testing.T) {
	t.Parallel()
	z := &zone{txt: map[string][]string{
		"_dmarc.mail.example.com": rec("v=DMARC1; p=none"),
		"_dmarc.example.com":      rec("v=DMARC1; p=none"),
		"_dmarc.corp.example.net": rec("v=DMARC1; p=none; psd=n"),
		"_dmarc.example.net":      rec("v=DMARC1; p=none"),
		"_dmarc.test":             rec("v=DMARC1; p=none; psd=y"),
	}}
	for in, want := range map[string]string{
		"a.mail.example.com": "example.com",
		"a.corp.example.net": "corp.example.net",
		"x.y.example.org":    "x.y.example.org", // no record anywhere: the domain itself
		"shop.test":          "shop.test",       // _dmarc.test psd=y: one label below
		"a.b.shop.test":      "shop.test",
	} {
		w := &walker{ctx: context.Background(), r: z.resolver(), seen: map[string]answer{}}
		if got, err := w.orgDomain(in); err != nil || got != want {
			t.Errorf("orgDomain(%s) = %q %v, want %q", in, got, err, want)
		}
	}
}

// 4.10: at most 8 queries, from 8 labels on cut to 7 after the first.
func TestTreeWalkQueryLimit(t *testing.T) {
	t.Parallel()
	z := &zone{}
	eval(z, "a.b.c.d.e.f.g.h.i.j.mail.example.com", "")
	want := []string{
		"_dmarc.a.b.c.d.e.f.g.h.i.j.mail.example.com", "_dmarc.g.h.i.j.mail.example.com",
		"_dmarc.h.i.j.mail.example.com", "_dmarc.i.j.mail.example.com", "_dmarc.j.mail.example.com",
		"_dmarc.mail.example.com", "_dmarc.example.com", "_dmarc.com",
	}
	if strings.Join(z.asked, " ") != strings.Join(want, " ") {
		t.Fatalf("queries %v", z.asked)
	}
}

// D4: record parsing per 4.7/4.8 and 4.10.1.
func TestRecordParsing(t *testing.T) {
	t.Parallel()
	for txt, want := range map[string]Result{
		"v=DMARC1; p=reject; pct=abc; ri=x; rf=junk; fo=9": {Fail, "reject"}, // was permerror
		"v=DMARC1; p=reject; adkim=x":                      {Fail, "reject"}, // bad value: default
		"v=DMARC1; rua=mailto:r@victim.example":            {Fail, "none"},   // no p, valid rua
		"v=DMARC1; p=bogus; rua=mailto:r@victim.example":   {Fail, "none"},
		"v=DMARC1; p=bogus":                                {None, ""}, // no p, no rua
		"v=DMARC1; p=reject; sp=bogus":                     {None, ""},
		"p=reject; v=DMARC1":                               {None, ""}, // v not first
		"v=dmarc1; p=reject":                               {None, ""}, // case-sensitive
		"v = DMARC1 ; P = Reject":                          {Fail, "reject"},
		"V=DMARC1; p=reject":                               {Fail, "reject"},     // review C1: tag names are case-insensitive
		"v=DMARC1; p=reject; t=y":                          {Fail, "quarantine"}, // D6
		"v=DMARC1; p=quarantine; t=y":                      {Fail, "none"},
		"v=DMARC1; p=reject; future=1":                     {Fail, "reject"},
	} {
		z := &zone{txt: map[string][]string{"_dmarc.victim.example": rec(txt)}}
		if r := eval(z, "victim.example", ""); r != want {
			t.Errorf("%q: %+v, want %+v", txt, r, want)
		}
	}
	// Two DMARC records: both discarded (4.10 step 2); other TXT records do not count.
	z := &zone{txt: map[string][]string{"_dmarc.victim.example": {"v=DMARC1; p=reject", "v=DMARC1; p=none"}}}
	if r := eval(z, "victim.example", ""); r.Result != None {
		t.Fatalf("two records: %+v", r)
	}
	z.txt["_dmarc.victim.example"] = []string{"site-verification=x", "v=DMARC1; p=reject"}
	if r := eval(z, "victim.example", ""); r != (Result{Fail, "reject"}) {
		t.Fatalf("one DMARC record among others: %+v", r)
	}
}

// 5.3.6: a DNS failure in the walk is neither pass nor fail.
func TestDNSFailure(t *testing.T) {
	t.Parallel()
	z := &zone{txt: map[string][]string{"_dmarc.victim.example": rec("v=DMARC1; p=reject")}, fail: "_dmarc.victim.example"}
	if r := eval(z, "victim.example", ""); r.Result != TempError {
		t.Fatalf("policy lookup: %+v", r)
	}
	// Review: an identifier outside the author's Organizational Domain is not looked up, so a sender
	// whose own DNS fails cannot turn the victim's fail into temperror.
	z.fail = "_dmarc.sender.example"
	if r := eval(z, "victim.example", "", "mail.sender.example"); r != (Result{Fail, "reject"}) {
		t.Fatalf("failing DNS of an unrelated signer: %+v", r)
	}
	for _, q := range z.asked {
		if strings.HasSuffix(q, "sender.example") {
			t.Fatalf("queried %s", q)
		}
	}
	// Inside the author's organization a failing walk stays temperror.
	z.fail = "_dmarc.mail.victim.example"
	if r := eval(z, "victim.example", "", "x.mail.victim.example"); r.Result != TempError {
		t.Fatalf("alignment walk: %+v", r)
	}
}

// Review S4: a failed existence query applies sp (or p) instead of no policy at all.
func TestExistsErrorKeepsSubdomainPolicy(t *testing.T) {
	t.Parallel()
	z := &zone{txt: map[string][]string{"_dmarc.victim.example": rec("v=DMARC1; p=reject; sp=quarantine; np=reject")}}
	r := z.resolver()
	r.Exists = func(context.Context, string) (bool, error) { return false, errors.New("resolver down") }
	if got := Evaluate(context.Background(), r, "ghost.victim.example", "", nil); got != (Result{Fail, "quarantine"}) {
		t.Fatalf("%+v", got)
	}
}
