package spf

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// zone is a recursive resolver over records in presentation format ("example.com TXT ..."), plus
// "SERVFAIL <name>" and "TIMEOUT <name>" lines. A name exists when it owns any record.
type zone struct {
	rrs  map[string][]dns.RR
	fail map[string]string
}

func newZone(t *testing.T, lines ...string) *zone {
	t.Helper()
	z := &zone{rrs: map[string][]dns.RR{}, fail: map[string]string{}}
	for _, l := range lines {
		if kind, name, ok := strings.Cut(l, " "); ok && (kind == "SERVFAIL" || kind == "TIMEOUT") {
			z.fail[dns.Fqdn(strings.ToLower(name))] = kind
			continue
		}
		rr, err := dns.NewRR(l)
		if err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		name := strings.ToLower(rr.Header().Name)
		z.rrs[name] = append(z.rrs[name], rr)
	}
	return z
}

func (z *zone) Resolve(_ context.Context, q *dns.Msg) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetReply(q)
	name, qtype := strings.ToLower(q.Question[0].Name), q.Question[0].Qtype
	for hops := 0; hops < 8; hops++ {
		switch z.fail[name] {
		case "TIMEOUT":
			return nil, errors.New("timeout")
		case "SERVFAIL":
			m.Rcode = dns.RcodeServerFailure
			return m, nil
		}
		rrs, ok := z.rrs[name]
		if !ok {
			m.Rcode = dns.RcodeNameError
			return m, nil
		}
		next := ""
		for _, rr := range rrs {
			if rr.Header().Rrtype == qtype {
				m.Answer = append(m.Answer, rr)
			} else if c, ok := rr.(*dns.CNAME); ok {
				m.Answer = append(m.Answer, rr)
				next = strings.ToLower(c.Target)
			}
		}
		if next == "" {
			return m, nil
		}
		name = next
	}
	m.Rcode = dns.RcodeServerFailure
	return m, nil
}

type rfcCase struct {
	name   string
	zone   []string
	ip     string // default 192.0.2.10
	sender string // default alice@example.com; its domain is checked
	helo   string // default mail.example.net
	want   Result
}

func runRFCCases(t *testing.T, cases []rfcCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, sender, helo := tc.ip, tc.sender, tc.helo
			if ip == "" {
				ip = "192.0.2.10"
			}
			if sender == "" {
				sender = "alice@example.com"
			}
			if helo == "" {
				helo = "mail.example.net"
			}
			domain := sender[strings.LastIndexByte(sender, '@')+1:]
			c := &Checker{Resolver: newZone(t, tc.zone...)}
			if got := c.CheckHost(context.Background(), net.ParseIP(ip), domain, sender, helo); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// RFC 7208 4.3-4.5: initial processing, record lookup, record selection.
func TestRFCRecordLookup(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("x", 64)
	runRFCCases(t, []rfcCase{
		{name: "label over 63", sender: "a@" + long + ".example.com", want: None},
		{name: "label of 63", sender: "a@" + long[:63] + ".example.com", zone: []string{long[:63] + `.example.com TXT "v=spf1 -all"`}, want: Fail},
		{name: "empty label", sender: "a@a..example.com", want: None},
		{name: "single label", sender: "a@localhost", zone: []string{`localhost TXT "v=spf1 +all"`}, want: None},
		{name: "nxdomain", want: None},
		{name: "no TXT", zone: []string{"example.com A 192.0.2.1"}, want: None},
		{name: "servfail", zone: []string{"SERVFAIL example.com"}, want: TempError},
		{name: "timeout", zone: []string{"TIMEOUT example.com"}, want: TempError},
		{name: "two records", zone: []string{`example.com TXT "v=spf1 -all"`, `example.com TXT "v=spf1 +all"`}, want: PermError},
		{name: "v=spf10 is not a version", zone: []string{`example.com TXT "v=spf10 +all"`}, want: None},
		{name: "version case-insensitive", zone: []string{`example.com TXT "V=SPF1 -all"`}, want: Fail},
		{name: "strings joined without space", zone: []string{`example.com TXT "v=spf1 ip4:192.0.2.10" " -all"`}, want: Pass},
		{name: "other TXT ignored", zone: []string{`example.com TXT "site-verification=x"`, `example.com TXT "v=spf1 -all"`}, want: Fail},
		{name: "trailing spaces", zone: []string{`example.com TXT "v=spf1 -all   "`}, want: Fail},
	})
}

// 4.6: the whole record is checked before evaluation; any syntax error is permerror.
func TestRFCSyntax(t *testing.T) {
	t.Parallel()
	rec := func(r string) []string { return []string{`example.com TXT "` + r + `"`} }
	runRFCCases(t, []rfcCase{
		{name: "unknown mechanism", zone: rec("v=spf1 frobnicate -all"), want: PermError},
		{name: "error after a match", zone: rec("v=spf1 ip4:192.0.2.10 frobnicate"), want: PermError},
		{name: "ip4 leading zero", zone: rec("v=spf1 ip4:192.0.2.010 -all"), want: PermError},
		{name: "ip4 prefix 33", zone: rec("v=spf1 ip4:192.0.2.0/33 -all"), want: PermError},
		{name: "ip4 prefix padded", zone: rec("v=spf1 ip4:192.0.2.0/024 -all"), want: PermError},
		{name: "ip4 short form", zone: rec("v=spf1 ip4:192.0.2 -all"), want: PermError},
		{name: "ip6 with an IPv4", zone: rec("v=spf1 ip6:192.0.2.10 -all"), want: PermError},
		{name: "ip6 prefix 129", zone: rec("v=spf1 ip6:2001:db8::/129 -all"), want: PermError},
		{name: "a with empty spec", zone: rec("v=spf1 a: -all"), want: PermError},
		{name: "spec without top label", zone: rec("v=spf1 a:example -all"), want: PermError},
		{name: "numeric top label", zone: rec("v=spf1 a:example.123 -all"), want: PermError},
		{name: "include needs a spec", zone: rec("v=spf1 include -all"), want: PermError},
		{name: "all with an argument", zone: rec("v=spf1 all:example.com"), want: PermError},
		{name: "redirect twice", zone: rec("v=spf1 redirect=a.example.org redirect=b.example.org"), want: PermError},
		{name: "exp twice", zone: rec("v=spf1 -all exp=a.example.org exp=b.example.org"), want: PermError},
		{name: "unknown modifier ignored", zone: rec("v=spf1 future=anything.%{d} -all"), want: Fail},
		{name: "bad modifier name", zone: rec("v=spf1 9x=y -all"), want: PermError},
		{name: "tab is not a separator", zone: []string{"example.com TXT \"v=spf1 ip4:192.0.2.1\t-all\""}, want: PermError},
		{name: "tab ends no version section", zone: []string{"example.com TXT \"v=spf1\t-all\""}, want: None},
		{name: "lone percent", zone: rec("v=spf1 exists:%x.example.org -all"), want: PermError},
		{name: "unclosed macro", zone: rec("v=spf1 exists:%{d.example.org -all"), want: PermError},
		{name: "exp-only letter in a domain-spec", zone: rec("v=spf1 exists:%{c}.example.org -all"), want: PermError},
		{name: "zero digit transformer", zone: rec("v=spf1 exists:%{d0}.example.org -all"), want: PermError},
		{name: "bad delimiter", zone: rec("v=spf1 exists:%{d:}.example.org -all"), want: PermError},
		{name: "mechanism names case-insensitive", zone: rec("v=spf1 IP4:192.0.2.10 -ALL"), want: Pass},
		{name: "spec with colon and slash", zone: append(rec("v=spf1 a:h:x/y.example.org -all"), "h:x/y.example.org A 192.0.2.10"), want: Pass},
	})
}

// 4.6.2, 4.7, 5.1, 5.6: qualifiers, default result, all, ip4/ip6.
func TestRFCBasicMechanisms(t *testing.T) {
	t.Parallel()
	rec := func(r string) []string { return []string{`example.com TXT "` + r + `"`} }
	runRFCCases(t, []rfcCase{
		{name: "pass", zone: rec("v=spf1 +all"), want: Pass},
		{name: "fail", zone: rec("v=spf1 -all"), want: Fail},
		{name: "softfail", zone: rec("v=spf1 ~all"), want: SoftFail},
		{name: "neutral", zone: rec("v=spf1 ?all"), want: Neutral},
		{name: "no match is neutral", zone: rec("v=spf1 ip4:198.51.100.1"), want: Neutral},
		{name: "terms after all ignored", zone: rec("v=spf1 -all ip4:192.0.2.10"), want: Fail},
		{name: "redirect ignored with all", zone: append(rec("v=spf1 ?all redirect=r.example.org"), `r.example.org TXT "v=spf1 +all"`), want: Neutral},
		{name: "ip4 cidr", zone: rec("v=spf1 ip4:192.0.2.0/24 -all"), want: Pass},
		{name: "ip4 exact", zone: rec("v=spf1 ip4:192.0.2.11 -all"), want: Fail},
		{name: "ip6 client vs ip4", ip: "2001:db8::10", zone: rec("v=spf1 ip4:192.0.2.0/24 -all"), want: Fail},
		{name: "ip6 cidr", ip: "2001:db8::10", zone: rec("v=spf1 ip6:2001:db8::/32 -all"), want: Pass},
		{name: "ipv4-mapped client vs ip4", ip: "::ffff:192.0.2.10", zone: rec("v=spf1 ip4:192.0.2.10 -all"), want: Pass},
		{name: "ipv4 client vs ip6 ::/0", zone: rec("v=spf1 ip6:::/0 -all"), want: Fail},
	})
}

// 5.2-5.5, 5.7, 6.1: DNS mechanisms and redirect.
func TestRFCDNSMechanisms(t *testing.T) {
	t.Parallel()
	rec := func(r string) string { return `example.com TXT "` + r + `"` }
	runRFCCases(t, []rfcCase{
		{name: "include pass", zone: []string{rec("v=spf1 include:i.example.org -all"), `i.example.org TXT "v=spf1 ip4:192.0.2.10 -all"`}, want: Pass},
		{name: "include fail is no match", zone: []string{rec("v=spf1 include:i.example.org ~all"), `i.example.org TXT "v=spf1 -all"`}, want: SoftFail},
		{name: "-include of a pass", zone: []string{rec("v=spf1 -include:i.example.org +all"), `i.example.org TXT "v=spf1 +all"`}, want: Fail},
		{name: "include of no record", zone: []string{rec("v=spf1 include:i.example.org -all")}, want: PermError},
		{name: "include temperror", zone: []string{rec("v=spf1 include:i.example.org -all"), "SERVFAIL i.example.org"}, want: TempError},
		{name: "include permerror", zone: []string{rec("v=spf1 include:i.example.org -all"), `i.example.org TXT "v=spf1 bogus"`}, want: PermError},
		{name: "include loop", zone: []string{rec("v=spf1 include:example.com -all")}, want: PermError},
		{name: "a on the domain", zone: []string{rec("v=spf1 a -all"), "example.com A 192.0.2.10"}, want: Pass},
		{name: "a with cidr", zone: []string{rec("v=spf1 a:h.example.org/24 -all"), "h.example.org A 192.0.2.99"}, want: Pass},
		{name: "a ipv6 dual cidr", ip: "2001:db8::99", zone: []string{rec("v=spf1 a:h.example.org/24//64 -all"), "h.example.org AAAA 2001:db8::1"}, want: Pass},
		{name: "a through CNAME", zone: []string{rec("v=spf1 a:alias.example.org -all"), "alias.example.org CNAME h.example.org.", "h.example.org A 192.0.2.10"}, want: Pass},
		{name: "a servfail", zone: []string{rec("v=spf1 a:h.example.org -all"), "SERVFAIL h.example.org"}, want: TempError},
		{name: "mx", zone: []string{rec("v=spf1 mx -all"), "example.com MX 10 mx1.example.com.", "mx1.example.com A 192.0.2.10"}, want: Pass},
		{name: "mx is not implicit", zone: []string{rec("v=spf1 mx -all"), "example.com A 192.0.2.10"}, want: Fail},
		{name: "mx over 10 names", zone: append([]string{rec("v=spf1 mx -all")}, mxRecords(11)...), want: PermError},
		{name: "mx 10 names", zone: append(append([]string{rec("v=spf1 mx -all")}, mxRecords(10)...), "mx9.example.com A 192.0.2.10"), want: Pass},
		{name: "ptr validated", zone: []string{rec("v=spf1 ptr -all"), "10.2.0.192.in-addr.arpa PTR mail.example.com.", "mail.example.com A 192.0.2.10"}, want: Pass},
		{name: "ptr not validated", zone: []string{rec("v=spf1 ptr -all"), "10.2.0.192.in-addr.arpa PTR mail.example.com.", "mail.example.com A 192.0.2.77"}, want: Fail},
		{name: "ptr outside the target", zone: []string{rec("v=spf1 ptr -all"), "10.2.0.192.in-addr.arpa PTR mail.example.net.", "mail.example.net A 192.0.2.10"}, want: Fail},
		{name: "ptr servfail does not match", zone: []string{rec("v=spf1 ptr ?all"), "SERVFAIL 10.2.0.192.in-addr.arpa"}, want: Neutral},
		{name: "exists", zone: []string{rec("v=spf1 exists:%{i}.ok.example.org -all"), "192.0.2.10.ok.example.org A 127.0.0.2"}, want: Pass},
		{name: "exists asks A for IPv6 clients", ip: "2001:db8::10", zone: []string{rec("v=spf1 exists:ok.example.org -all"), "ok.example.org A 127.0.0.2"}, want: Pass},
		{name: "redirect", zone: []string{rec("v=spf1 redirect=r.example.org"), `r.example.org TXT "v=spf1 ip4:192.0.2.10 -all"`}, want: Pass},
		{name: "redirect keeps the sender domain in %{o}", zone: []string{rec("v=spf1 redirect=r.example.org"), `r.example.org TXT "v=spf1 exists:%{o}.%{d}.x.example.org -all"`, "example.com.r.example.org.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "redirect to no record", zone: []string{rec("v=spf1 redirect=r.example.org")}, want: PermError},
		{name: "redirect loop", zone: []string{rec("v=spf1 redirect=example.com")}, want: PermError},
		{name: "two void lookups", zone: []string{rec("v=spf1 a:v1.example.org a:v2.example.org ?all")}, want: Neutral},
		{name: "three void lookups", zone: []string{rec("v=spf1 a:v1.example.org a:v2.example.org a:v3.example.org ?all")}, want: PermError},
	})
}

func mxRecords(n int) []string {
	var out []string
	for i := range n {
		out = append(out, "example.com MX 10 mx"+string(rune('0'+i%10))+strings.Repeat("x", i/10)+".example.com.")
	}
	return out
}

// 7: macro expansion.
func TestRFCMacros(t *testing.T) {
	t.Parallel()
	rec := func(r string) string { return `example.com TXT "` + r + `"` }
	longLocal := strings.Repeat("abcdefghi.", 30) + "end"
	runRFCCases(t, []rfcCase{
		{name: "s l o d", zone: []string{rec("v=spf1 exists:%{l}.%{o}.%{d1}.x.example.org -all"), "alice.example.com.com.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "uppercase is URL-escaped", sender: "a+b@example.com", zone: []string{rec("v=spf1 exists:%{L}.x.example.org -all"), "a%2Bb.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "delimiters and reverse", sender: "first-last@example.com", zone: []string{rec("v=spf1 exists:%{lr-}.x.example.org -all"), "last.first.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "escapes", zone: []string{rec("v=spf1 exists:p%%q%-r.example.org -all"), "p%q%20r.example.org A 127.0.0.2"}, want: Pass},
		{name: "h is the HELO", zone: []string{rec("v=spf1 exists:%{h}.x.example.org -all"), "mail.example.net.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "v and ir", zone: []string{rec("v=spf1 exists:%{ir}.%{v}.x.example.org -all"), "10.2.0.192.in-addr.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "p validated name", zone: []string{rec("v=spf1 exists:%{p}.x.example.org -all"), "10.2.0.192.in-addr.arpa PTR mail.example.com.", "mail.example.com A 192.0.2.10", "mail.example.com.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "p unknown", zone: []string{rec("v=spf1 exists:%{p}.x.example.org -all"), "unknown.x.example.org A 127.0.0.2"}, want: Pass},
		{name: "truncated to 253 from the left", sender: longLocal + "@example.com",
			zone: []string{rec("v=spf1 exists:%{l}.example.com -all"), strings.Repeat("abcdefghi.", 23) + "end.example.com A 127.0.0.2"}, want: Pass},
		{name: "unknown modifier may use exp letters", zone: []string{rec("v=spf1 note=%{c}%{r}%{t} -all")}, want: Fail},
	})
}
