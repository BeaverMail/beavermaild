package spf

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// fakeDNS answers TXT, A and PTR from maps and counts the queries.
type fakeDNS struct {
	mu      sync.Mutex
	txt     map[string]string
	a       map[string]string
	ptr     []string
	queries int
	block   bool
}

func (f *fakeDNS) Resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	f.mu.Lock()
	f.queries++
	f.mu.Unlock()
	if f.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	m := new(dns.Msg)
	m.SetReply(q)
	name := strings.ToLower(q.Question[0].Name)
	hdr := dns.RR_Header{Name: name, Class: dns.ClassINET, Rrtype: q.Question[0].Qtype}
	switch q.Question[0].Qtype {
	case dns.TypeTXT:
		if t, ok := f.txt[name]; ok {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{t}})
		} else {
			m.Rcode = dns.RcodeNameError
		}
	case dns.TypeA:
		if a, ok := f.a[name]; ok {
			m.Answer = append(m.Answer, &dns.A{Hdr: hdr, A: net.ParseIP(a)})
		}
	case dns.TypePTR:
		for _, p := range f.ptr {
			m.Answer = append(m.Answer, &dns.PTR{Hdr: hdr, Ptr: p})
		}
	}
	return m, nil
}

var client = net.ParseIP("192.0.2.9")

func check(f *fakeDNS, domain, sender string) Result {
	return (&Checker{Resolver: f}).CheckHost(context.Background(), client, domain, sender, "mail.example.org")
}

// L1 (RFC 7208 audit): 10 DNS terms are allowed, the 11th is permerror; the record lookup of
// check_host() is not a term. The previous library counted it: 10 terms gave permerror.
func TestTenTermsAllowed(t *testing.T) {
	t.Parallel()
	for n, want := range map[int]Result{10: Pass, 11: PermError} {
		f := &fakeDNS{txt: map[string]string{}, a: map[string]string{}}
		var terms []string
		for i := range n {
			h := fmt.Sprintf("h%d.example.com", i)
			terms = append(terms, "a:"+h)
			f.a[h+"."] = "192.0.2.200"
		}
		f.a[fmt.Sprintf("h%d.example.com.", n-1)] = "192.0.2.9"
		f.txt["example.com."] = "v=spf1 " + strings.Join(terms, " ") + " -all"
		if got := check(f, "example.com", "a@example.com"); got != want {
			t.Errorf("%d terms: %s, want %s", n, got, want)
		}
	}
}

// L2: ptr counts as a DNS term. The previous library did not: 40 ptr terms made 441 queries for
// one message, an amplification any sender could ask for.
func TestPTRCountsAsTerm(t *testing.T) {
	t.Parallel()
	f := &fakeDNS{txt: map[string]string{"example.com.": "v=spf1 " + strings.Repeat("ptr ", 40) + "-all"}, a: map[string]string{}}
	for i := range 10 {
		f.ptr = append(f.ptr, fmt.Sprintf("n%d.example.com.", i))
	}
	if got := check(f, "example.com", "a@example.com"); got != PermError {
		t.Fatalf("40 ptr: %s, want permerror", got)
	}
	// 10 terms x (1 PTR + 10 A) + the record: the most a record can ask for.
	if f.queries > 1+10*11 {
		t.Fatalf("%d queries", f.queries)
	}
}

// %{p} counts as a term too (4.6.4).
func TestPMacroCountsAsTerm(t *testing.T) {
	t.Parallel()
	f := &fakeDNS{txt: map[string]string{"example.com.": "v=spf1 " + strings.Repeat("exists:%{p}.x.example.com ", 6) + "-all"}, a: map[string]string{}}
	if got := check(f, "example.com", "a@example.com"); got != PermError {
		t.Fatalf("6 exists with %%{p}: %s, want permerror (12 terms)", got)
	}
}

// L3: for the HELO identity the sender is postmaster@<helo>, so %{o} and %{s} expand to it.
func TestHELOSenderMacros(t *testing.T) {
	t.Parallel()
	f := &fakeDNS{
		txt: map[string]string{"mail.example.org.": "v=spf1 exists:%{o}.%{l}.x.example.com -all"},
		a:   map[string]string{"mail.example.org.postmaster.x.example.com.": "127.0.0.2"},
	}
	if got := check(f, "mail.example.org", "postmaster@mail.example.org"); got != Pass {
		t.Fatalf("%s, want pass", got)
	}
	// A sender without local-part gets "postmaster" (4.3).
	if got := check(f, "mail.example.org", "@mail.example.org"); got != Pass {
		t.Fatalf("empty local-part: %s, want pass", got)
	}
}

// L4: an address literal or a single label is not a domain: none, with no query.
func TestNotADomain(t *testing.T) {
	t.Parallel()
	for _, d := range []string{"[192.0.2.1]", "localhost", "", "a..example.com", strings.Repeat("a", 64) + ".example.com"} {
		f := &fakeDNS{}
		if got := check(f, d, "postmaster@"+d); got != None || f.queries != 0 {
			t.Errorf("%q: %s after %d queries", d, got, f.queries)
		}
	}
}

// L5: check_host() gets at least 20 seconds (4.6.4) and a timeout is temperror.
func TestTimeout(t *testing.T) {
	t.Parallel()
	if c := (&Checker{Timeout: time.Second}); max(c.Timeout, MinTimeout) != 20*time.Second {
		t.Fatal("timeout under 20 s")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	f := &fakeDNS{block: true}
	if got := (&Checker{Resolver: f}).CheckHost(ctx, client, "example.com", "a@example.com", "h"); got != TempError {
		t.Fatalf("%s, want temperror", got)
	}
}

// Macro expansion examples of RFC 7208 7.4.
func TestMacroExamples(t *testing.T) {
	t.Parallel()
	e := &eval{ip: net.ParseIP("192.0.2.3").To4(), v4: true, local: "strong-bad", senderDomain: "email.example.com"}
	for spec, want := range map[string]string{
		"%{s}.x":                            "strong-bad@email.example.com.x",
		"%{d2}":                             "example.com",
		"%{dr}":                             "com.example.email",
		"%{d2r}":                            "example.email",
		"%{l-}.x":                           "strong.bad.x",
		"%{lr-}.x":                          "bad.strong.x",
		"%{l1r-}.x":                         "strong.x",
		"%{ir}.%{v}._spf.%{d2}":             "3.2.0.192.in-addr._spf.example.com",
		"%{lr-}.lp.%{ir}.%{v}._spf.%{d2}":   "bad.strong.lp.3.2.0.192.in-addr._spf.example.com",
		"%{d2}.trusted-domains.example.net": "example.com.trusted-domains.example.net",
		"a%_b%%c%-d.example.org":            "a b%c%20d.example.org", // 7.1 escapes
		"%{d99999999999999999999}":          "email.example.com",     // review C1: no upper bound on *DIGIT
	} {
		if got, exc := e.target(spec, "email.example.com"); got != want || exc != "" {
			t.Errorf("%s = %q %s, want %q", spec, got, exc, want)
		}
	}
	e6 := &eval{ip: net.ParseIP("2001:db8::cb01"), local: "a", senderDomain: "email.example.com"}
	want := "1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com"
	if got, _ := e6.target("%{ir}.%{v}._spf.%{d2}", "email.example.com"); got != want {
		t.Errorf("IPv6 %%{ir}: %q", got)
	}
}

// The Checker is shared by every SMTP session: concurrent checks must not race (run with -race).
func TestConcurrentChecks(t *testing.T) {
	t.Parallel()
	f := &fakeDNS{txt: map[string]string{"example.com.": "v=spf1 ip4:192.0.2.0/24 -all"}}
	c := &Checker{Resolver: f}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if got := c.CheckHost(context.Background(), client, "example.com", "a@example.com", "h"); got != Pass {
				t.Errorf("%s", got)
			}
		})
	}
	wg.Wait()
}
