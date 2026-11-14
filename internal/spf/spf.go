// Package spf evaluates Sender Policy Framework records (RFC 7208), written from the RFC.
//
// Processing limits (4.6.4): at most 10 terms that query the DNS (include, a, mx, ptr, exists,
// redirect, and each %{p} expansion; the record lookup of check_host() itself is not a term),
// at most 2 of them answering with no records, at most 10 MX names per mx, the first 10 PTR names
// per ptr. The exp modifier is checked for syntax but never fetched: explanations are not used,
// and fetching one is another query on a name the sender chooses.
package spf

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Result is a check_host() result (2.6).
type Result string

const (
	Pass      Result = "pass"
	Fail      Result = "fail"
	SoftFail  Result = "softfail"
	Neutral   Result = "neutral"
	None      Result = "none"
	TempError Result = "temperror"
	PermError Result = "permerror"
)

const (
	maxTerms = 10
	maxVoid  = 2
	maxNames = 10
	// MinTimeout is the default and the least time check_host() gets (4.6.4: at least 20 s).
	MinTimeout = 20 * time.Second
)

// Checker evaluates SPF. It is safe for concurrent use.
type Checker struct {
	Resolver Resolver
	Timeout  time.Duration // whole check_host(); below MinTimeout counts as MinTimeout
}

// CheckHost is check_host() (4): may ip send mail for domain? sender is the MAIL FROM mailbox
// ("postmaster@<helo>" for the HELO identity), helo the HELO/EHLO argument (for %{h}).
func (c *Checker) CheckHost(ctx context.Context, ip net.IP, domain, sender, helo string) Result {
	if strings.HasPrefix(domain, "[") {
		return None // an address literal (HELO [192.0.2.1]) is not a domain (4.3)
	}
	timeout := max(c.Timeout, MinTimeout)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	local, senderDomain := "", sender
	if at := strings.LastIndexByte(sender, '@'); at >= 0 {
		local, senderDomain = sender[:at], sender[at+1:]
	}
	if local == "" {
		local = "postmaster" // 4.3
	}
	e := &eval{ctx: ctx, r: c.Resolver, ip: ip, v4: ip.To4() != nil, local: local,
		senderDomain: senderDomain, helo: helo}
	if e.v4 {
		e.ip = ip.To4()
	}
	return e.checkHost(domain)
}

// eval is one check_host() evaluation, includes and redirects included: the limits are shared.
type eval struct {
	ctx                 context.Context
	r                   Resolver
	ip                  net.IP
	v4                  bool
	local, senderDomain string
	helo                string
	terms, voids        int
	ptrName             string // %{p}, computed once
}

func (e *eval) checkHost(domain string) Result {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if !validDomain(domain) {
		return None // 4.3: malformed or single-label, no query
	}
	m, err := e.query(domain, dns.TypeTXT)
	switch {
	case err != nil:
		return TempError
	case m.Rcode == dns.RcodeNameError:
		return None
	case m.Rcode != dns.RcodeSuccess:
		return TempError // 4.4
	}
	var spfs []string
	for _, rr := range m.Answer {
		if t, ok := rr.(*dns.TXT); ok {
			if txt := strings.Join(t.Txt, ""); isSPF(txt) {
				spfs = append(spfs, txt)
			}
		}
	}
	switch len(spfs) {
	case 0:
		return None
	case 1:
	default:
		return PermError // 4.5
	}
	rec, err := parse(spfs[0])
	if err != nil {
		return PermError
	}
	for _, d := range rec.directives {
		if d.kind == mAll {
			return d.result // later mechanisms and any redirect are ignored (5.1)
		}
		match, exc := e.mechanism(d, domain)
		if exc != "" {
			return exc
		}
		if match {
			return d.result
		}
	}
	if rec.redirect != "" {
		if exc := e.countTerm(); exc != "" {
			return exc
		}
		target, exc := e.target(rec.redirect, domain)
		if exc != "" {
			return exc
		}
		// 6.1: no record, or a malformed target, is permerror rather than none.
		if r := e.checkHost(target); r != None {
			return r
		}
		return PermError
	}
	return Neutral // 4.7
}

// mechanism evaluates one directive: match, or an exception (temperror/permerror).
func (e *eval) mechanism(d directive, domain string) (bool, Result) {
	switch d.kind {
	case mIP4:
		return e.v4 && d.net.Contains(e.ip), ""
	case mIP6:
		return !e.v4 && d.net.Contains(e.ip), ""
	}
	if exc := e.countTerm(); exc != "" {
		return false, exc
	}
	target, exc := e.target(d.spec, domain)
	if exc != "" {
		return false, exc
	}
	if d.kind == mInclude {
		switch e.checkHost(target) { // 5.2 table
		case Pass:
			return true, ""
		case Fail, SoftFail, Neutral:
			return false, ""
		case TempError:
			return false, TempError
		default: // permerror, none
			return false, PermError
		}
	}
	if !validDomain(target) {
		return false, "" // 4.8 leaves it undefined: an invalid target does not match
	}
	switch d.kind {
	case mA:
		ips, exc := e.addresses(target, true)
		return e.matchAny(ips, d), exc
	case mMX:
		rrs, exc := e.lookup(target, dns.TypeMX, true)
		if exc != "" {
			return false, exc
		}
		if len(rrs) > maxNames {
			return false, PermError // 4.6.4
		}
		for _, rr := range rrs {
			ips, exc := e.addresses(rr.(*dns.MX).Mx, false) // no implicit MX (5.4)
			if exc != "" {
				return false, exc
			}
			if e.matchAny(ips, d) {
				return true, ""
			}
		}
		return false, ""
	case mExists:
		rrs, exc := e.lookup(target, dns.TypeA, true) // A even for IPv6 clients (5.7)
		return len(rrs) > 0, exc
	case mPTR:
		names, exc := e.validatedNames(func(n string) bool { return n == target || strings.HasSuffix(n, "."+target) })
		return len(names) > 0, exc
	}
	return false, PermError
}

func (e *eval) countTerm() Result {
	if e.terms++; e.terms > maxTerms {
		return PermError
	}
	return ""
}

func (e *eval) matchAny(ips []net.IP, d directive) bool {
	bits, size := d.cidr6, 128
	if e.v4 {
		bits, size = d.cidr4, 32
	}
	mask := net.CIDRMask(bits, size)
	for _, ip := range ips {
		if (&net.IPNet{IP: ip.Mask(mask), Mask: mask}).Contains(e.ip) {
			return true
		}
	}
	return false
}

// validatedNames is the PTR procedure of 5.5: the first 10 names of the client's PTR records
// that want accepts and whose addresses include the client. A PTR lookup error matches nothing;
// an address lookup error skips that name.
func (e *eval) validatedNames(want func(string) bool) ([]string, Result) {
	rev, err := dns.ReverseAddr(e.ip.String())
	if err != nil {
		return nil, ""
	}
	rrs, exc := e.lookup(rev, dns.TypePTR, true)
	if exc == PermError {
		return nil, exc // void limit
	}
	if len(rrs) > maxNames {
		rrs = rrs[:maxNames]
	}
	var out []string
	for _, rr := range rrs {
		name := strings.ToLower(strings.TrimSuffix(rr.(*dns.PTR).Ptr, "."))
		if !want(name) {
			continue
		}
		ips, exc := e.addresses(name, false)
		if exc != "" {
			continue
		}
		for _, ip := range ips {
			if ip.Equal(e.ip) {
				out = append(out, name)
				break
			}
		}
	}
	return out, ""
}

// addresses returns the A or AAAA records of name, as the client's address family.
func (e *eval) addresses(name string, countVoid bool) ([]net.IP, Result) {
	qtype := dns.TypeAAAA
	if e.v4 {
		qtype = dns.TypeA
	}
	rrs, exc := e.lookup(name, qtype, countVoid)
	var ips []net.IP
	for _, rr := range rrs {
		switch a := rr.(type) {
		case *dns.A:
			ips = append(ips, a.A)
		case *dns.AAAA:
			ips = append(ips, a.AAAA)
		}
	}
	return ips, exc
}

// lookup queries name: NXDOMAIN is no records (5); no records counts as a void lookup when the
// query is a term's own (4.6.4); any other failure is temperror.
func (e *eval) lookup(name string, qtype uint16, countVoid bool) ([]dns.RR, Result) {
	m, err := e.query(name, qtype)
	if err != nil {
		return nil, TempError
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return nil, TempError
	}
	var rrs []dns.RR
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qtype {
			rrs = append(rrs, rr)
		}
	}
	if len(rrs) == 0 && countVoid {
		if e.voids++; e.voids > maxVoid {
			return nil, PermError
		}
	}
	return rrs, ""
}

func (e *eval) query(name string, qtype uint16) (*dns.Msg, error) {
	if err := e.ctx.Err(); err != nil {
		return nil, err // past the time limit: temperror (4.6.4)
	}
	q := new(dns.Msg)
	q.SetQuestion(dns.Fqdn(name), qtype)
	m, err := e.r.Resolve(e.ctx, q)
	if err == nil && m == nil {
		err = errors.New("spf: empty response")
	}
	return m, err
}

// target expands a domain-spec (4.8, 7), "" meaning the current domain.
func (e *eval) target(spec, domain string) (string, Result) {
	if spec == "" {
		return domain, ""
	}
	exc := Result("")
	out, _, err := scanMacros(spec, func(letter byte, digits int, reverse bool, delims string, url bool) (string, error) {
		var v string
		switch letter | 0x20 {
		case 's':
			v = e.local + "@" + e.senderDomain
		case 'l':
			v = e.local
		case 'o':
			v = e.senderDomain
		case 'd':
			v = domain
		case 'i':
			v = e.dotIP()
		case 'v':
			v = "ip6"
			if e.v4 {
				v = "in-addr"
			}
		case 'h':
			v = e.helo
		case 'p':
			if exc = e.countTerm(); exc != "" {
				return "", errors.New("limit")
			}
			v = e.validatedName(domain)
		default:
			return "", errors.New("macro letter not allowed here")
		}
		v = transform(v, digits, reverse, delims)
		if url {
			v = urlEscape(v)
		}
		return v, nil
	})
	if exc != "" {
		return "", exc
	}
	if err != nil {
		return "", PermError
	}
	return strings.ToLower(truncate253(strings.TrimSuffix(out, "."))), ""
}

// validatedName is %{p} (7.3): domain itself, else a subdomain of it, else any validated name,
// else "unknown".
func (e *eval) validatedName(domain string) string {
	if e.ptrName != "" {
		return e.ptrName
	}
	names, _ := e.validatedNames(func(string) bool { return true })
	e.ptrName = "unknown"
	for _, n := range names {
		switch {
		case n == domain:
			e.ptrName = n
			return n
		case strings.HasSuffix(n, "."+domain) && e.ptrName == "unknown":
			e.ptrName = n
		}
	}
	if e.ptrName == "unknown" && len(names) > 0 {
		e.ptrName = names[0]
	}
	return e.ptrName
}

// dotIP is %{i}: dotted quad, or for IPv6 32 dot-separated nibbles.
func (e *eval) dotIP() string {
	if e.v4 {
		return e.ip.String()
	}
	h := hex.EncodeToString(e.ip.To16())
	return strings.Join(strings.Split(h, ""), ".")
}

// validDomain: labels of 1-63 characters, at least two of them, 253 characters at most (4.3).
// Labels may hold any printable character: a domain-spec allows every visible one (7.1), and
// macros expand to spaces. A backslash is refused, it would read as an escape in the query name.
func validDomain(d string) bool {
	if d == "" || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; c < 0x20 || c > 0x7e || c == '\\' {
				return false
			}
		}
	}
	return true
}
