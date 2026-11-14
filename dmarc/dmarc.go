// Package dmarc evaluates DMARC (RFC 9989) for one message: policy discovery and the Organizational
// Domain through the DNS Tree Walk (4.10), identifier alignment, and the policy to apply (p, sp, np,
// t). The server and the antispam plugin both use it, so a message gets one verdict.
//
// Domains are passed as A-labels; case and a trailing dot do not matter.
package dmarc

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
)

// Results, as registered for Authentication-Results (RFC 9989 9.2).
const (
	Pass      = "pass"
	Fail      = "fail"
	None      = "none"
	TempError = "temperror"
)

// Resolver is the DNS the evaluation uses.
type Resolver struct {
	// LookupTXT returns the TXT records of name, one string per record. A *net.DNSError with
	// IsNotFound means no record; any other error is a DNS failure (temperror).
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// Exists reports whether domain exists in the DNS (false only on NXDOMAIN, RFC 8020), for the
	// np tag. Nil, or an error: the domain is taken as existing (sp or p applies).
	Exists func(ctx context.Context, domain string) (bool, error)
}

// Result is the DMARC verdict for one message.
type Result struct {
	Result string // Pass, Fail, None or TempError
	Policy string // on Fail: the policy to apply after sp/np and t ("none", "quarantine", "reject")
}

// Evaluate checks author (the RFC5322.From domain) against the authenticated identifiers:
// spfDomain is the SPF-validated MAIL FROM domain ("" when SPF did not pass; for a null sender it
// is the HELO domain, RFC 9989 3.2.4), dkimDomains the d= of every verified DKIM signature.
func Evaluate(ctx context.Context, r Resolver, author, spfDomain string, dkimDomains []string) Result {
	w := &walker{ctx: ctx, r: r, seen: map[string]answer{}}
	author = norm(author)
	if author == "" {
		return Result{Result: None}
	}
	rec, policy, err := w.policy(author)
	if err != nil {
		return Result{Result: TempError}
	}
	if rec == nil {
		return Result{Result: None} // 4.10.1: no record, DMARC does not apply
	}

	var dnsErr bool
	aligned := func(id string, strict bool) bool {
		id = norm(id)
		if id == "" {
			return false
		}
		if id == author {
			return true
		}
		if strict {
			return false
		}
		org, err := w.orgDomain(author)
		if err != nil {
			dnsErr = true
			return false
		}
		// The Organizational Domain of id is id or one of its parents: outside org it cannot align,
		// and its DNS is not queried. Otherwise a sender whose own _dmarc lookups time out turned
		// the victim's fail into temperror.
		if id != org && !strings.HasSuffix(id, "."+org) {
			return false
		}
		b, err := w.orgDomain(id)
		if err != nil {
			dnsErr = true
			return false
		}
		return b == org
	}
	if aligned(spfDomain, rec.spfStrict) {
		return Result{Result: Pass}
	}
	for _, d := range dkimDomains {
		if aligned(d, rec.dkimStrict) {
			return Result{Result: Pass}
		}
	}
	if dnsErr {
		return Result{Result: TempError} // 5.3.6: neither pass nor fail
	}
	if rec.testing { // t=y: one level below the published policy (4.7)
		switch policy {
		case "reject":
			policy = "quarantine"
		case "quarantine":
			policy = "none"
		}
	}
	return Result{Result: Fail, Policy: policy}
}

// record is a parsed DMARC Policy Record.
type record struct {
	p, sp, np             string // "" when absent
	dkimStrict, spfStrict bool
	psd                   byte // 'y', 'n' or 'u'
	testing               bool
	usable                bool // p (or the p=none fallback of 4.10.1) applies
}

// parse reads a DMARC Policy Record (4.7, 4.8). ok is false when txt is not one: "v=DMARC1" must be
// the first tag (tag names are case-insensitive ABNF strings, the value "DMARC1" is %s, sensitive). Syntax errors fall back to the default or drop the tag (4.8); a missing or invalid
// p, or an invalid sp or np, leaves the record usable only as p=none, and only with a valid rua
// (4.10.1).
func parse(txt string) (rec *record, ok bool) {
	tags := strings.Split(txt, ";")
	if k, v, _ := strings.Cut(tags[0], "="); strings.ToLower(strings.TrimSpace(k)) != "v" || strings.TrimSpace(v) != "DMARC1" {
		return nil, false
	}
	rec = &record{psd: 'u'}
	seen := map[string]bool{}
	var badPolicy, rua bool
	for _, t := range tags[1:] {
		k, v, found := strings.Cut(t, "=")
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if !found || seen[k] {
			continue
		}
		seen[k] = true
		lv := strings.ToLower(v)
		switch k {
		case "p", "sp", "np":
			if lv != "none" && lv != "quarantine" && lv != "reject" {
				badPolicy = true
				continue
			}
			switch k {
			case "p":
				rec.p = lv
			case "sp":
				rec.sp = lv
			case "np":
				rec.np = lv
			}
		case "adkim":
			rec.dkimStrict = lv == "s"
		case "aspf":
			rec.spfStrict = lv == "s"
		case "psd":
			if lv == "y" || lv == "n" {
				rec.psd = lv[0]
			}
		case "t":
			rec.testing = lv == "y"
		case "rua":
			rua = validURIList(v)
		}
	}
	switch {
	case rec.p != "" && !badPolicy:
		rec.usable = true
	case rua:
		rec.p, rec.sp, rec.np, rec.usable = "none", "", "", true
	}
	return rec, true
}

// validURIList reports whether a rua value holds at least one syntactically valid URI.
func validURIList(v string) bool {
	for _, u := range strings.Split(v, ",") {
		u = strings.TrimSpace(u)
		if i := strings.LastIndexByte(u, '!'); i > 0 {
			u = u[:i] // obsolete size limit (4.8)
		}
		if p, err := url.Parse(u); err == nil && p.Scheme != "" && (p.Opaque != "" || p.Host != "") {
			return true
		}
	}
	return false
}

type answer struct {
	rec *record // nil: no single DMARC record at this name
	err error
}

type walker struct {
	ctx  context.Context
	r    Resolver
	seen map[string]answer // one query per name per message
}

// lookup returns the single DMARC record at _dmarc.<domain>, nil when there is none or several
// (4.10 step 2).
func (w *walker) lookup(domain string) (*record, error) {
	if a, ok := w.seen[domain]; ok {
		return a.rec, a.err
	}
	var rec *record
	txts, err := w.r.LookupTXT(w.ctx, "_dmarc."+domain)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		err = nil
	}
	if err == nil {
		n := 0
		for _, t := range txts {
			if r, ok := parse(t); ok {
				rec, n = r, n+1
			}
		}
		if n != 1 {
			rec = nil
		}
	}
	w.seen[domain] = answer{rec, err}
	return rec, err
}

// found is a DMARC record met during a Tree Walk.
type found struct {
	name string
	rec  *record
}

// walk is the DNS Tree Walk of 4.10 from start: start itself, then (from 8 labels on, cut to 7)
// one label less at a time up to the top-level domain, stopping at a record with psd=y or psd=n.
// It returns the records met, longest name first; at most 8 queries.
func (w *walker) walk(start string) ([]found, error) {
	var out []found
	labels := strings.Split(start, ".")
	for i := 0; i < len(labels); {
		name := strings.Join(labels[i:], ".")
		rec, err := w.lookup(name)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, found{name, rec})
			if rec.psd != 'u' {
				break
			}
		}
		if i == 0 && len(labels) >= 8 {
			i = len(labels) - 7
		} else {
			i++
		}
	}
	return out, nil
}

// orgDomainOf selects the Organizational Domain of start from its Tree Walk (4.10.2).
func orgDomainOf(start string, recs []found) string {
	for _, f := range recs {
		if f.rec.psd == 'n' {
			return f.name
		}
		if f.rec.psd == 'y' && f.name != start {
			below := strings.TrimSuffix(start, "."+f.name)
			return below[strings.LastIndexByte(below, '.')+1:] + "." + f.name
		}
	}
	if len(recs) > 0 {
		return recs[len(recs)-1].name
	}
	return start
}

func (w *walker) orgDomain(domain string) (string, error) {
	recs, err := w.walk(domain)
	if err != nil {
		return "", err
	}
	return orgDomainOf(domain, recs), nil
}

// policy picks the record that applies to author and its policy (4.10.1): the author's own record
// (p), else the Organizational Domain's, else the PSD's, with sp for an existing author domain and
// np for a non-existent one. A nil record means DMARC does not apply.
func (w *walker) policy(author string) (*record, string, error) {
	own, err := w.lookup(author)
	if err != nil {
		return nil, "", err
	}
	if own != nil {
		if !own.usable {
			return nil, "", nil
		}
		return own, own.p, nil
	}
	recs, err := w.walk(author)
	if err != nil || len(recs) == 0 {
		return nil, "", err
	}
	org := orgDomainOf(author, recs)
	var rec *record
	for _, f := range recs {
		if f.name == org {
			rec = f.rec
		}
	}
	if rec == nil { // org is one label below a psd=y record, which has no record of its own
		for _, f := range recs {
			if f.rec.psd == 'y' {
				rec = f.rec
			}
		}
	}
	if rec == nil || !rec.usable {
		return nil, "", nil
	}
	policy := rec.p
	if rec.sp != "" {
		policy = rec.sp
	}
	if rec.np != "" && w.r.Exists != nil {
		// A failed existence query keeps sp/p: the record was found, only the choice between two of
		// its policies is in doubt. Deviation from 5.3.6 (temperror), which applied no policy at all.
		if exists, err := w.r.Exists(w.ctx, author); err == nil && !exists {
			policy = rec.np
		}
	}
	return rec, policy, nil
}

func norm(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}
