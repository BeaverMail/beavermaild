// Package mailauth verifies inbound SPF, DKIM, and DMARC for SMTP sessions.
package mailauth

import (
	"bufio"
	"context"
	"fmt"
	"net"
	netmail "net/mail"
	"os"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/miekg/dns"
	spflib "github.com/wttw/spf"

	"github.com/BeaverMail/beavermaild/dmarc"
	"github.com/BeaverMail/beavermaild/internal/dnsname"
	"github.com/BeaverMail/beavermaild/internal/mailauth/arc"
)

// Config controls which mail-auth checks run and DNS timeouts.
type Config struct {
	Enabled      bool
	DNSTimeout   time.Duration
	SPFEnabled   bool
	DKIMEnabled  bool
	DMARCEnabled bool
	ARCEnabled   bool
	SPFResolver  spflib.Resolver
	LookupTXT    func(context.Context, string) ([]string, error)
	DomainExists func(context.Context, string) (bool, error) // test seam; nil asks the SPF resolver
}

// SessionState holds per-transaction auth results for filter wire encoding.
type SessionState struct {
	SPFEhlo     string
	SPFMailFrom string
	DKIM        string
	DMARC       string
	DMARCPolicy string
	ARC         string
	DKIMDomain  string // d= of the passing signature (else the first one), for Authentication-Results
	FromDomain  string // RFC5322.From domain DMARC evaluated, for Authentication-Results
}

// Wire maps session auth fields to filter request auth values.
func (s SessionState) Wire() SessionState { return s }

// Verifier runs SPF, DKIM, and DMARC checks for one SMTP session.
type Verifier struct {
	cfg Config
	spf *spflib.Checker
}

// New builds a Verifier from host config. Returns nil when disabled.
func New(cfg Config) *Verifier {
	if !cfg.Enabled {
		return nil
	}
	if cfg.DNSTimeout <= 0 {
		cfg.DNSTimeout = 5 * time.Second
	}
	spf := spflib.NewChecker()
	if cfg.SPFResolver != nil {
		spf.Resolver = cfg.SPFResolver
	}
	return &Verifier{cfg: cfg, spf: spf}
}

// Enabled reports whether mail-auth checks are active.
func (v *Verifier) Enabled() bool {
	return v != nil && v.cfg.Enabled
}

// CheckSPF evaluates SPF for mailFrom (empty uses HELO identity per RFC 7208).
func (v *Verifier) CheckSPF(ctx context.Context, ip net.IP, mailFrom, helo string) string {
	if v == nil || !v.cfg.Enabled || !v.cfg.SPFEnabled {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, v.cfg.DNSTimeout)
	defer cancel()
	var res spflib.Result
	if mailFrom == "" {
		res = v.spf.SPF(ctx, ip, "", helo)
	} else {
		domain := strings.TrimSuffix(domainFromAddress(mailFrom), ".") + "."
		res = v.spf.CheckHost(ctx, ip, domain, mailFrom, helo)
	}
	return spfResultString(res)
}

// FinishEom verifies DKIM and DMARC on the message at bodyPath and updates state.
func (v *Verifier) FinishEom(ctx context.Context, bodyPath, mailFrom, helo string, state SessionState) SessionState {
	if v == nil || !v.cfg.Enabled {
		return state
	}
	ctx, cancel := context.WithTimeout(ctx, v.cfg.DNSTimeout)
	defer cancel()

	fromDomain, fromOK := headerFromDomain(bodyPath)
	state.FromDomain = fromDomain
	var dkimPassed []string
	if v.cfg.DKIMEnabled {
		state.DKIM, state.DKIMDomain, dkimPassed = v.verifyDKIM(ctx, bodyPath)
	}
	if v.cfg.DMARCEnabled {
		dmarcRes, policy := v.evaluateDMARC(ctx, fromDomain, fromOK, mailFrom, helo, state, dkimPassed)
		state.DMARC = dmarcRes
		state.DMARCPolicy = policy
	}
	if v.cfg.ARCEnabled {
		state.ARC = v.verifyARC(ctx, bodyPath)
	}
	return state
}

// verifyARC validates the inbound Authenticated Received Chain (RFC 8617).
func (v *Verifier) verifyARC(ctx context.Context, bodyPath string) string {
	f, err := os.Open(bodyPath)
	if err != nil {
		return "temperror"
	}
	defer f.Close()
	return string(arc.Verify(ctx, f, v.arcLookupTXT()))
}

// arcLookupTXT binds the verifier DNS seam to the ARC lookup signature.
func (v *Verifier) arcLookupTXT() arc.LookupTXT {
	return func(reqCtx context.Context, name string) ([]string, error) {
		name = dnsname.ToASCII(name)
		if v.cfg.LookupTXT != nil {
			return v.cfg.LookupTXT(reqCtx, name)
		}
		return net.DefaultResolver.LookupTXT(reqCtx, name)
	}
}

// verifyDKIM verifies bounded signatures using the verifier DNS seam. It returns the result, the
// signing domain (of the first passing signature, else of the first one) and the domains of every
// passing signature, which DMARC alignment needs (any of them may align with From).
func (v *Verifier) verifyDKIM(ctx context.Context, bodyPath string) (result, domain string, passed []string) {
	f, err := os.Open(bodyPath)
	if err != nil {
		return "temperror", "", nil
	}
	defer f.Close()
	verifs, err := dkim.VerifyWithOptions(f, &dkim.VerifyOptions{
		LookupTXT:        v.lookupTXT(ctx),
		MaxVerifications: 8, // bounds the DNS and hashing work a sender can ask for
	})
	// Past 8 signatures the first 8 are still verified (RFC 6376 6.1: one passing is enough).
	if err != nil && err != dkim.ErrTooManySignatures {
		if dkim.IsPermFail(err) {
			return "permerror", "", nil
		}
		if dkim.IsTempFail(err) {
			return "temperror", "", nil
		}
		return "fail", "", nil
	}
	if len(verifs) == 0 {
		return "none", "", nil
	}
	for _, vr := range verifs {
		if vr.Err == nil {
			passed = append(passed, vr.Domain)
		}
	}
	if len(passed) > 0 {
		return "pass", passed[0], passed
	}
	if dkim.IsPermFail(verifs[0].Err) {
		return "permerror", verifs[0].Domain, nil
	}
	if dkim.IsTempFail(verifs[0].Err) {
		return "temperror", verifs[0].Domain, nil
	}
	return "fail", verifs[0].Domain, nil
}

// evaluateDMARC applies RFC 9989 (package dmarc) to the message.
func (v *Verifier) evaluateDMARC(ctx context.Context, fromDomain string, fromOK bool, mailFrom, helo string, state SessionState, dkimPassed []string) (result, policy string) {
	// RFC 7489 6.6.1: no From, several, or several mailboxes in it are "typically rejected"; anything
	// softer would let a second From field slip a forged one past the policy.
	if !fromOK {
		return "fail", "reject"
	}
	if state.SPFMailFrom == "" && state.DKIM == "" {
		return "none", "" // neither SPF nor DKIM ran
	}
	var spfDomain string
	if state.SPFMailFrom == "pass" {
		// RFC 9989 3.2.4: with a null MAIL FROM the SPF identity is postmaster@<HELO>.
		spfDomain = helo
		if mailFrom != "" {
			spfDomain = domainFromAddress(mailFrom)
		}
	}
	dkimDomains := make([]string, len(dkimPassed))
	for i, d := range dkimPassed {
		dkimDomains[i] = dnsname.ToASCII(d) // d= may carry U-labels (RFC 8616 4)
	}
	lookup := v.lookupTXT(ctx)
	res := dmarc.Evaluate(ctx, dmarc.Resolver{
		LookupTXT: func(_ context.Context, name string) ([]string, error) { return lookup(name) },
		Exists:    v.domainExists,
	}, fromDomain, dnsname.ToASCII(spfDomain), dkimDomains)
	return res.Result, res.Policy
}

// domainExists reports whether domain exists (RFC 8020: only NXDOMAIN says it does not), for the
// DMARC np tag. net cannot tell NXDOMAIN from "no records of this type", so it asks the SPF resolver.
func (v *Verifier) domainExists(ctx context.Context, domain string) (bool, error) {
	if v.cfg.DomainExists != nil {
		return v.cfg.DomainExists(ctx, domain)
	}
	// A name the DNS cannot hold does not exist; asking would fail and turn np into temperror.
	if _, ok := dns.IsDomainName(domain); !ok {
		return false, nil
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	r, err := v.spf.Resolver.Resolve(ctx, m)
	if err != nil {
		return false, err
	}
	switch r.Rcode {
	case dns.RcodeNameError:
		return false, nil
	case dns.RcodeSuccess:
		return true, nil
	}
	return false, fmt.Errorf("dns %s: %s", domain, dns.RcodeToString[r.Rcode])
}

func domainFromAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return dnsname.ToASCII(addr)
	}
	return dnsname.ToASCII(addr[i+1:])
}

// headerFromDomain returns the domain of the message's RFC5322.From and whether DMARC can evaluate it:
// exactly one From field holding exactly one mailbox (RFC 7489 6.6.1), parsed with unfolding and
// comments as RFC 5322 defines them.
func headerFromDomain(bodyPath string) (string, bool) {
	f, err := os.Open(bodyPath)
	if err != nil {
		return "", false
	}
	defer f.Close()
	msg, err := netmail.ReadMessage(bufio.NewReader(f))
	if err != nil || len(msg.Header["From"]) != 1 {
		return "", false
	}
	list, err := msg.Header.AddressList("From")
	if err != nil || len(list) != 1 {
		return "", false
	}
	d := domainFromAddress(list[0].Address)
	return d, d != ""
}

func spfResultString(res spflib.Result) string {
	switch res.Type {
	case spflib.Pass:
		return "pass"
	case spflib.Fail:
		return "fail"
	case spflib.Softfail:
		return "softfail"
	case spflib.Neutral:
		return "neutral"
	case spflib.None:
		return "none"
	case spflib.Temperror:
		return "temperror"
	case spflib.Permerror:
		return "permerror"
	default:
		return "none"
	}
}

// lookupTXT binds DNS lookup implementations to the request context.
func (v *Verifier) lookupTXT(ctx context.Context) func(string) ([]string, error) {
	return func(name string) ([]string, error) {
		name = dnsname.ToASCII(name) // DKIM d= may carry U-labels (RFC 8616 4)
		var txts []string
		err := ctx.Err()
		if err == nil {
			if v.cfg.LookupTXT != nil {
				txts, err = v.cfg.LookupTXT(ctx, name)
			} else {
				txts, err = net.DefaultResolver.LookupTXT(ctx, name)
			}
		}
		// Our timeout is a transient DNS failure (RFC 6376 6.1.2: TEMPFAIL); unwrapped, the library
		// took it for a missing key and reported permerror.
		if err != nil && ctx.Err() != nil {
			return nil, &net.DNSError{Err: ctx.Err().Error(), Name: name, IsTimeout: true}
		}
		return txts, err
	}
}
