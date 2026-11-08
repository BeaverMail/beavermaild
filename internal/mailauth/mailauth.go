// Package mailauth verifies inbound SPF, DKIM, and DMARC for SMTP sessions.
package mailauth

import (
	"context"
	"net"
	"os"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mailauth/arc"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	spflib "github.com/wttw/spf"
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

	state.FromDomain = domainFromAddress(extractFromHeader(bodyPath))
	if v.cfg.DKIMEnabled {
		state.DKIM, state.DKIMDomain = v.verifyDKIM(ctx, bodyPath)
	}
	if v.cfg.DMARCEnabled {
		dmarcRes, policy := v.evaluateDMARC(ctx, bodyPath, mailFrom, state)
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
		if v.cfg.LookupTXT != nil {
			return v.cfg.LookupTXT(reqCtx, name)
		}
		return net.DefaultResolver.LookupTXT(reqCtx, name)
	}
}

// verifyDKIM verifies bounded signatures using the verifier DNS seam. It returns the result
// and the signing domain (of the passing signature, else of the first one).
func (v *Verifier) verifyDKIM(ctx context.Context, bodyPath string) (result, domain string) {
	f, err := os.Open(bodyPath)
	if err != nil {
		return "temperror", ""
	}
	defer f.Close()
	verifs, err := dkim.VerifyWithOptions(f, &dkim.VerifyOptions{
		LookupTXT:        v.lookupTXT(ctx),
		MaxVerifications: 8,
	})
	if err != nil {
		if dkim.IsPermFail(err) {
			return "permerror", ""
		}
		if dkim.IsTempFail(err) {
			return "temperror", ""
		}
		return "fail", ""
	}
	if len(verifs) == 0 {
		return "none", ""
	}
	for _, vr := range verifs {
		if vr.Err == nil {
			return "pass", vr.Domain
		}
	}
	if dkim.IsPermFail(verifs[0].Err) {
		return "permerror", verifs[0].Domain
	}
	if dkim.IsTempFail(verifs[0].Err) {
		return "temperror", verifs[0].Domain
	}
	return "fail", verifs[0].Domain
}

func (v *Verifier) evaluateDMARC(ctx context.Context, bodyPath, mailFrom string, state SessionState) (result, policy string) {
	fromDomain := domainFromAddress(extractFromHeader(bodyPath))
	if fromDomain == "" {
		fromDomain = domainFromAddress(mailFrom)
	}
	if fromDomain == "" {
		return "none", ""
	}
	rec, err := dmarc.LookupWithOptions(fromDomain, &dmarc.LookupOptions{
		LookupTXT: v.lookupTXT(ctx),
	})
	if err != nil {
		if dmarc.IsTempFail(err) {
			return "temperror", ""
		}
		if err == dmarc.ErrNoPolicy {
			return "none", ""
		}
		return "permerror", ""
	}

	spfAligned := spfAligned(state.SPFMailFrom, fromDomain, mailFrom, rec.SPFAlignment)
	dkimAligned := dkimAligned(state.DKIM, fromDomain, bodyPath, rec.DKIMAlignment)
	if spfAligned || dkimAligned {
		return "pass", ""
	}
	if state.SPFMailFrom == "" && state.DKIM == "" {
		return "none", ""
	}
	pol := string(rec.Policy)
	if pol == "" {
		pol = "unspecified"
	}
	return "fail", pol
}

func spfAligned(spfResult, fromDomain, mailFrom string, mode dmarc.AlignmentMode) bool {
	if spfResult != "pass" {
		return false
	}
	envDomain := domainFromAddress(mailFrom)
	if envDomain == "" {
		return false
	}
	return domainsAlign(envDomain, fromDomain, mode)
}

func dkimAligned(dkimResult, fromDomain, bodyPath string, mode dmarc.AlignmentMode) bool {
	if dkimResult != "pass" {
		return false
	}
	domain := dkimSigningDomain(bodyPath)
	if domain == "" {
		return false
	}
	return domainsAlign(domain, fromDomain, mode)
}

func domainsAlign(authDomain, fromDomain string, mode dmarc.AlignmentMode) bool {
	authDomain = strings.ToLower(authDomain)
	fromDomain = strings.ToLower(fromDomain)
	if mode == dmarc.AlignmentStrict {
		return authDomain == fromDomain
	}
	return orgDomain(authDomain) == orgDomain(fromDomain)
}

func orgDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return domain
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func domainFromAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return strings.ToLower(addr)
	}
	return strings.ToLower(addr[i+1:])
}

func extractFromHeader(bodyPath string) string {
	b, err := os.ReadFile(bodyPath)
	if err != nil {
		return ""
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "from:") {
			return strings.TrimSpace(line[5:])
		}
	}
	return ""
}

func dkimSigningDomain(bodyPath string) string {
	b, err := os.ReadFile(bodyPath)
	if err != nil {
		return ""
	}
	// ponytail: scan first DKIM-Signature d= only; full parse is in dkim.Verify.
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if !strings.HasPrefix(lower, "dkim-signature:") {
			continue
		}
		for _, part := range strings.Split(line, ";") {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(strings.ToLower(part), "d=") {
				return strings.TrimSpace(part[2:])
			}
		}
	}
	return ""
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
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if v.cfg.LookupTXT != nil {
			return v.cfg.LookupTXT(ctx, name)
		}
		return net.DefaultResolver.LookupTXT(ctx, name)
	}
}
