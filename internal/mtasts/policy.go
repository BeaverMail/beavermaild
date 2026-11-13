// MTA-STS policy parsing and MX host matching (RFC 8461).
package mtasts

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
)

// Mode is the MTA-STS policy enforcement level.
type Mode string

const (
	ModeNone    Mode = "none"
	ModeTesting Mode = "testing"
	ModeEnforce Mode = "enforce"
)

// Policy is a parsed MTA-STS policy for one recipient domain.
type Policy struct {
	Domain   string
	Mode     Mode
	MX       []string
	MaxAge   time.Duration
	PolicyID string
}

// Enforce reports whether failed policy checks must block delivery.
func (p *Policy) Enforce() bool {
	return p != nil && p.Mode == ModeEnforce
}

// AllowsMX reports whether host matches any mx: entry (exact or single-label wildcard).
func (p *Policy) AllowsMX(host string) bool {
	if p == nil || len(p.MX) == 0 {
		return true
	}
	host = normalizeHost(host)
	for _, pattern := range p.MX {
		if mxMatch(pattern, host) {
			return true
		}
	}
	return false
}

// maxAgeLimit is the largest max_age (RFC 8461 3.2); larger values are clamped.
const maxAgeLimit = 31557600

// maxMXPatterns bounds a cached policy: real ones list a handful of MX. A policy over it counts as
// no policy, which only affects the domain publishing it.
const maxMXPatterns = 100

// parsePolicy parses the HTTPS policy file body for domain (RFC 8461 3.2).
func parsePolicy(domain string, body string, policyID string) (*Policy, error) {
	p := &Policy{Domain: domain, PolicyID: policyID}
	seen := map[string]bool{}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("mta-sts: invalid policy line %q", line)
		}
		key = strings.TrimSpace(strings.ToLower(key))
		val = strings.TrimSpace(val)
		if key == "mx" {
			p.MX = append(p.MX, normalizeHost(val))
			continue
		}
		if seen[key] {
			continue // a repeated non-mx field: only the first counts
		}
		seen[key] = true
		switch key {
		case "version":
			if val != "STSv1" {
				return nil, fmt.Errorf("mta-sts: unsupported version %q", val)
			}
		case "mode":
			switch Mode(strings.ToLower(val)) {
			case ModeNone, ModeTesting, ModeEnforce:
				p.Mode = Mode(strings.ToLower(val))
			default:
				return nil, fmt.Errorf("mta-sts: invalid mode %q", val)
			}
		case "max_age":
			if val == "" || len(val) > 10 || strings.Trim(val, "0123456789") != "" {
				return nil, fmt.Errorf("mta-sts: invalid max_age %q", val)
			}
			sec, _ := strconv.ParseInt(val, 10, 64)
			p.MaxAge = time.Duration(min(sec, maxAgeLimit)) * time.Second
		}
	}
	for _, k := range []string{"version", "mode", "max_age"} {
		if !seen[k] {
			return nil, fmt.Errorf("mta-sts: missing %s", k)
		}
	}
	if len(p.MX) == 0 && p.Mode != ModeNone {
		return nil, fmt.Errorf("mta-sts: missing mx")
	}
	if len(p.MX) > maxMXPatterns {
		return nil, fmt.Errorf("mta-sts: %d mx patterns, over %d", len(p.MX), maxMXPatterns)
	}
	return p, nil
}

// parseTXTRecord returns the policy id of the one _mta-sts TXT record starting with "v=STSv1;"
// (RFC 8461 3.1). Several such records, or a syntactically invalid one, mean no policy.
func parseTXTRecord(records []string) (string, bool) {
	var rest string
	n := 0
	for _, rec := range records {
		if after, ok := strings.CutPrefix(rec, "v=STSv1"); ok && strings.HasPrefix(strings.TrimLeft(after, " \t"), ";") {
			rest, n = after, n+1
		}
	}
	if n != 1 {
		return "", false
	}
	fields := strings.Split(rest, ";")[1:]
	if last := len(fields) - 1; strings.Trim(fields[last], " \t") == "" {
		fields = fields[:last] // trailing delimiter
	}
	id := ""
	for _, f := range fields {
		key, val, ok := strings.Cut(strings.Trim(f, " \t"), "=")
		if !ok || key == "" || val == "" || strings.ContainsAny(val, " \t=") {
			return "", false
		}
		if key == "id" && id == "" {
			if len(val) > 32 || !isAlnum(val) {
				return "", false
			}
			id = val
		}
	}
	return id, id != ""
}

func isAlnum(s string) bool {
	for _, c := range s {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9') {
			return false
		}
	}
	return true
}

func normalizeHost(host string) string {
	return dnsname.ToASCII(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

// mxMatch implements RFC 8461 mx pattern (exact or *.suffix single label).
func mxMatch(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	host = normalizeHost(host)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		if !strings.HasSuffix(host, suffix) {
			return false
		}
		prefix := strings.TrimSuffix(host, suffix)
		return prefix != "" && !strings.Contains(prefix, ".")
	}
	return false
}
