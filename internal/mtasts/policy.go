// MTA-STS policy parsing and MX host matching (RFC 8461).
package mtasts

import (
	"fmt"
	"strconv"
	"strings"
	"time"
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
	Domain  string
	Mode    Mode
	MX      []string
	MaxAge  time.Duration
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

// parsePolicy parses the HTTPS policy file body for domain.
func parsePolicy(domain string, body string, policyID string) (*Policy, error) {
	p := &Policy{Domain: domain, Mode: ModeNone, PolicyID: policyID}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
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
		case "mx":
			p.MX = append(p.MX, normalizeHost(val))
		case "max_age":
			sec, err := strconv.Atoi(val)
			if err != nil || sec <= 0 {
				return nil, fmt.Errorf("mta-sts: invalid max_age %q", val)
			}
			p.MaxAge = time.Duration(sec) * time.Second
		}
	}
	if p.MaxAge == 0 {
		return nil, fmt.Errorf("mta-sts: missing max_age")
	}
	if len(p.MX) == 0 {
		return nil, fmt.Errorf("mta-sts: missing mx")
	}
	return p, nil
}

// parseTXTRecord extracts the policy id from _mta-sts TXT (v=STSv1; id=...).
func parseTXTRecord(records []string) (string, bool) {
	joined := strings.Join(records, "")
	joined = strings.TrimSpace(joined)
	if joined == "" {
		return "", false
	}
	var version string
	var id string
	for _, part := range strings.Split(joined, ";") {
		part = strings.TrimSpace(part)
		key, val, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "v":
			version = strings.TrimSpace(val)
		case "id":
			id = strings.TrimSpace(val)
		}
	}
	if version != "STSv1" || id == "" {
		return "", false
	}
	return id, true
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
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
