// Outbound delivery probe: MX/relay path without sending mail.
package smtp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	probeLookupTimeout = 5 * time.Second
	probeDialTimeout   = 5 * time.Second
	probeIOTimeout     = 10 * time.Second
	probeMaxMXHosts    = 2
)

// ProbeRequest selects MX (from To) or configured relay.
type ProbeRequest struct {
	// To is an email address or bare domain for MX probe.
	To string
	// Mode is "", "mx", or "relay". Empty prefers relay when configured, else MX.
	Mode string
}

// ProbeStep is one stage of a delivery connectivity test.
type ProbeStep struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	Error  string `json:"error,omitempty"`
}

// ProbeResult summarizes a delivery probe (no message is submitted).
type ProbeResult struct {
	OK     bool        `json:"ok"`
	Mode   string      `json:"mode"`
	Domain string      `json:"domain,omitempty"`
	Host   string      `json:"host,omitempty"`
	Steps  []ProbeStep `json:"steps"`
}

// ProbeRemote checks outbound connectivity (dial, EHLO, optional STARTTLS/AUTH) without DATA.
func ProbeRemote(ctx context.Context, cfg RemoteConfig, req ProbeRequest) ProbeResult {
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	switch mode {
	case "", "auto":
		if cfg.Relay != "" {
			return probeRelay(ctx, cfg)
		}
		return probeMX(ctx, cfg, req.To)
	case "relay":
		if cfg.Relay == "" {
			return ProbeResult{
				OK:   false,
				Mode: "relay",
				Steps: []ProbeStep{{
					Name:  "config",
					OK:    false,
					Error: "smtp.relay is not configured",
				}},
			}
		}
		return probeRelay(ctx, cfg)
	case "mx":
		return probeMX(ctx, cfg, req.To)
	default:
		return ProbeResult{
			OK:   false,
			Mode: mode,
			Steps: []ProbeStep{{
				Name:  "config",
				OK:    false,
				Error: "mode must be auto, mx, or relay",
			}},
		}
	}
}

func probeRelay(ctx context.Context, cfg RemoteConfig) ProbeResult {
	res := ProbeResult{Mode: "relay", Host: cfg.Relay}
	step, conn, r, caps, ok := probeConnect(ctx, cfg.Relay, cfg.RelayOptions)
	res.Steps = append(res.Steps, step...)
	if !ok {
		return res
	}
	defer conn.Close()
	_ = cmd(conn, r, "QUIT", 221)
	res.OK = true
	if len(caps.Auth) > 0 {
		res.Steps = append(res.Steps, ProbeStep{Name: "capabilities", OK: true, Detail: "AUTH " + strings.Join(caps.Auth, " ")})
	}
	return res
}

func probeMX(ctx context.Context, cfg RemoteConfig, to string) ProbeResult {
	res := ProbeResult{Mode: "mx"}
	domain, err := probeDomain(to)
	if err != nil {
		res.Steps = append(res.Steps, ProbeStep{Name: "domain", OK: false, Error: err.Error()})
		return res
	}
	res.Domain = domain
	res.Steps = append(res.Steps, ProbeStep{Name: "domain", OK: true, Detail: domain})

	lookupCtx, cancel := context.WithTimeout(ctx, probeLookupTimeout)
	hosts, err := LookupHosts(lookupCtx, domain)
	cancel()
	if err != nil {
		res.Steps = append(res.Steps, ProbeStep{Name: "mx_lookup", OK: false, Error: err.Error()})
		return res
	}
	if len(hosts) > probeMaxMXHosts {
		hosts = hosts[:probeMaxMXHosts]
	}
	res.Steps = append(res.Steps, ProbeStep{Name: "mx_lookup", OK: true, Detail: strings.Join(hosts, ", ")})

	// Connectivity only — skip MTA-STS HTTPS/DNS (can hang; not needed for a probe).
	opts := ClientOptions{
		OpportunisticSTARTTLS: true,
		TLSInsecureSkipVerify: cfg.MXOptions.TLSInsecureSkipVerify,
	}
	var lastFail ProbeResult
	for _, host := range hosts {
		if err := ctx.Err(); err != nil {
			res.Steps = append(res.Steps, ProbeStep{Name: "connect", OK: false, Error: err.Error()})
			return res
		}
		attempt := ProbeResult{Mode: "mx", Domain: domain, Host: host, Steps: append([]ProbeStep(nil), res.Steps...)}
		step, conn, r, caps, ok := probeConnect(ctx, host, opts)
		attempt.Steps = append(attempt.Steps, step...)
		if !ok {
			lastFail = attempt
			continue
		}
		_ = cmd(conn, r, "QUIT", 221)
		_ = conn.Close()
		attempt.OK = true
		if caps.StartTLS {
			attempt.Steps = append(attempt.Steps, ProbeStep{Name: "capabilities", OK: true, Detail: "STARTTLS"})
		}
		return attempt
	}
	if lastFail.Host != "" {
		return lastFail
	}
	res.Steps = append(res.Steps, ProbeStep{Name: "connect", OK: false, Error: "no MX hosts"})
	return res
}

func probeDomain(to string) (string, error) {
	to = strings.TrimSpace(strings.ToLower(to))
	if to == "" {
		return "", fmt.Errorf("to (email or domain) required for MX probe")
	}
	if strings.Contains(to, "@") {
		return DomainFromAddress(to)
	}
	if strings.Contains(to, " ") || strings.Contains(to, ":") {
		return "", fmt.Errorf("invalid domain %q", to)
	}
	return strings.TrimSuffix(to, "."), nil
}

func probeConnect(ctx context.Context, addr string, opts ClientOptions) (steps []ProbeStep, conn net.Conn, r *bufio.Reader, caps clientCaps, ok bool) {
	if err := ctx.Err(); err != nil {
		steps = append(steps, ProbeStep{Name: "connect", OK: false, Error: err.Error()})
		return steps, nil, nil, caps, false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	dialer := net.Dialer{Timeout: probeDialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		steps = append(steps, ProbeStep{Name: "connect", OK: false, Error: err.Error()})
		return steps, nil, nil, caps, false
	}
	_ = raw.SetDeadline(time.Now().Add(probeIOTimeout))
	steps = append(steps, ProbeStep{Name: "connect", OK: true, Detail: addr})

	r = bufio.NewReader(raw)
	if err := expectCode(r, 220); err != nil {
		_ = raw.Close()
		steps = append(steps, ProbeStep{Name: "banner", OK: false, Error: err.Error()})
		return steps, nil, nil, caps, false
	}
	steps = append(steps, ProbeStep{Name: "banner", OK: true})

	caps, err = ehlo(raw, r, "beavermail-probe")
	if err != nil {
		_ = raw.Close()
		steps = append(steps, ProbeStep{Name: "ehlo", OK: false, Error: err.Error()})
		return steps, nil, nil, caps, false
	}
	steps = append(steps, ProbeStep{Name: "ehlo", OK: true})

	conn = raw
	if wantSTARTTLS(opts) && caps.StartTLS {
		conn, err = startTLS(conn, r, host, opts.TLSInsecureSkipVerify)
		if err != nil {
			_ = raw.Close()
			steps = append(steps, ProbeStep{Name: "starttls", OK: false, Error: err.Error()})
			return steps, nil, nil, caps, false
		}
		r = bufio.NewReader(conn)
		caps, err = ehlo(conn, r, "beavermail-probe")
		if err != nil {
			_ = conn.Close()
			steps = append(steps, ProbeStep{Name: "starttls", OK: true})
			steps = append(steps, ProbeStep{Name: "ehlo", OK: false, Error: err.Error()})
			return steps, nil, nil, caps, false
		}
		steps = append(steps, ProbeStep{Name: "starttls", OK: true})
		steps = append(steps, ProbeStep{Name: "ehlo", OK: true, Detail: "after STARTTLS"})
	} else if opts.MTASTSRequireTLS {
		_ = conn.Close()
		steps = append(steps, ProbeStep{Name: "starttls", OK: false, Error: "STARTTLS required but not advertised"})
		return steps, nil, nil, caps, false
	} else if wantSTARTTLS(opts) && !caps.StartTLS {
		steps = append(steps, ProbeStep{Name: "starttls", OK: true, Detail: "not offered"})
	}

	if opts.User != "" && opts.Password != "" {
		if err := authPlain(conn, r, caps, opts.User, opts.Password); err != nil {
			_ = conn.Close()
			steps = append(steps, ProbeStep{Name: "auth", OK: false, Error: err.Error()})
			return steps, nil, nil, caps, false
		}
		steps = append(steps, ProbeStep{Name: "auth", OK: true, Detail: "PLAIN"})
	}

	return steps, conn, r, caps, true
}
