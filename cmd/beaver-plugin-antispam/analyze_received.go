// Received header heuristics (reference analysis/received.rs subset).
package main

import (
	"net"
	"strings"
	"unicode"
)

func analyzeReceived(ctx *classifyCtx, res *classifyResult) {
	lines := ctx.msg.received
	rcvdCount := len(lines)
	rcvdFromIP := 0
	tlsCount := 0

	for _, line := range lines {
		if !isASCII(line) {
			res.addTag("RCVD_ILLEGAL_CHARS")
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, " helo=user") || strings.Contains(lower, " ehlo=user") {
			res.addTag("RCVD_HELO_USER")
		}
		checkForgedRcvdTrail(line, res)
		if receivedFromBareIP(lower) {
			rcvdFromIP++
		}
		if strings.Contains(lower, "tls") || strings.Contains(lower, "ssl") {
			tlsCount++
		}
		if strings.Contains(lower, "for ") && recipientOnReceived(ctx, lower) {
			res.addTag("PREVIOUSLY_DELIVERED")
		}
	}

	if rcvdFromIP >= 2 || (rcvdFromIP == 1 && parseHostname(ctx.req.EHLODomain).isIP) {
		res.addTag("RCVD_DOUBLE_IP_SPAM")
	}
	if ctx.req.Authenticated {
		res.addTag("RCVD_VIA_SMTP_AUTH")
	}
	if rcvdCount > 0 {
		if rcvdCount == tlsCount && ctx.req.TLS {
			res.addTag("RCVD_TLS_ALL")
		} else if ctx.req.TLS {
			res.addTag("RCVD_TLS_LAST")
		} else {
			res.addTag("RCVD_NO_TLS_LAST")
		}
	}
	addReceivedCountTag(res, rcvdCount)
}

// checkForgedRcvdTrail tags when a Received HELO/from hostname disagrees with its PTR name.
func checkForgedRcvdTrail(line string, res *classifyResult) {
	lower := strings.ToLower(line)
	if strings.Contains(lower, " helo=user") || strings.Contains(lower, " ehlo=user") {
		return
	}
	idx := strings.Index(lower, "from ")
	if idx < 0 {
		return
	}
	rest := strings.TrimSpace(line[idx+5:])
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return
	}
	heloDomain := strings.Trim(fields[0], "([")
	if strings.EqualFold(heloDomain, "user") {
		return
	}
	pStart := strings.Index(rest, "(")
	if pStart < 0 {
		return
	}
	pEnd := strings.Index(rest[pStart:], ")")
	if pEnd < 0 {
		return
	}
	inner := strings.TrimSpace(rest[pStart+1 : pStart+pEnd])
	if bracket := strings.Index(inner, "["); bracket >= 0 {
		inner = strings.TrimSpace(inner[:bracket])
	}
	if inner == "" || net.ParseIP(inner) != nil {
		return
	}
	if strings.HasPrefix(strings.ToLower(inner), "helo ") {
		inner = strings.TrimSpace(inner[5:])
	}
	if inner != "" && !strings.EqualFold(heloDomain, inner) {
		res.addTag("FORGED_RCVD_TRAIL")
	}
}

func addReceivedCountTag(res *classifyResult, n int) {
	switch {
	case n == 0:
		res.addTag("RCVD_COUNT_ZERO")
	case n == 1:
		res.addTag("RCVD_COUNT_ONE")
	case n == 2:
		res.addTag("RCVD_COUNT_TWO")
	case n == 3:
		res.addTag("RCVD_COUNT_THREE")
	case n == 4, n == 5:
		res.addTag("RCVD_COUNT_FIVE")
	case n == 6, n == 7:
		res.addTag("RCVD_COUNT_SEVEN")
	case n >= 8 && n <= 12:
		res.addTag("RCVD_COUNT_TWELVE")
	}
}

func receivedFromBareIP(line string) bool {
	idx := strings.Index(line, "from ")
	if idx < 0 {
		return false
	}
	rest := strings.TrimSpace(line[idx+5:])
	if i := strings.IndexByte(rest, ' '); i > 0 {
		rest = rest[:i]
	}
	rest = strings.Trim(rest, "[]")
	return netParseMaybeIP(rest)
}

func netParseMaybeIP(s string) bool {
	return net.ParseIP(s) != nil
}

func recipientOnReceived(ctx *classifyCtx, line string) bool {
	for _, to := range ctx.req.To {
		addr := strings.ToLower(strings.TrimSpace(to))
		if addr != "" && strings.Contains(line, addr) {
			return true
		}
	}
	if ctx.msg.To != nil {
		for _, to := range ctx.msg.To {
			if strings.Contains(line, strings.ToLower(to)) {
				return true
			}
		}
	}
	return false
}

func isASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}
