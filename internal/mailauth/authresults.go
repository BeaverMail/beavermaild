package mailauth

import (
	"net"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
)

// AuthResults returns the value of an RFC 8601 Authentication-Results header for the
// checks recorded in st (folded, without the field name), e.g.
//
//	mx.example.com;
//		spf=pass smtp.mailfrom=a@example.org;
//		dkim=pass header.d=example.org;
//		dmarc=pass header.from=example.org
//
// mailFrom is the envelope sender ("" for a null sender, then SPF is reported for helo).
func AuthResults(authservID, mailFrom, helo string, st SessionState) string {
	var methods []string
	switch {
	case mailFrom != "" && st.SPFMailFrom != "":
		// RFC 8601 2.7.2: SPF does not authenticate the local-part, so only the domain is reported.
		m := "spf=" + st.SPFMailFrom
		if d := pvalueDomain(domainFromAddress(mailFrom)); d != "" {
			m += " smtp.mailfrom=" + d
		}
		methods = append(methods, m)
	case st.SPFEhlo != "":
		m := "spf=" + st.SPFEhlo
		if h := pvalueDomain(helo); h != "" {
			m += " smtp.helo=" + h
		}
		methods = append(methods, m)
	}
	if st.DKIM != "" {
		m := "dkim=" + st.DKIM
		if d := pvalueDomain(st.DKIMDomain); d != "" {
			m += " header.d=" + d
		}
		methods = append(methods, m)
	}
	if st.DMARC != "" {
		m := "dmarc=" + st.DMARC
		if st.DMARCPolicy != "" {
			m += " (p=" + st.DMARCPolicy + ")"
		}
		if d := pvalueDomain(st.FromDomain); d != "" {
			m += " header.from=" + d
		}
		methods = append(methods, m)
	}
	// RFC 8617 10.1 registers only none, pass and fail for arc (RFC 8601 4: results MUST be
	// registered): an invalid chain is a failure, a DNS error is left unreported.
	switch st.ARC {
	case "none", "pass", "fail":
		methods = append(methods, "arc="+st.ARC)
	case "invalid":
		methods = append(methods, "arc=fail")
	}
	if len(methods) == 0 {
		return authservID + "; none" // RFC 8601 §2.2: no method was applied
	}
	return authservID + ";\r\n\t" + strings.Join(methods, ";\r\n\t")
}

// pvalueDomain is a domain as an RFC 8601 pvalue: a domain name, or an address literal as a quoted
// string, else "" (the property is left out). Every reported domain comes from the sender (EHLO
// argument, envelope, a DKIM d= tag even of a failing signature, From): put as is, an EHLO of
// "x;dkim=pass header.d=bank.example" added a forged result, and a d= of "evil(" opened a comment
// that hid the rest of our field, DMARC result included.
func pvalueDomain(s string) string {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		ip := s[1 : len(s)-1]
		if len(ip) > 5 && strings.EqualFold(ip[:5], "IPv6:") {
			ip = ip[5:]
		}
		if net.ParseIP(ip) == nil {
			return ""
		}
		return `"` + s + `"`
	}
	d := dnsname.ToASCII(s) // A-labels, lowercase; an "@" is refused below, never cut away
	if d == "" || len(d) > 253 {
		return ""
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' ||
			strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return ""
		}
	}
	return d
}
