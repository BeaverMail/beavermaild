// Derived from rspamd (https://github.com/rspamd/rspamd), Copyright (c) Vsevolod Stakhov and the
// rspamd contributors, Apache License 2.0 (LICENSES/Apache-2.0.txt): src/plugins/lua/{hfilter,dmarc,whitelist,spamtrap}.lua, lualib/plugins/dmarc.lua,
// rules/misc.lua and conf/modules.d/whitelist.conf.
// Translated to Go and modified for BeaverMail; see NOTICE.

// SMTP-session checks: host mail-auth results, trusted domains, spam traps, HELO / rDNS (hfilter).
package main

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// checkAuth maps the host SPF/DKIM/DMARC/ARC results to rspamd's policy symbols.
func checkAuth(a *authResults, r *result) {
	if a == nil {
		return
	}
	spf := map[string]string{"pass": "R_SPF_ALLOW", "fail": "R_SPF_FAIL", "softfail": "R_SPF_SOFTFAIL",
		"neutral": "R_SPF_NEUTRAL", "temperror": "R_SPF_DNSFAIL", "permerror": "R_SPF_PERMFAIL", "none": "R_SPF_NA"}
	if s := spf[a.SPFMailFrom]; s != "" {
		r.add(s, 1)
	} else if s := spf[a.SPFEhlo]; s != "" {
		r.add(s, 1)
	}
	dkim := map[string]string{"pass": "R_DKIM_ALLOW", "fail": "R_DKIM_REJECT", "temperror": "R_DKIM_TEMPFAIL",
		"permerror": "R_DKIM_PERMFAIL", "none": "R_DKIM_NA"}
	if s := dkim[a.DKIM]; s != "" {
		r.add(s, 1)
	}
	switch a.DMARC {
	case "pass":
		r.add("DMARC_POLICY_ALLOW", 1)
	case "fail":
		switch a.DMARCPolicy {
		case "reject":
			r.add("DMARC_POLICY_REJECT", 1)
		case "quarantine":
			r.add("DMARC_POLICY_QUARANTINE", 1)
		default:
			r.add("DMARC_POLICY_SOFTFAIL", 1)
		}
	case "temperror":
		r.add("DMARC_DNSFAIL", 1)
	case "permerror":
		r.add("DMARC_BAD_POLICY", 1)
	case "none":
		r.add("DMARC_NA", 1)
	}
	arc := map[string]string{"pass": "ARC_ALLOW", "fail": "ARC_REJECT", "invalid": "ARC_INVALID",
		"temperror": "ARC_DNSFAIL", "none": "ARC_NA"}
	if s := arc[a.ARC]; s != "" {
		r.add(s, 1)
	}
}

// fromDomain returns the lowercase domain of the first From header address.
func fromDomain(m *message) string {
	l, _, ok := m.addrs("From")
	if !ok {
		return ""
	}
	return domainOf(l[0].Address)
}

func domainOf(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(strings.Trim(addr[i+1:], "<> ")), ".")
}

// checkWhitelist ports the WHITELIST_DMARC rule of rspamd's whitelist plugin over trusted-domains.txt:
// a listed From domain scores WHITELIST_DMARC when DMARC passes and BLACKLIST_DMARC when it fails.
func (f *Filter) checkWhitelist(m *message, a *authResults, r *result) {
	d := fromDomain(m)
	if d == "" || a == nil || !f.trusted(d) {
		return
	}
	switch a.DMARC {
	case "pass":
		r.add("WHITELIST_DMARC", 1, d)
	case "fail":
		r.add("BLACKLIST_DMARC", 1, d)
	}
}

// trusted matches d or any parent domain against trusted-domains.txt.
func (f *Filter) trusted(d string) bool {
	for d != "" {
		if f.lists.Trusted[d] {
			return true
		}
		_, d, _ = strings.Cut(d, ".")
	}
	return false
}

// checkSpamtrap ports spamtrap.lua: a single recipient listed (address or @domain) is a trap hit.
func (f *Filter) checkSpamtrap(to []string, r *result) {
	if len(to) != 1 {
		return
	}
	rcpt := strings.ToLower(strings.Trim(to[0], "<> "))
	if f.lists.SpamTraps[rcpt] || f.lists.SpamTraps["@"+domainOf(rcpt)] {
		r.add("SPAMTRAP", 1, rcpt)
		switch f.cfg.Spamtrap.Action {
		case "reject":
			r.forced = actReject
		case "discard":
			r.forced = actDiscard
		}
	}
}

type weightedRe struct {
	re *regexp.Regexp
	w  int
}

func compileWeighted(src string) []weightedRe {
	var out []weightedRe
	for _, line := range strings.Split(strings.TrimSpace(src), "\n") {
		line, _, _ = strings.Cut(line, " #")
		f := strings.Fields(line)
		pat := strings.TrimSuffix(strings.TrimPrefix(f[0], "/"), "/i")
		w := 1
		if len(f) > 1 {
			w, _ = strconv.Atoi(f[1])
		}
		out = append(out, weightedRe{regexp.MustCompile("(?i)" + pat), w})
	}
	return out
}

func maxWeight(list []weightedRe, s string) int {
	w := 0
	for _, x := range list {
		if x.w > w && x.re.MatchString(s) {
			w = x.w
		}
	}
	return w
}

func anyMatch(list []weightedRe, s string) bool { return maxWeight(list, s) > 0 }

// Pattern tables from rspamd src/plugins/lua/hfilter.lua (weights: 5 very hard .. 1 very low).
var (
	checksHellohost = compileWeighted(`
/[-.0-9][0-9][.-]?nat/i 5
/homeuser[.-][0-9]/i 5
/[-.0-9][0-9][.-]?unused-addr/i 3
/[-.0-9][0-9][.-]?pppoe/i 5
/[-.0-9][0-9][.-]?dynamic/i 5
/[.-]catv[.-]/i 5
/unused-addr[.-][0-9]/i 3
/comcast[.-][0-9]/i 5
/[.-]broadband[.-]/i 5
/[0-9][.-]?fbx/i 4
/[.-]peer[.-]/i 1
/[.-]homeuser[.-]/i 5
/[-.0-9][0-9][.-]?catv/i 5
/customers?[.-][0-9]/i 1
/[.-]wifi[.-]/i 5
/[0-9][.-]?kabel/i 3
/dynip[.-][0-9]/i 5
/[.-]broad[.-]/i 5
/[a|x]?dsl-line[.-]?[0-9]/i 4
/[-.0-9][0-9][.-]?ppp/i 5
/pool[.-][0-9]/i 4
/[.-]nat[.-]/i 5
/gprs[.-][0-9]/i 5
/brodband[.-][0-9]/i 5
/[.-]gprs[.-]/i 5
/[.-]user[.-]/i 1
/[-.0-9][0-9][.-]?in-?addr/i 4
/[.-]host[.-]/i 2
/[.-]fbx[.-]/i 4
/dynamic[.-][0-9]/i 5
/[-.0-9][0-9][.-]?peer/i 1
/[-.0-9][0-9][.-]?pool/i 4
/[-.0-9][0-9][.-]?user/i 1
/[.-]cdma[.-]/i 5
/user[.-][0-9]/i 1
/[-.0-9][0-9][.-]?customers?/i 1
/ppp[.-][0-9]/i 5
/kabel[.-][0-9]/i 3
/dhcp[.-][0-9]/i 5
/peer[.-][0-9]/i 1
/[-.0-9][0-9][.-]?host/i 2
/clients?[.-][0-9]{2,}/i 5
/host[.-][0-9]/i 2
/[.-]ppp[.-]/i 5
/[.-]dhcp[.-]/i 5
/cable[.-][0-9]/i 3
/[-.0-9][0-9][.-]?dial-?up/i 5
/[-.0-9][0-9][.-]?bredband/i 5
/[-.0-9][0-9][.-]?[a|x]?dsl-line/i 4
/[.-]dial-?up[.-]/i 5
/[.-]cablemodem[.-]/i 5
/pppoe[.-][0-9]/i 5
/[.-]unused-addr[.-]/i 3
/pptp[.-][0-9]/i 5
/broadband[.-][0-9]/i 5
/[.-][a|x]?dsl-line[.-]/i 4
/[.-]customers?[.-]/i 1
/[-.0-9][0-9][.-]?fibertel/i 4
/[-.0-9][0-9][.-]?comcast/i 5
/[.-]dynamic[.-]/i 5
/cdma[.-][0-9]/i 5
/[0-9][.-]?broad/i 5
/fbx[.-][0-9]/i 4
/catv[.-][0-9]/i 5
/[-.0-9][0-9][.-]?homeuser/i 5
/[-.0-9][.-]pppoe[.-]/i 5
/[-.0-9][.-]dynip[.-]/i 5
/[-.0-9][0-9][.-]?[a|x]?dsl/i 4
/[-.0-9][0-9]{3,}[.-]?clients?/i 5
/[-.0-9][0-9][.-]?pptp/i 5
/[.-]clients?[.-]/i 1
/[.-]in-?addr[.-]/i 4
/[.-]pool[.-]/i 4
/[a|x]?dsl[.-]?[0-9]/i 4
/[.-][a|x]?dsl[.-]/i 4
/[-.0-9][0-9][.-]?[a|x]?dsl-dynamic/i 5
/dial-?up[.-][0-9]/i 5
/[-.0-9][0-9][.-]?cablemodem/i 5
/[a|x]?dsl-dynamic[.-]?[0-9]/i 5
/[.-]pptp[.-]/i 5
/[.-][a|x]?dsl-dynamic[.-]/i 5
/[0-9][.-]?wifi/i 5
/fibertel[.-][0-9]/i 4
/dyn[.-][0-9][-.0-9]/i 5
/[-.0-9][0-9][.-]broadband/i 5
/[-.0-9][0-9][.-]cable/i 3
/broad[.-][0-9]/i 5
/[-.0-9][0-9][.-]gprs/i 5
/cablemodem[.-][0-9]/i 5
/[-.0-9][0-9][.-]modem/i 5
/[-.0-9][0-9][.-]dyn/i 5
/[-.0-9][0-9][.-]dynip/i 5
/[-.0-9][0-9][.-]cdma/i 5
/[.-]modem[.-]/i 5
/[.-]kabel[.-]/i 3
/[.-]cable[.-]/i 3
/in-?addr[.-][0-9]/i 4
/nat[.-][0-9]/i 5
/[.-]fibertel[.-]/i 4
/[.-]bredband[.-]/i 5
/modem[.-][0-9]/i 5
/[0-9][.-]?dhcp/i 5
/wifi[.-][0-9]/i 5
/[.-]vps[.-]/i 1`)

	checksHello = compileWeighted(`
/^[^\.]+$/i 5
/^(dsl)?(device|speedtouch)\.lan$/i 5
/\.(lan|local|home|localdomain|intra|in-addr.arpa|priv|user|veloxzon)$/i 5`)

	checksHelloBadIP = compileWeighted(`
/^\d+\.\d+\.\d+\.255$/i 1
/^192\.0\.0\.\d+/i 1
/^2001:db8::/i 1
/^10\.\d+\.\d+\.\d+/i 1
/^192\.0\.2\.\d+/i 1
/^172\.1[6-9]\.\d+\.\d+/i 1
/^192\.168\.\d+\.\d+/i 1
/^127\.\d+\.\d+\.\d+/i 1
/^::1$/i 1
/^ffxx::/i 1
/^fc00::/i 1
/^203\.0\.113\.\d+/i 1
/^fe[cdf][0-9a-f]:/i 1
/^100.12[0-7]\.\d+\.\d+/i 1
/^fe[89ab][0-9a-f]::/i 1
/^169\.254\.\d+\.\d+/i 1
/^0\.\d+\.\d+\.\d+/i 1
/^198\.51\.100\.\d+/i 1
/^172\.3[01]\.\d+\.\d+/i 1
/^100.[7-9]\d\.\d+\.\d+/i 1
/^100.1[01]\d\.\d+\.\d+/i 1
/^100.6[4-9]\.\d+\.\d+/i 1
/^192\.88\.99\.\d+/i 1
/^172\.2[0-9]\.\d+\.\d+/i 1`)

	checksHelloBareIP = compileWeighted(`
/^\d+[x.-]\d+[x.-]\d+[x.-]\d+$/i
/^[0-9a-f]+:/i`)
)

// checkHelloHost ports hfilter's HELO and HOSTNAME (PTR) pattern checks and rspamd's RDNS_* rule.
// Only the higher of the HELO and HOSTNAME weights is inserted, as in hfilter.
func checkHelloHost(req *request, r *result) {
	weightHelo := 0
	helo := strings.NewReplacer("[", "", "]", "").Replace(strings.ToLower(req.EHLODomain))
	if helo != "" {
		switch {
		case anyMatch(checksHelloBadIP, helo):
			r.add("HFILTER_HELO_BADIP", 1, helo)
		case anyMatch(checksHelloBareIP, helo):
			r.add("HFILTER_HELO_BAREIP", 1, helo)
		default:
			weightHelo = max(maxWeight(checksHello, helo), maxWeight(checksHellohost, helo))
		}
	}
	weightHost := 0
	switch req.IPRevResult {
	case "pass":
		if req.IPRevPTR != "" {
			weightHost = maxWeight(checksHellohost, strings.ToLower(req.IPRevPTR))
		}
	case "none":
		r.add("RDNS_NONE", 1)
		r.add("HFILTER_HOSTNAME_UNKNOWN", 1)
	case "temperror":
		// rspamd also adds RDNS_NONE here; a resolver failure is not scored as a missing PTR.
		r.add("RDNS_DNSFAIL", 1)
	}
	if weightHelo > 0 && weightHelo >= weightHost {
		r.add("HFILTER_HELO_"+strconv.Itoa(weightHelo), 1, helo)
	} else if weightHost > 0 {
		r.add("HFILTER_HOSTNAME_"+strconv.Itoa(weightHost), 1, req.IPRevPTR)
	}
}

// checkHFilterMessage ports hfilter's bounce and URL-only checks.
func checkHFilterMessage(req *request, m *message, r *result) {
	bounce := req.From == "" || strings.HasPrefix(strings.ToLower(req.From), "postmaster@")
	if req.From == "" && req.EHLODomain != "" {
		r.add("HFILTER_FROM_BOUNCE", 1, req.EHLODomain)
	}
	if bounce && len(req.To) > 1 {
		r.add("HFILTER_RCPT_BOUNCEMOREONE", 1, strconv.Itoa(len(req.To)))
	}
	var plain, htm *part
	for _, p := range m.textParts() {
		if p.html != nil {
			htm = p
		} else {
			plain = p
		}
	}
	p, ty := htm, "html"
	if p == nil {
		p, ty = plain, "plain"
	}
	if p == nil {
		return
	}
	plen, ulen := len(strings.TrimSpace(p.text)), textURLLen(p)
	if plen == 0 || ulen == 0 {
		return
	}
	if rel := float64(ulen) / float64(plen); rel > 0.8 {
		r.add("HFILTER_URL_ONLY", min((rel-0.8)*5, 1))
		if p.lines < 2 {
			r.add("HFILTER_URL_ONELINE", 1, ty)
		}
	}
}

// isFQDN is hfilter's check_fqdn: 4-253 chars, labels of 1-63 [a-z0-9-] not starting/ending with '-',
// at least two labels, the last 2-63 chars.
func isFQDN(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if len(s) < 4 || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 || len(labels[len(labels)-1]) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// checkHostsDNS ports hfilter's check_host for HELO, MAIL FROM domain and Message-ID host.
func (f *Filter) checkHostsDNS(ctx context.Context, req *request, m *message, r *result) {
	helo := strings.ToLower(req.EHLODomain)
	if helo != "" && !r.has("HFILTER_HELO_BADIP") && !r.has("HFILTER_HELO_BAREIP") &&
		maxWeight(checksHello, helo) == 0 && maxWeight(checksHellohost, helo) == 0 {
		f.checkHost(ctx, helo, "HELO", req.ClientIP, r)
	}
	if d := domainOf(req.From); d != "" {
		f.checkHost(ctx, d, "FROMHOST", "", r)
	}
	if mid, ok := m.get("Message-ID"); ok {
		if _, rhs, ok := strings.Cut(strings.Trim(mid, "<> "), "@"); ok && !strings.Contains(rhs, "local") {
			f.checkHost(ctx, strings.ToLower(rhs), "MID", "", r)
		}
	}
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

func (f *Filter) checkHost(ctx context.Context, host, suffix, eqIP string, r *result) {
	if !isFQDN(host) {
		r.add("HFILTER_"+suffix+"_NOT_FQDN", 1, host)
		return
	}
	addrs, err := f.resolver.LookupIPAddr(ctx, host)
	if err != nil && !isNotFound(err) {
		return // resolver failure: no verdict
	}
	if eqIP != "" {
		matched := false
		for _, a := range addrs {
			matched = matched || a.IP.String() == eqIP
		}
		if !matched {
			r.add("HFILTER_"+suffix+"_IP_A", 1, host)
		}
	}
	if len(addrs) > 0 {
		return
	}
	mxs, err := f.resolver.LookupMX(ctx, host)
	if err != nil && !isNotFound(err) {
		return
	}
	if len(mxs) == 0 {
		r.add("HFILTER_"+suffix+"_NORES_A_OR_MX", 1, host)
		return
	}
	for _, mx := range mxs {
		if a, err := f.resolver.LookupIPAddr(ctx, mx.Host); len(a) == 0 && isNotFound(err) {
			r.add("HFILTER_"+suffix+"_NORESOLVE_MX", 1, mx.Host)
		}
	}
}
