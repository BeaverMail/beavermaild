// Domain DMARC/TLS-RPT report list and aggregates from the raw report store.
package httpapi

import (
	"errors"
	"net/http"
	"sort"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
)

// reportItem is one stored report with its parse outcome. Unparsed reports stay in
// the list with their Problems; they never contribute to the aggregates.
type reportItem struct {
	directory.ReportMeta
	Parsed   bool     `json:"parsed"`
	Problems []string `json:"problems,omitempty"`
}

// dmarcAggs aggregates DMARC outcomes over parsed reports only. Pass counts are the
// RFC 7489 policy_evaluated results (already identifier-aligned). Spoofing counts
// messages whose header_from is the reported domain (or a subdomain of it) with both
// aligned SPF and DKIM failing.
type dmarcAggs struct {
	Reports   int       `json:"reports"`
	Messages  int       `json:"messages"`
	DKIMPass  int       `json:"dkim_pass"`
	SPFPass   int       `json:"spf_pass"`
	DMARCPass int       `json:"dmarc_pass"`
	DMARCFail int       `json:"dmarc_fail"`
	Spoofing  spoofAggs `json:"spoofing"`
}

type spoofAggs struct {
	Messages  int      `json:"messages"`
	SourceIPs []string `json:"source_ips,omitempty"`
}

// tlsAggs aggregates TLS-RPT session outcomes over parsed reports only. Per-MX
// failures come from failure-details (optional in the report), so their sum can be
// lower than FailedSessions from the summaries.
type tlsAggs struct {
	Reports            int            `json:"reports"`
	SuccessfulSessions int            `json:"successful_sessions"`
	FailedSessions     int            `json:"failed_sessions"`
	MXFailures         []tlsMXFailure `json:"mx_failures,omitempty"`
}

type tlsMXFailure struct {
	MX             string   `json:"mx"`
	FailedSessions int      `json:"failed_sessions"`
	ResultTypes    []string `json:"result_types"`
}

// handleDomainReports lists the stored reports of a domain with aggregates computed
// only from successfully parsed payloads; unparsed reports are listed with their
// problems and never counted.
func (s *Server) handleDomainReports(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	domainName := r.PathValue("domain")
	dom, err := s.dir.LookupDomain(r.Context(), domainName)
	if err != nil {
		if errors.Is(err, directory.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "lookup domain failed")
		return
	}
	if !canListAllDomains(p) && !canSeeDomainTenant(p, dom.TenantID) &&
		!(p.Role == directory.RoleUser && strings.EqualFold(p.DomainName, dom.Name)) {
		writeError(w, http.StatusForbidden, "forbidden")
		return
	}
	stored, err := directory.ListDomainReports(s.dir.DataDir(), dom.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list reports failed")
		return
	}
	items := make([]reportItem, 0, len(stored))
	parsed := make([]directory.ParsedReport, 0, len(stored))
	for _, st := range stored {
		res := directory.ParseReport(s.log, st.Meta.Kind, st.Raw)
		problems := append(append([]string{}, st.Problems...), res.Problems...)
		items = append(items, reportItem{
			ReportMeta: st.Meta,
			Parsed:     res.DMARC != nil || res.TLS != nil,
			Problems:   problems,
		})
		parsed = append(parsed, res)
	}
	// Aggregates keys are omitted entirely (not null) when no report of that kind
	// parsed: the wire contract matches api.ts's optional dmarc?/tls? fields.
	resp := map[string]any{"domain": dom.Name, "reports": items}
	if d := aggregateDMARC(dom.Name, parsed); d != nil {
		resp["dmarc"] = d
	}
	if t := aggregateTLS(parsed); t != nil {
		resp["tls"] = t
	}
	writeJSON(w, http.StatusOK, resp)
}

// aggregateDMARC returns the DMARC aggregates or nil when no report parsed (never
// zero-filled aggregates over unparsed data).
func aggregateDMARC(domain string, parsed []directory.ParsedReport) *dmarcAggs {
	var agg *dmarcAggs
	seen := map[string]bool{}
	for _, p := range parsed {
		if p.DMARC == nil {
			continue
		}
		if agg == nil {
			agg = &dmarcAggs{}
		}
		agg.Reports++
		for _, rec := range p.DMARC.Records {
			n := rec.Row.Count
			dkim := strings.EqualFold(rec.Row.PolicyEvaluated.DKIM, "pass")
			spf := strings.EqualFold(rec.Row.PolicyEvaluated.SPF, "pass")
			agg.Messages += n
			if dkim {
				agg.DKIMPass += n
			}
			if spf {
				agg.SPFPass += n
			}
			if dkim || spf {
				agg.DMARCPass += n
				continue
			}
			agg.DMARCFail += n
			if !headerFromInDomain(rec.Identifiers.HeaderFrom, domain) {
				continue
			}
			agg.Spoofing.Messages += n
			ip := rec.Row.SourceIP
			if ip != "" && !seen[ip] {
				seen[ip] = true
				agg.Spoofing.SourceIPs = append(agg.Spoofing.SourceIPs, ip)
			}
		}
	}
	if agg != nil {
		sort.Strings(agg.Spoofing.SourceIPs)
	}
	return agg
}

// headerFromInDomain reports whether headerFrom is the domain or a subdomain of it.
func headerFromInDomain(headerFrom, domain string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(headerFrom)), ".")
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	return d != "" && (h == d || strings.HasSuffix(h, "."+d))
}

// aggregateTLS returns the TLS-RPT aggregates or nil when no report parsed.
func aggregateTLS(parsed []directory.ParsedReport) *tlsAggs {
	var agg *tlsAggs
	idx := map[string]int{}
	for _, p := range parsed {
		if p.TLS == nil {
			continue
		}
		if agg == nil {
			agg = &tlsAggs{}
		}
		agg.Reports++
		for _, pol := range p.TLS.Policies {
			agg.SuccessfulSessions += pol.Summary.TotalSuccessfulSessionCount
			agg.FailedSessions += pol.Summary.TotalFailureSessionCount
			for _, f := range pol.FailureDetails {
				mx := f.ReceivingMXHostname
				if mx == "" {
					mx = f.ReceivingMXIP
				}
				if mx == "" {
					mx = "unknown"
				}
				i, ok := idx[mx]
				if !ok {
					i = len(agg.MXFailures)
					idx[mx] = i
					agg.MXFailures = append(agg.MXFailures, tlsMXFailure{MX: mx})
				}
				agg.MXFailures[i].FailedSessions += f.FailedSessionCount
				agg.MXFailures[i].ResultTypes = appendUnique(agg.MXFailures[i].ResultTypes, f.ResultType)
			}
		}
	}
	if agg != nil {
		sort.Slice(agg.MXFailures, func(i, j int) bool { return agg.MXFailures[i].MX < agg.MXFailures[j].MX })
		for i := range agg.MXFailures {
			sort.Strings(agg.MXFailures[i].ResultTypes)
		}
	}
	return agg
}

// appendUnique appends v to xs unless already present.
func appendUnique(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}
