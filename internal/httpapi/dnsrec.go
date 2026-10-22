// Recommended DNS records for a hosted domain (MX, SPF, DKIM, autoconfig).
package httpapi

import (
	"errors"
	"net/http"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/storage"
)

type dnsRecordDTO struct {
	Type        string `json:"type"`
	Host        string `json:"host"`
	Value       string `json:"value"`
	Placeholder bool   `json:"placeholder,omitempty"`
	Note        string `json:"note,omitempty"`
}

// dnsRecommendedRecords builds the publish-ready record list. dkimName/dkimVal come from
// directory.DKIMDNSRecord: empty with dkimErr==nil means no key is generated and no row is
// emitted (inactive features stay hidden), empty with dkimErr!=nil means the key could not
// be read and the row stays with an honest note; every non-real value is flagged as
// placeholder so nothing invented goes unmarked.
func dnsRecommendedRecords(dom storage.Domain, dkimName, dkimVal string, dkimErr error) []dnsRecordDTO {
	mailHost := dom.MailHostname
	hostPlaceholder := mailHost == ""
	if hostPlaceholder {
		mailHost = "mail." + dom.Name
	}
	hostNote := ""
	if hostPlaceholder {
		hostNote = "placeholder: set the domain mail hostname first"
	}

	recs := []dnsRecordDTO{
		{Type: "MX", Host: dom.Name, Value: "10 " + mailHost, Placeholder: hostPlaceholder, Note: hostNote},
		{Type: "TXT", Host: dom.Name, Value: "v=spf1 mx a:" + mailHost + " ~all", Placeholder: hostPlaceholder, Note: hostNote},
	}

	// Inactive features emit no row: no DKIM row while no key is generated, and no MTA-STS
	// row because the server does not serve an inbound policy (https://mta-sts.<domain>/.well-known/mta-sts.txt).
	switch {
	case dkimName != "" && dkimVal != "":
		recs = append(recs, dnsRecordDTO{Type: "TXT", Host: dkimName, Value: dkimVal})
	case dkimErr != nil:
		// DKIM is on but the key is unreadable: a real problem, not an inactive
		// feature, so the row stays visible with an honest note instead of a fake key.
		selector := dom.DKIMSelector
		if selector == "" {
			selector = "<selector>"
		}
		recs = append(recs, dnsRecordDTO{
			Type: "TXT", Host: selector + "._domainkey." + dom.Name,
			Value:       "v=DKIM1; k=rsa; p=<DKIM public key>",
			Placeholder: true,
			Note:        "placeholder: the DKIM key could not be read (missing or unreadable, see server logs); the value below is not the real key",
		})
	}

	// DMARC (RFC 9989/9990) and TLS-RPT (RFC 8460) reports land on addresses the SMTP server
	// already ingests on every hosted domain (smtp.reportKindForAddress). Same-domain rua needs
	// no _report._dmarc authorization record. p=none only asks for reports, it changes no delivery.
	recs = append(recs,
		dnsRecordDTO{
			Type: "TXT", Host: "_dmarc." + dom.Name,
			Value: "v=DMARC1; p=none; rua=mailto:dmarc-reports@" + dom.Name,
			Note:  "monitoring only; move to p=quarantine or p=reject once reports show all legitimate mail passes. If a DMARC record already exists, add this rua to it: two DMARC records invalidate both",
		},
		dnsRecordDTO{
			Type: "TXT", Host: "_smtp._tls." + dom.Name,
			Value: "v=TLSRPTv1; rua=mailto:tls-reports@" + dom.Name,
		},
		dnsRecordDTO{Type: "CNAME", Host: "autoconfig." + dom.Name, Value: mailHost, Placeholder: hostPlaceholder, Note: hostNote},
		dnsRecordDTO{Type: "CNAME", Host: "autodiscover." + dom.Name, Value: mailHost, Placeholder: hostPlaceholder, Note: hostNote},
	)
	return recs
}

// handleDomainDNSRecommended returns the recommended DNS records for a domain in scope.
func (s *Server) handleDomainDNSRecommended(w http.ResponseWriter, r *http.Request) {
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
	dkimName, dkimVal, dkimErr := s.dir.DKIMDNSRecord(dom)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":  dom.Name,
		"records": dnsRecommendedRecords(dom, dkimName, dkimVal, dkimErr),
	})
}
