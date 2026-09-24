// Recommended DNS records for a hosted domain (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT, autoconfig).
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
// directory.DKIMDNSRecord and are empty when no key is generated; every non-real value is
// flagged as placeholder so nothing invented goes unmarked.
func dnsRecommendedRecords(dom storage.Domain, dkimName, dkimVal string) []dnsRecordDTO {
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

	switch {
	case dkimName != "" && dkimVal != "":
		recs = append(recs, dnsRecordDTO{Type: "TXT", Host: dkimName, Value: dkimVal})
	default:
		selector := dom.DKIMSelector
		if selector == "" {
			selector = "selector"
		}
		recs = append(recs, dnsRecordDTO{
			Type: "TXT", Host: selector + "._domainkey." + dom.Name,
			Value:       "v=DKIM1; k=rsa; p=<DKIM public key>",
			Placeholder: true,
			Note:        "placeholder: enable DKIM to generate the key and get the real value",
		})
	}

	recs = append(recs,
		dnsRecordDTO{
			Type: "TXT", Host: "_dmarc." + dom.Name,
			Value:       "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@" + dom.Name,
			Placeholder: true,
			Note:        "placeholder: point rua at your report inbox (report addresses not configurable yet)",
		},
		dnsRecordDTO{
			Type: "TXT", Host: "_mta-sts." + dom.Name,
			Value:       "v=STSv1; id=<policy id>",
			Placeholder: true,
			Note:        "placeholder: set id to the policy version published at https://mta-sts." + dom.Name + "/.well-known/mta-sts.txt",
		},
		dnsRecordDTO{
			Type: "TXT", Host: "_smtp._tls." + dom.Name,
			Value:       "v=TLSRPTv1; rua=mailto:tls-reports@" + dom.Name,
			Placeholder: true,
			Note:        "placeholder: point rua at your report inbox (report addresses not configurable yet)",
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
	dkimName, dkimVal, _ := s.dir.DKIMDNSRecord(dom)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain":  dom.Name,
		"records": dnsRecommendedRecords(dom, dkimName, dkimVal),
	})
}
