// Dedicated DMARC/TLS-RPT report ingest routing.
package smtp

import (
	"context"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
)

// reportKindForAddress maps the report addresses dmarc-reports@ / tls-reports@ to a
// report kind. Any other address returns "".
func reportKindForAddress(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	switch strings.ToLower(addr[:i]) {
	case "dmarc-reports":
		return "dmarc"
	case "tls-reports":
		return "tls"
	}
	return ""
}

// storeReport saves the raw report message to the domain report store in the data dir.
// The payload is kept verbatim; parsing happens later.
func (s *session) storeReport(ctx context.Context, t rcptTarget, raw []byte) error {
	domName, err := DomainFromAddress(t.address)
	if err != nil {
		return err
	}
	dom, err := s.dir.LookupDomain(ctx, domName)
	if err != nil {
		return err
	}
	_, err = directory.SaveDomainReport(s.dir.DataDir(), dom.ID, t.report, s.mailFrom, t.address, raw)
	return err
}
