// Dedicated DMARC/TLS-RPT report ingest routing.
package smtp

import (
	"context"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/directory"
)

// reportKindForAddress maps the report addresses dmarc-reports@ / tls-reports@ to a
// report kind. Any other address returns "".
func reportKindForAddress(addr string) string {
	i := strings.LastIndexByte(addr, '@')
	if i < 0 {
		return ""
	}
	return directory.ReportLocalParts[strings.ToLower(addr[:i])]
}

// storeReport saves the report message (header, then the spooled body) to the domain report store.
// The payload is kept verbatim; parsing happens later.
func (s *session) storeReport(ctx context.Context, t rcptTarget, header []byte) error {
	domName, err := DomainFromAddress(t.address)
	if err != nil {
		return err
	}
	dom, err := s.dir.LookupDomain(ctx, domName)
	if err != nil {
		return err
	}
	msg, err := s.spool.message(header)
	if err != nil {
		return err
	}
	path, err := directory.SaveDomainReportFrom(s.dir.DataDir(), dom.ID, t.report, s.mailFrom, t.address, msg)
	if err != nil {
		return err
	}
	directory.ParseStoredReport(s.log, t.report, path) // parse once on arrival (bounded), cached for listings
	return nil
}
