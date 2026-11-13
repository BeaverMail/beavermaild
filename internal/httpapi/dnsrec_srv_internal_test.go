package httpapi

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// RFC 6186 / RFC 8314 4.5.2: one SRV record per client-facing listener, Implicit TLS preferred.
func TestDNSRecommendedSRV(t *testing.T) {
	t.Parallel()
	services := []MailService{{"_submissions._tcp", 0, 465}, {"_imap._tcp", 10, 143}}
	recs := dnsRecommendedRecords(storage.Domain{Name: "hosted.example", MailHostname: "mail.hosted.example"}, "", "", nil, services)
	want := map[string]string{
		"_submissions._tcp.hosted.example": "0 1 465 mail.hosted.example",
		"_imap._tcp.hosted.example":        "10 1 143 mail.hosted.example",
	}
	for _, r := range recs {
		if r.Type != "SRV" {
			continue
		}
		if want[r.Host] != r.Value || r.Placeholder {
			t.Errorf("unexpected SRV %+v", r)
		}
		delete(want, r.Host)
	}
	if len(want) != 0 {
		t.Fatalf("missing SRV %v", want)
	}
}
