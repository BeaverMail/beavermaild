package httpapi

import (
	"testing"

	"github.com/BeaverMail/beavermaild/internal/smtp"
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

// RFC 7208 audit L8: the EHLO name gets "v=spf1 a -all" so null-sender notifications pass SPF; not
// when a relay delivers or the name is not a domain.
func TestHeloSPFRecord(t *testing.T) {
	rec, ok := heloSPFRecord(&smtp.RemoteConfig{MXOptions: smtp.ClientOptions{HeloName: "mx.hosted.example"}})
	if !ok || rec.Type != "TXT" || rec.Host != "mx.hosted.example" || rec.Value != "v=spf1 a -all" {
		t.Fatalf("%+v %v", rec, ok)
	}
	for _, remote := range []*smtp.RemoteConfig{
		nil,
		{Relay: "relay.example:587", MXOptions: smtp.ClientOptions{HeloName: "mx.hosted.example"}},
		{MXOptions: smtp.ClientOptions{HeloName: "localhost"}},
	} {
		if rec, ok := heloSPFRecord(remote); ok {
			t.Errorf("row %+v for %+v", rec, remote)
		}
	}
}
