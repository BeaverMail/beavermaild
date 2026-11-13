package smtp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/smtp"
)

func TestDomainFromAddress(t *testing.T) {
	t.Parallel()
	d, err := smtp.DomainFromAddress("user@Example.COM")
	if err != nil || d != "example.com" {
		t.Fatalf("domain %q err %v", d, err)
	}
	if _, err := smtp.DomainFromAddress("bad"); err == nil {
		t.Fatal("expected error")
	}
	// RFC 6531 3.2: MX lookups and local domain lookups use the A-label.
	if d, _ := smtp.DomainFromAddress("ivan@Пример.рф"); d != "xn--e1afmkfd.xn--p1ai" {
		t.Fatalf("U-label domain %q", d)
	}
}

// A domain with a null MX (RFC 7505; nullmx.test in the stub resolver of TestMain): no host to try,
// a permanent failure carrying 5.1.10 into the DSN.
func TestLookupHostsNullMX(t *testing.T) {
	t.Parallel()
	hosts, err := smtp.LookupHosts(context.Background(), "nullmx.test")
	var de *smtp.DeliveryError
	if !errors.As(err, &de) || !de.Permanent || mail.SMTPStatusFromError(err) != "5.1.10" {
		t.Fatalf("hosts %v err %v status %q, want permanent null MX with 5.1.10", hosts, err, mail.SMTPStatusFromError(err))
	}
}
