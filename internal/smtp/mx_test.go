package smtp_test

import (
	"context"
	"errors"
	"strings"
	"testing"

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
}

// example.com publishes a null MX (RFC 7505): no host to try, a permanent failure.
func TestLookupHostsExampleCOM(t *testing.T) {
	t.Parallel()
	hosts, err := smtp.LookupHosts(context.Background(), "example.com")
	var de *smtp.DeliveryError
	if !errors.As(err, &de) || !de.Permanent {
		if err != nil && strings.Contains(err.Error(), "lookup") {
			t.Skipf("mx lookup: %v", err)
		}
		t.Fatalf("hosts %v err %v, want permanent null MX", hosts, err)
	}
}
