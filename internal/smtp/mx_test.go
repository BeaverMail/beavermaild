package smtp_test

import (
	"context"
	"testing"

	"github.com/BeaverMail/beaver/internal/smtp"
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

func TestLookupHostsExampleCOM(t *testing.T) {
	t.Parallel()
	hosts, err := smtp.LookupHosts(context.Background(), "example.com")
	if err != nil {
		t.Skipf("mx lookup: %v", err)
	}
	if len(hosts) == 0 {
		t.Fatal("no hosts")
	}
	for _, h := range hosts {
		if h == "" {
			t.Fatalf("empty host in %v", hosts)
		}
	}
}
