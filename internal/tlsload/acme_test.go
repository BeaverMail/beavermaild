package tlsload_test

import (
	"testing"

	"github.com/BeaverMail/beaver/internal/tlsload"
)

func TestLoadACMERequiresHost(t *testing.T) {
	t.Parallel()
	_, err := tlsload.LoadACME(t.TempDir(), nil, "1.2")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadACMEBuildsConfig(t *testing.T) {
	t.Parallel()
	certs, err := tlsload.LoadACME(t.TempDir(), []string{"mail.example.com"}, "1.2")
	if err != nil {
		t.Fatal(err)
	}
	cfg := certs.Config()
	if cfg == nil || cfg.GetCertificate == nil {
		t.Fatal("expected GetCertificate from autocert")
	}
}
