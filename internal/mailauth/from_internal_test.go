package mailauth

import (
	"os"
	"path/filepath"
	"testing"
)

// RFC 5322 4.5.2: "From :" is a From field. DMARC must read the same From the inbound check and a
// conforming MUA read, or a second From in obsolete syntax would go unchecked.
func TestHeaderFromDomainObsoleteSyntax(t *testing.T) {
	t.Parallel()
	for msg, want := range map[string]string{
		"From : a@bank.example\r\n\r\nbody":                             "bank.example",
		"From : a@bank.example\r\nFrom: b@attacker.example\r\n\r\nbody": "",
	} {
		p := filepath.Join(t.TempDir(), "m")
		if err := os.WriteFile(p, []byte(msg), 0o600); err != nil {
			t.Fatal(err)
		}
		if d, ok := headerFromDomain(p); d != want || ok != (want != "") {
			t.Errorf("%q: got %q %v, want %q", msg, d, ok, want)
		}
	}
}
