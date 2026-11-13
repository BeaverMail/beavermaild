package mailauth_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/mailauth"
)

func TestNewDisabledReturnsNil(t *testing.T) {
	if v := mailauth.New(mailauth.Config{Enabled: false}); v != nil {
		t.Fatal("expected nil verifier")
	}
}

func TestSessionStateWireRoundTrip(t *testing.T) {
	s := mailauth.SessionState{
		SPFEhlo:     "pass",
		SPFMailFrom: "fail",
		DKIM:        "pass",
		DMARC:       "fail",
		DMARCPolicy: "reject",
	}
	w := s.Wire()
	if w.SPFEhlo != "pass" || w.DMARCPolicy != "reject" {
		t.Fatalf("wire: %+v", w)
	}
}

// TestFinishEomARCNone confirms a message with no ARC set yields ResultNone
// and never triggers DNS lookups, keeping the verify path deterministic.
func TestFinishEomARCNone(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plain.eml")
	raw := "From: sender@example.com\r\nSubject: hi\r\n\r\nbody\r\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	lookups := 0
	v := mailauth.New(mailauth.Config{
		Enabled:    true,
		ARCEnabled: true,
		LookupTXT: func(context.Context, string) ([]string, error) {
			lookups++
			return nil, nil
		},
	})
	state := v.FinishEom(context.Background(), path, "sender@example.com", "helo.example", mailauth.SessionState{})
	if state.ARC != "none" {
		t.Fatalf("arc=%q want none", state.ARC)
	}
	if lookups != 0 {
		t.Fatalf("unexpected %d ARC DNS lookups for a message without ARC", lookups)
	}
}

// RFC 8616 / RFC 6531 3.2: a From domain in U-label (or fullwidth) form is the same domain as its
// A-label and gets that domain's DMARC policy. Unconverted, the Go resolver answers "no such host"
// without querying and a forged From passed as "none".
func TestDMARCUnicodeFromDomain(t *testing.T) {
	for _, from := range []string{"ceo@münchen.example", "ceo@ＭＵＮＣＨＥＮ.example", "ceo@ｅｘａｍｐｌｅ.com"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "m.eml")
		if err := os.WriteFile(path, []byte("From: "+from+"\r\nSubject: hi\r\n\r\nbody\r\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		v := mailauth.New(mailauth.Config{
			Enabled:      true,
			DMARCEnabled: true,
			LookupTXT: func(_ context.Context, name string) ([]string, error) {
				switch name {
				case "_dmarc.xn--mnchen-3ya.example", "_dmarc.munchen.example", "_dmarc.example.com":
					return []string{"v=DMARC1; p=reject"}, nil
				}
				return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
			},
		})
		state := v.FinishEom(context.Background(), path, "x@attacker.example", "helo.example", mailauth.SessionState{SPFMailFrom: "pass"})
		if state.DMARC != "fail" || state.DMARCPolicy != "reject" {
			t.Errorf("%s: dmarc=%q policy=%q, want fail/reject", from, state.DMARC, state.DMARCPolicy)
		}
	}
}
