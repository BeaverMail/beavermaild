package mailauth_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/mailauth"
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
