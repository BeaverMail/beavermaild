package mailauth_test

import (
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
