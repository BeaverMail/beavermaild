package dkimout

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "dkim.pem")
	if err := GenerateTestKey(keyPath); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Selector: "beaver", Domain: "example.com", KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: alice@example.com\r\nTo: bob@example.com\r\nSubject: hi\r\n\r\nbody\r\n")
	signed, err := s.Sign("alice@example.com", raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(signed, raw) {
		t.Fatal("expected signature added")
	}
	lower := strings.ToLower(string(signed))
	if !strings.Contains(lower, "dkim-signature:") || !strings.Contains(lower, "s=beaver") || !strings.Contains(lower, "d=example.com") {
		t.Fatalf("missing dkim header in %q", signed[:min(200, len(signed))])
	}
	signed2, err := s.Sign("alice@example.com", signed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed2, signed) {
		t.Fatal("expected idempotent sign with same selector")
	}
}

func TestSignDomainFromReturnPath(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "dkim.pem")
	if err := GenerateTestKey(keyPath); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Selector: "s1", KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: a@mail.test\r\n\r\nx\r\n")
	signed, err := s.Sign("sender@mail.test", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed), "d=mail.test") {
		t.Fatalf("signed headers %q", signed[:min(120, len(signed))])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
