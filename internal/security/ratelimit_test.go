package security_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/security"
)

func TestRateLimitGateBlocksAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_700_000_000, 0)
	now := start
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 3, Window: time.Minute})
	gate.SetClockForTest(func() time.Time { return now })

	ip := "203.0.113.7"
	for i := 0; i < 3; i++ {
		if !gate.AllowAuth(ip, "alice") {
			t.Fatalf("attempt %d: unexpected block", i+1)
		}
		gate.RecordAuthFailure(ip, "alice")
	}
	if gate.AllowAuth(ip, "alice") {
		t.Fatal("expected block after max failures")
	}

	now = start.Add(time.Minute)
	if !gate.AllowAuth(ip, "alice") {
		t.Fatal("expected window reset")
	}

	gate.RecordAuthFailure(ip, "alice")
	gate.RecordAuthSuccess(ip, "alice")
	if !gate.AllowAuth(ip, "alice") {
		t.Fatal("expected clear after success")
	}
}

func TestRateLimitGateSuccessClearsFailures(t *testing.T) {
	t.Parallel()
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 2, Window: time.Minute})
	ip := "198.51.100.1"
	gate.RecordAuthFailure(ip, "bob")
	gate.RecordAuthSuccess(ip, "bob")
	gate.RecordAuthFailure(ip, "bob")
	if !gate.AllowAuth(ip, "bob") {
		t.Fatal("success should reset counter")
	}
}

// TestRateLimitSuccessForgivesOnlyItsName: signing in to one's own account must not reset the
// guesses at another (RFC 3501 11.2; CVE-2026-126618 class: keeping an address from being blocked).
func TestRateLimitSuccessForgivesOnlyItsName(t *testing.T) {
	t.Parallel()
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 3, Window: time.Minute})
	ip := "203.0.113.9"
	for round := 0; round < 3; round++ {
		gate.RecordAuthFailure(ip, "bob@example.com")
		gate.RecordAuthSuccess(ip, "alice@example.com")
	}
	if gate.AllowAuth(ip, "bob@example.com") {
		t.Fatal("a success under another name reset the failures")
	}
	gate.RecordAuthSuccess(ip, " BOB@example.com")
	if !gate.AllowAuth(ip, "bob@example.com") {
		t.Fatal("a success under the same name must forgive its failures")
	}
}

// TestRateLimitIPv6Network: an IPv6 client holds a whole /64, so every address in it shares one
// counter.
func TestRateLimitIPv6Network(t *testing.T) {
	t.Parallel()
	gate := security.NewRateLimitGate(security.RateLimitConfig{MaxAttempts: 3, Window: time.Minute})
	for _, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::3"} {
		gate.RecordAuthFailure(ip, "bob")
	}
	if gate.AllowAuth("2001:db8:1:2::99", "bob") {
		t.Fatal("rotating addresses inside one /64 escaped the limit")
	}
	if !gate.AllowAuth("2001:db8:1:3::1", "bob") {
		t.Fatal("another /64 must have its own counter")
	}
}
