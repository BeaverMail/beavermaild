package security_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/security"
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
