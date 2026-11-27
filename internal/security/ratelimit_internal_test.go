package security

import (
	"fmt"
	"testing"
	"time"
)

// TestRateLimitPrunesExpired: addresses that failed once and never came back are dropped, so the
// map does not grow with every address ever seen.
func TestRateLimitPrunesExpired(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	g := NewRateLimitGate(RateLimitConfig{MaxAttempts: 3, Window: time.Minute})
	g.SetClockForTest(func() time.Time { return now })
	for i := range 5000 {
		g.RecordAuthFailure(fmt.Sprintf("2001:db8:1:%x::1", i), "bob")
	}
	now = now.Add(time.Minute)
	for i := range 5000 {
		g.RecordAuthFailure(fmt.Sprintf("2001:db8:2:%x::1", i), "bob")
	}
	if n := len(g.byIP); n > 5000+minPrune {
		t.Fatalf("%d buckets kept, expired ones not dropped", n)
	}
}
