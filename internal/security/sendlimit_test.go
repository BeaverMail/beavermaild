package security_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/security"
)

func TestSendLimitGateBlocksAfterMaxMessages(t *testing.T) {
	t.Parallel()
	gate := security.NewSendLimitGate(security.SendLimitConfig{MaxMessages: 2, Window: time.Minute})

	if !gate.AllowSend("alice@localhost") {
		t.Fatal("expected allow before any sends")
	}
	gate.RecordSend("alice@localhost")
	gate.RecordSend("Alice@localhost") // same principal
	if gate.AllowSend("alice@localhost") {
		t.Fatal("expected block after max messages")
	}
	if !gate.AllowSend("bob@localhost") {
		t.Fatal("other principal should still be allowed")
	}
}

func TestSendLimitGateWindowReset(t *testing.T) {
	t.Parallel()
	gate := security.NewSendLimitGate(security.SendLimitConfig{MaxMessages: 1, Window: time.Minute})
	now := time.Unix(1_700_000_000, 0)
	gate.SetClockForTest(func() time.Time { return now })

	gate.RecordSend("alice@localhost")
	if gate.AllowSend("alice@localhost") {
		t.Fatal("expected block within window")
	}
	now = now.Add(time.Minute)
	if !gate.AllowSend("alice@localhost") {
		t.Fatal("expected allow after window")
	}
}

func TestWrapDomainSendGateOverride(t *testing.T) {
	t.Parallel()
	base := security.NewSendLimitGate(security.SendLimitConfig{MaxMessages: 100, Window: time.Hour})
	gate := security.WrapDomainSendGate(base, func(principal string) (int, time.Duration, bool) {
		if principal == "alice@tight.test" {
			return 1, time.Hour, true
		}
		return 0, 0, false
	})
	gate.RecordSend("alice@tight.test")
	if gate.AllowSend("alice@tight.test") {
		t.Fatal("domain override should block after 1")
	}
	if !gate.AllowSend("bob@loose.test") {
		t.Fatal("other domain should use base and allow")
	}
}
