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
