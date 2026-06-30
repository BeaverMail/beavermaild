package daemon

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/smtp"
)

type mockSession struct {
	action string
	delay  time.Duration
	err    error
	alive  bool
}

func (m *mockSession) ready() bool { return m.alive }

func (m *mockSession) filter(ctx context.Context, _ smtp.FilterRequest) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return "", errFilterTimeout
		case <-time.After(m.delay):
		}
	}
	if m.action == "" {
		return smtp.FilterActionAccept, nil
	}
	return m.action, nil
}

func newTestChain(peers []filterPeer, timeout time.Duration, failOpen bool) *Chain {
	return &Chain{log: slog.Default(), plugins: peers, timeout: timeout, failOpen: failOpen}
}

func TestChainNoPluginsAccepts(t *testing.T) {
	c := newTestChain(nil, time.Second, true)
	action, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail})
	if err != nil || action != smtp.FilterActionAccept {
		t.Fatalf("got %q %v", action, err)
	}
}

func TestChainTimeoutFailOpenSkips(t *testing.T) {
	m := &mockSession{alive: true, delay: 50 * time.Millisecond, action: smtp.FilterActionReject}
	c := newTestChain([]filterPeer{m}, 5*time.Millisecond, true)
	action, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail, TimeoutMs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if action != smtp.FilterActionAccept {
		t.Fatalf("fail-open want accept got %q", action)
	}
}

func TestChainTimeoutFailClosedTempfail(t *testing.T) {
	m := &mockSession{alive: true, delay: 50 * time.Millisecond, action: smtp.FilterActionReject}
	c := newTestChain([]filterPeer{m}, 5*time.Millisecond, false)
	action, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail, TimeoutMs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if action != smtp.FilterActionTempfail {
		t.Fatalf("want tempfail got %q", action)
	}
}

func TestChainFirstRejectWins(t *testing.T) {
	peers := []filterPeer{
		&mockSession{alive: true, action: smtp.FilterActionAccept},
		&mockSession{alive: true, action: smtp.FilterActionReject},
	}
	c := newTestChain(peers, time.Second, true)
	action, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseEom})
	if err != nil || action != smtp.FilterActionReject {
		t.Fatalf("got %q %v", action, err)
	}
}
