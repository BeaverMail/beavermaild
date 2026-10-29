package daemon

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/smtp"
)

type mockSession struct {
	action string
	delay  time.Duration
	err    error
	alive  bool
}

func (m *mockSession) ready() bool { return m.alive }

func (m *mockSession) filter(ctx context.Context, _ smtp.FilterRequest) (smtp.FilterOutcome, error) {
	if m.err != nil {
		return smtp.FilterOutcome{}, m.err
	}
	if m.delay > 0 {
		select {
		case <-ctx.Done():
			return smtp.FilterOutcome{}, errFilterTimeout
		case <-time.After(m.delay):
		}
	}
	if m.action == "" {
		return smtp.FilterOutcome{Action: smtp.FilterActionAccept}, nil
	}
	return smtp.FilterOutcome{Action: m.action}, nil
}

func newTestChain(peers []filterPeer, timeout time.Duration, failOpen bool) *Chain {
	return &Chain{log: slog.Default(), plugins: peers, timeout: timeout, failOpen: failOpen}
}

func TestChainNoPluginsAccepts(t *testing.T) {
	c := newTestChain(nil, time.Second, true)
	out, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail})
	if err != nil || out.Action != smtp.FilterActionAccept {
		t.Fatalf("got %+v %v", out, err)
	}
}

func TestChainTimeoutFailOpenSkips(t *testing.T) {
	m := &mockSession{alive: true, delay: 50 * time.Millisecond, action: smtp.FilterActionReject}
	c := newTestChain([]filterPeer{m}, 5*time.Millisecond, true)
	out, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail, TimeoutMs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != smtp.FilterActionAccept {
		t.Fatalf("fail-open want accept got %q", out.Action)
	}
}

func TestChainTimeoutFailClosedTempfail(t *testing.T) {
	m := &mockSession{alive: true, delay: 50 * time.Millisecond, action: smtp.FilterActionReject}
	c := newTestChain([]filterPeer{m}, 5*time.Millisecond, false)
	out, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail, TimeoutMs: 5})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != smtp.FilterActionTempfail {
		t.Fatalf("want tempfail got %q", out.Action)
	}
}

func TestChainFirstRejectWins(t *testing.T) {
	peers := []filterPeer{
		&mockSession{alive: true, action: smtp.FilterActionAccept},
		&mockSession{alive: true, action: smtp.FilterActionReject},
	}
	c := newTestChain(peers, time.Second, true)
	out, err := c.Filter(context.Background(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseEom})
	if err != nil || out.Action != smtp.FilterActionReject {
		t.Fatalf("got %+v %v", out, err)
	}
}
