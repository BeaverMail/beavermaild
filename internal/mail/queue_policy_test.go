package mail_test

import (
	"testing"
	"time"

	"github.com/BeaverMail/beaver/internal/mail"
)

func TestQueueRetryIntervalTable(t *testing.T) {
	t.Parallel()

	p := mail.DefaultQueuePolicy()
	now := time.Unix(0, 0)

	if due := p.NextDueAfterFailure(0, now); due != now.Add(2*time.Minute) {
		t.Fatalf("attempt 0 %v", due)
	}
	if due := p.NextDueAfterFailure(1, now); due != now.Add(5*time.Minute) {
		t.Fatalf("attempt 1 %v", due)
	}
	last := uint32(len(mail.DefaultRetryIntervals) - 1)
	if due := p.NextDueAfterFailure(last+5, now); due != now.Add(3*24*time.Hour) {
		t.Fatalf("clamped last %v", due)
	}
}

func TestQueueReadyForAttemptUsesNextDue(t *testing.T) {
	t.Parallel()

	p := mail.TestQueuePolicy()
	now := time.Now()
	next := now.Add(200 * time.Millisecond).UnixMilli()

	if !p.ReadyForAttempt(0, now) {
		t.Fatal("zero next due should run immediately")
	}
	if p.ReadyForAttempt(next, now.Add(50*time.Millisecond)) {
		t.Fatal("should wait until next due")
	}
	if !p.ReadyForAttempt(next, now.Add(250*time.Millisecond)) {
		t.Fatal("should run after next due")
	}
}
