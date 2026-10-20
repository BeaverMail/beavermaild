// Queue retry schedule: fixed interval table and message TTL.
package mail

import "time"

// Default retry intervals between delivery attempts.
var DefaultRetryIntervals = []time.Duration{
	2 * time.Minute,
	5 * time.Minute,
	10 * time.Minute,
	15 * time.Minute,
	30 * time.Minute,
	time.Hour,
	2 * time.Hour,
	24 * time.Hour,
	3 * 24 * time.Hour,
}

// QueuePolicy controls outbound queue scan interval, retry table, and lifetime.
type QueuePolicy struct {
	RetryIntervals   []time.Duration
	MaxLifetime      time.Duration
	RunDelay         time.Duration
	DelayNotifyAfter time.Duration // 0 = notify on first transient failure
	KeepCompleted    time.Duration // how long finished entries stay listed; 0 = delete at once
}

// DefaultQueuePolicy returns production defaults (3d message lifetime).
func DefaultQueuePolicy() QueuePolicy {
	return QueuePolicy{
		RetryIntervals:   append([]time.Duration(nil), DefaultRetryIntervals...),
		MaxLifetime:      3 * 24 * time.Hour,
		RunDelay:         time.Second,
		DelayNotifyAfter: 30 * time.Minute,
		KeepCompleted:    7 * 24 * time.Hour,
	}
}

// TestQueuePolicy returns short timings for unit tests.
func TestQueuePolicy() QueuePolicy {
	return QueuePolicy{
		RetryIntervals: []time.Duration{
			50 * time.Millisecond,
			200 * time.Millisecond,
		},
		MaxLifetime: time.Hour,
		RunDelay:    20 * time.Millisecond,
	}
}

// NextDueAfterFailure returns when to retry after attempt index failed at now.
func (p QueuePolicy) NextDueAfterFailure(attempt uint32, now time.Time) time.Time {
	intervals := p.RetryIntervals
	if len(intervals) == 0 {
		intervals = DefaultRetryIntervals
	}
	idx := attempt
	if idx >= uint32(len(intervals)) {
		idx = uint32(len(intervals)) - 1
	}
	return now.Add(intervals[idx])
}

// ReadyForAttempt reports whether nextDue (unix ms, 0 = now) is reached.
func (p QueuePolicy) ReadyForAttempt(nextDueMillis int64, now time.Time) bool {
	if nextDueMillis == 0 {
		return true
	}
	return !now.Before(time.UnixMilli(nextDueMillis))
}

// Expired reports whether the message exceeded max lifetime.
func (p QueuePolicy) Expired(created, now time.Time) bool {
	return now.Sub(created) > p.MaxLifetime
}
