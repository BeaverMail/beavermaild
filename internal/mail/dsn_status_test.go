package mail

import (
	"errors"
	"testing"
)

type enhancedErr string

func (e enhancedErr) Error() string          { return "remote: " + string(e) }
func (e enhancedErr) EnhancedStatus() string { return string(e) }

// RFC 3464 2.3.4, RFC 7505 6: the DSN Status is the precise RFC 3463 code of the outcome, with the
// class of the action (4 delayed, 5 failed). Before: every permanent error became 5.0.0.
func TestDSNStatusFromEnhancedCode(t *testing.T) {
	t.Parallel()
	wrapped := func(s string) error { return errors.Join(errors.New("deliver"), enhancedErr(s)) }
	for _, tc := range []struct {
		action DSNAction
		err    error
		want   string
	}{
		{DSNActionFailed, wrapped("5.1.10"), "5.1.10"}, // null MX
		{DSNActionFailed, wrapped("5.1.1"), "5.1.1"},   // remote 550 5.1.1
		{DSNActionFailed, wrapped("4.2.2"), "5.2.2"},   // 4xx until expiry: a failure
		{DSNActionDelayed, wrapped("4.2.2"), "4.2.2"},
		{DSNActionFailed, wrapped(""), "5.0.0"},
		{DSNActionFailed, errors.New("no code"), "5.0.0"},
		{DSNActionFailed, ErrNeedsSMTPUTF8, "5.6.7"},
	} {
		if got := dsnStatusFor(tc.action, tc.err); got != tc.want {
			t.Errorf("%s %v: %q, want %q", tc.action, tc.err, got, tc.want)
		}
	}
}
