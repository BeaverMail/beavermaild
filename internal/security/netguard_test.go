package security

import (
	"errors"
	"testing"
)

func TestRejectInternalDial(t *testing.T) {
	t.Parallel()
	for _, a := range []string{"127.0.0.1:25", "10.1.2.3:25", "172.16.0.1:25", "192.168.1.1:443", "169.254.1.1:25",
		"100.64.0.1:25", "100.127.255.254:443", "[::1]:25", "[fd00::1]:25", "[fe80::1]:25", "0.0.0.0:25", "[::ffff:127.0.0.1]:25", "224.0.0.1:25"} {
		if err := RejectInternalDial("tcp", a, nil); !errors.Is(err, ErrPrivateAddr) {
			t.Errorf("%s allowed", a)
		}
	}
	for _, a := range []string{"192.0.2.10:25", "100.128.0.1:25", "[2001:db8::1]:25"} {
		if err := RejectInternalDial("tcp", a, nil); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
}
