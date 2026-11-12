package security

import "testing"

func TestIPLimiter(t *testing.T) {
	l := NewIPLimiter(2)
	r1, ok1 := l.Acquire("192.0.2.1")
	_, ok2 := l.Acquire("192.0.2.1")
	if _, ok := l.Acquire("192.0.2.1"); !ok1 || !ok2 || ok {
		t.Fatal("third holder from one IPv4 address admitted")
	}
	if _, ok := l.Acquire("192.0.2.2"); !ok {
		t.Fatal("another address refused")
	}
	r1()
	r1() // a second release must not free another holder's slot
	if _, ok := l.Acquire("192.0.2.1"); !ok {
		t.Fatal("slot not freed")
	}
	if _, ok := l.Acquire("192.0.2.1"); ok {
		t.Fatal("double release freed two slots")
	}

	// One IPv6 /64 is one network: rotating the interface id does not get around the cap.
	l = NewIPLimiter(1)
	if _, ok := l.Acquire("2001:db8:1:2::a"); !ok {
		t.Fatal("first IPv6 holder refused")
	}
	if _, ok := l.Acquire("2001:db8:1:2::b"); ok {
		t.Fatal("same /64 admitted twice")
	}
	if _, ok := l.Acquire("2001:db8:1:3::a"); !ok {
		t.Fatal("other /64 refused")
	}
	if r, ok := NewIPLimiter(0).Acquire("192.0.2.1"); !ok || r == nil {
		t.Fatal("unlimited limiter refused")
	}
}
