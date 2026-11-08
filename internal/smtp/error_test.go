package smtp

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestWrapDNSPermanent(t *testing.T) {
	t.Parallel()
	err := WrapDNS(&net.DNSError{IsNotFound: true, Err: "no such host", Name: "invalid.invalid"})
	var de *DeliveryError
	if !errors.As(err, &de) || !de.Permanent {
		t.Fatalf("got %#v", err)
	}
	if !deliveryPermanent(err) {
		t.Fatal("expected permanent")
	}
}

func TestWrapDNSTemporary(t *testing.T) {
	t.Parallel()
	err := WrapDNS(fmt.Errorf("lookup timeout"))
	var de *DeliveryError
	if !errors.As(err, &de) || de.Permanent {
		t.Fatalf("got %#v", err)
	}
	if deliveryPermanent(err) {
		t.Fatal("expected transient")
	}
}

func TestShouldTryNextMX(t *testing.T) {
	t.Parallel()
	dialErr := fmt.Errorf("smtp client dial: %w", &net.OpError{Op: "dial", Err: errors.New("refused")})
	if !shouldTryNextMX(dialErr) {
		t.Fatal("dial should try next mx")
	}
	if shouldTryNextMX(&ResponseError{Code: 550, Line: "user unknown"}) {
		t.Fatal("550 should not try next mx")
	}
	if !shouldTryNextMX(&ResponseError{Code: 421, Line: "closing"}) {
		t.Fatal("421 should try next mx")
	}
	if shouldTryNextMX(&ResponseError{Code: 451, Line: "try later"}) {
		t.Fatal("451 should not try next mx")
	}
}

func TestResponseErrorDeliveryPermanent(t *testing.T) {
	t.Parallel()
	if !deliveryPermanent(&ResponseError{Code: 550, Line: "nope"}) {
		t.Fatal("550 permanent")
	}
	if deliveryPermanent(&ResponseError{Code: 451, Line: "later"}) {
		t.Fatal("451 transient")
	}
}
