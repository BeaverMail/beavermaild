// SMTP response and delivery error classification (RFC 5321).
package smtp

import (
	"errors"
	"fmt"
	"net"
)

// ResponseError is an SMTP reply code from the peer.
type ResponseError struct {
	Code int
	Line string
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("smtp: %d %s", e.Code, e.Line)
}

// Temporary reports a 4xx reply (retry later).
func (e *ResponseError) Temporary() bool {
	return e.Code >= 400 && e.Code < 500
}

// Permanent reports a 5xx reply (do not retry this recipient).
func (e *ResponseError) Permanent() bool {
	return e.Code >= 500 && e.Code < 600
}

// DeliveryPermanent implements mail permanent delivery error classification.
func (e *ResponseError) DeliveryPermanent() bool {
	return e.Permanent()
}

// DeliveryError wraps an error with permanent vs transient delivery semantics.
type DeliveryError struct {
	Err       error
	Permanent bool
}

func (e *DeliveryError) Error() string { return e.Err.Error() }
func (e *DeliveryError) Unwrap() error { return e.Err }

// DeliveryPermanent reports whether the worker should stop retrying the recipient.
func (e *DeliveryError) DeliveryPermanent() bool { return e.Permanent }

// WrapDNS wraps a DNS lookup error with delivery permanent/transient semantics.
func WrapDNS(err error) error {
	if err == nil {
		return nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return &DeliveryError{Err: err, Permanent: true}
	}
	return &DeliveryError{Err: err, Permanent: false}
}

// deliveryPermanent reports whether err is a final delivery failure for one recipient.
func deliveryPermanent(err error) bool {
	type permanent interface {
		error
		DeliveryPermanent() bool
	}
	var p permanent
	if errors.As(err, &p) {
		return p.DeliveryPermanent()
	}
	return false
}

// shouldTryNextMX reports whether DeliverRemote should attempt the next MX host.
func shouldTryNextMX(err error) bool {
	if isDialError(err) {
		return true
	}
	var re *ResponseError
	if errors.As(err, &re) && re.Code == 421 {
		return true
	}
	return false
}

func isDialError(err error) bool {
	for err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return true
		}
		err = errors.Unwrap(err)
	}
	return false
}
