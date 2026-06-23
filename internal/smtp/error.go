// SMTP response errors for outbound delivery classification (RFC 5321).
package smtp

import "fmt"

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
