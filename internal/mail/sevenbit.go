package mail

import "errors"

// ErrNeeds7Bit is returned by the SMTP client, before MAIL, when the next hop does not offer
// 8BITMIME and the message holds octets outside US-ASCII: RFC 6152 3 forbids sending them. Like
// Exim, the message is not converted: the delivery fails for good with status 5.6.3.
var ErrNeeds7Bit = errors.New("mail: next hop accepts 7-bit content only, message has 8-bit octets")

// Has8Bit reports whether b holds any octet outside US-ASCII.
func Has8Bit(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return true
		}
	}
	return false
}
