// IMAP AUTHENTICATE PLAIN parsing (RFC 4616), shared with SMTP through internal/sasl.
package imap

import "github.com/BeaverMail/beavermaild/internal/sasl"

// decodeAuthPlain decodes a PLAIN response: base64 (RFC 3501 6.2.2) of
// [authzid] NUL authcid NUL passwd (RFC 4616 2). Anything else is malformed.
func decodeAuthPlain(line string) (authzid, user, pass string, ok bool) {
	raw, err := sasl.DecodeResponse(line)
	if err != nil {
		return "", "", "", false
	}
	authzid, user, pass, err = sasl.ParsePlain(raw)
	return authzid, user, pass, err == nil
}
