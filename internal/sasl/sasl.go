// Package sasl decodes the SASL exchanges shared by IMAP AUTHENTICATE and SMTP AUTH: BASE64
// responses (RFC 4954 4, RFC 3501 6.2.2) and the PLAIN message (RFC 4616).
package sasl

import (
	"encoding/base64"
	"errors"
	"strings"
)

// ErrBadBase64 is a response that is not BASE64: a character outside the alphabet or a pad
// character before the end. RFC 4954 4 says to reject it (501), never to read it as text.
var ErrBadBase64 = errors.New("sasl: response is not base64")

// ErrBadPlain is a PLAIN message without exactly three fields or with an empty authcid.
var ErrBadPlain = errors.New("sasl: malformed PLAIN message")

// Cancel is the client response that aborts an exchange (RFC 4954 4, RFC 3501 6.2.2).
const Cancel = "*"

// DecodeResponse decodes one client response line. "=" is an empty response (RFC 4954 4).
func DecodeResponse(line string) ([]byte, error) {
	line = strings.TrimSpace(line)
	if line == "=" {
		return []byte{}, nil
	}
	// StdEncoding refuses characters outside the alphabet and padding before the end; CR and LF
	// cannot occur inside one line.
	raw, err := base64.StdEncoding.Strict().DecodeString(line)
	if err != nil || line == "" {
		return nil, ErrBadBase64
	}
	return raw, nil
}

// ParsePlain splits a PLAIN message: [authzid] NUL authcid NUL passwd (RFC 4616 2).
func ParsePlain(raw []byte) (authzid, user, pass string, err error) {
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 || parts[1] == "" {
		return "", "", "", ErrBadPlain
	}
	return parts[0], parts[1], parts[2], nil
}

// AuthorizedAs reports whether the PLAIN authorization identity is acceptable for user: empty,
// or the user itself. Acting as someone else needs an authorization rule this server has none of
// (RFC 4616 2).
func AuthorizedAs(authzid, user string) bool {
	return authzid == "" || strings.EqualFold(authzid, user)
}
