// RFC 6409 §8 message modifications done by the submission server (MSA).
package smtp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	netmail "net/mail"
	"regexp"
	"strings"
	"time"
)

// msgIDRe approximates RFC 5322 §3.6.4 msg-id: "<" id-left "@" id-right ">".
// shortcut: not the full dot-atom/no-fold-literal grammar; tighten if clients send odd ids.
var msgIDRe = regexp.MustCompile(`^<[^<>@\s]+@[^<>@\s]+>$`)

// completeSubmission adds or replaces Message-ID (RFC 6409 §8.3, SHOULD) and Date (§8.2, MAY)
// when missing or malformed, so authenticated submissions leave the MSA as valid RFC 5322 mail.
// A header block that cannot be parsed is left untouched.
func completeSubmission(raw []byte, hostname string, now time.Time) []byte {
	msg, err := netmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return raw
	}
	if !msgIDRe.MatchString(strings.TrimSpace(msg.Header.Get("Message-ID"))) {
		raw = prependHeader(stripHeaderFields(raw, "Message-ID", nil), "Message-ID", newMessageID(hostname, now))
	}
	if _, err := netmail.ParseDate(msg.Header.Get("Date")); err != nil {
		raw = prependHeader(stripHeaderFields(raw, "Date", nil), "Date", now.Format(time.RFC1123Z))
	}
	return raw
}

func newMessageID(hostname string, now time.Time) string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("<%d.%s@%s>", now.UnixNano(), hex.EncodeToString(b[:]), hostname)
}
