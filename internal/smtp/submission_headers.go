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

	"github.com/BeaverMail/beavermaild/internal/rfc5322"

	"github.com/BeaverMail/beavermaild/internal/dnsname"
)

// msgIDRe approximates RFC 5322 §3.6.4 msg-id: "<" id-left "@" id-right ">".
// shortcut: not the full dot-atom/no-fold-literal grammar; tighten if clients send odd ids.
var msgIDRe = regexp.MustCompile(`^<[^<>@\s]+@[^<>@\s]+>$`)

// completeSubmission adds or replaces Message-ID (RFC 6409 §8.3, SHOULD) and Date (§8.2, MAY)
// when missing or malformed, so authenticated submissions leave the MSA as valid RFC 5322 mail.
// A header block that cannot be parsed is left untouched.
func completeSubmission(raw []byte, hostname string, now time.Time) []byte {
	msg, err := rfc5322.ReadMessage(bytes.NewReader(raw))
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

// singleFields may appear at most once (RFC 5322 3.6, the "Max" column); From exactly once.
var singleFields = []string{"Date", "From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Message-Id", "In-Reply-To", "References", "Subject"}

// addressFields are the RFC 5322 3.6.2-3.6.3 originator and destination fields.
var addressFields = []string{"From", "Sender", "Reply-To", "To", "Cc", "Bcc"}

// readSingleFields parses the header section and checks the RFC 5322 3.6 counts: From exactly once,
// the other singleFields at most once.
func readSingleFields(raw []byte) (*netmail.Message, string) {
	msg, err := rfc5322.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, "header section cannot be parsed"
	}
	for _, name := range singleFields {
		if n := len(msg.Header[name]); n > 1 {
			return nil, fmt.Sprintf("%d %s fields, at most one allowed", n, name)
		}
	}
	if len(msg.Header["From"]) == 0 {
		return nil, "missing From field"
	}
	return msg, ""
}

// checkInboundHeaders returns why a message arriving on port 25 is refused, or "" when it is accepted.
// A From that is missing, repeated, unreadable or not exactly one mailbox has no DMARC identity
// (RFC 9989 4.4), and each MUA reads it its own way: the domain shown can be one no check ever saw
// (RFC 9989 11.5). A repeated single field (Subject, Date...) lets a signed message show an unsigned
// value (RFC 6376 8.15).
func checkInboundHeaders(raw []byte) string {
	msg, why := readSingleFields(raw)
	if why != "" {
		return why
	}
	list, err := msg.Header.AddressList("From")
	if err != nil {
		return "invalid address in From"
	}
	if len(list) != 1 {
		return "From must hold exactly one mailbox"
	}
	return ""
}

// checkSubmissionHeaders returns why a submitted message cannot leave the MSA, or "" when it can.
// RFC 6409 8: what the MSA forwards MUST conform to RFC 5322; 4.2: since the MSA alters the message
// (Message-ID, Date, DKIM), domains in address fields MUST be fully qualified; 5.1: illegal address
// syntax in them SHOULD be rejected. hosted reports our own domains, accepted as they are.
func checkSubmissionHeaders(raw []byte, hosted func(domain string) bool) string {
	msg, why := readSingleFields(raw)
	if why != "" {
		return why
	}
	for _, name := range addressFields {
		if len(msg.Header[name]) == 0 {
			continue
		}
		list, err := msg.Header.AddressList(name)
		if err != nil && !(name == "Bcc" && strings.TrimSpace(msg.Header.Get(name)) == "") {
			return "invalid address in " + name
		}
		for _, a := range list {
			at := strings.LastIndexByte(a.Address, '@')
			d := dnsname.ToASCII(a.Address[at+1:])
			if strings.HasPrefix(d, "[") || hosted(d) {
				continue
			}
			if !validDomain(d) || !strings.Contains(d, ".") {
				return "domain not fully qualified in " + name
			}
		}
		switch {
		case name == "From" && len(list) == 0:
			return "no mailbox in From"
		case name == "From" && len(list) > 1 && len(msg.Header["Sender"]) == 0:
			return "From with several mailboxes needs a Sender field" // RFC 5322 3.6.2
		case name == "Sender" && len(list) != 1:
			return "Sender must hold one mailbox"
		}
	}
	return ""
}
