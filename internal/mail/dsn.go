// DSN envelope metadata and NOTIFY decision logic (RFC 3461).
package mail

import (
	"strings"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// NotifyFlags is the NOTIFY= bitmask requested on RCPT TO.
type NotifyFlags uint8

const (
	NotifyFailure         NotifyFlags = 1 << 0
	NotifyDelay           NotifyFlags = 1 << 1
	NotifySuccess         NotifyFlags = 1 << 2
	NotifyNever           NotifyFlags = 1 << 3
	NotifyDefault         NotifyFlags = NotifyFailure | NotifyDelay
	notifyStorageNever    uint8       = 255
	rcptDelayNotifiedFlag uint64      = 1 << 2
)

// RetMode is MAIL FROM RET= (RFC 3461).
type RetMode string

const (
	RetNone RetMode = ""
	RetFull RetMode = "FULL"
	RetHdrs RetMode = "HDRS"
)

// RcptDSN holds per-recipient DSN parameters from RCPT TO.
type RcptDSN struct {
	Address string
	Notify  NotifyFlags
	Orcpt   string
}

// EnvelopeDSN holds MAIL FROM DSN parameters and per-recipient NOTIFY/ORCPT.
type EnvelopeDSN struct {
	ReturnPath string
	SignAs     string // authenticated sender, DKIM identity for a null ReturnPath
	Ret        RetMode
	Envid      string
	Body       string // 7BIT or 8BITMIME from MAIL FROM BODY=
	Recipients []RcptDSN
}

// DSNAction classifies the delivery event for a status notification.
type DSNAction string

const (
	DSNActionFailed    DSNAction = "failed"
	DSNActionDelayed   DSNAction = "delayed"
	DSNActionDelivered DSNAction = "delivered"
	DSNActionRelayed   DSNAction = "relayed" // passed to a server that does not issue DSNs (RFC 3461 5.2.2)
)

// ParseNotify parses NOTIFY= values (FAILURE, DELAY, SUCCESS, NEVER).
func ParseNotify(s string) (NotifyFlags, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return NotifyDefault, true
	}
	upper := strings.ToUpper(s)
	if upper == "NEVER" {
		return NotifyNever, true
	}
	var flags NotifyFlags
	for _, part := range strings.Split(upper, ",") {
		switch strings.TrimSpace(part) {
		case "FAILURE":
			flags |= NotifyFailure
		case "DELAY":
			flags |= NotifyDelay
		case "SUCCESS":
			flags |= NotifySuccess
		default:
			return 0, false
		}
	}
	if flags == 0 {
		return 0, false
	}
	return flags, true
}

// ParseRet parses MAIL FROM RET= (FULL or HDRS).
func ParseRet(s string) (RetMode, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "":
		return RetNone, true
	case "FULL":
		return RetFull, true
	case "HDRS":
		return RetHdrs, true
	default:
		return "", false
	}
}

// RelayDSN carries a recipient's DSN parameters to the SMTP client relaying it (RFC 3461 5.2.1):
// values as received (xtext for ENVID and ORCPT), Notify in its stored form where 0 means "no
// NOTIFY was given". The client sets Passed when the next server offered DSN and took them, so the
// notifications are its job from there on.
type RelayDSN struct {
	Ret    RetMode
	Envid  string
	Notify uint8
	Orcpt  string
	Passed bool
}

// NotifyKeyword is the NOTIFY value for a stored notify mask ("" when none was given).
func NotifyKeyword(stored uint8) string {
	if stored == 0 {
		return ""
	}
	n := NotifyFlagsFromStorage(stored)
	if n&NotifyNever != 0 {
		return "NEVER"
	}
	var kw []string
	for _, f := range []struct {
		bit  NotifyFlags
		name string
	}{{NotifySuccess, "SUCCESS"}, {NotifyFailure, "FAILURE"}, {NotifyDelay, "DELAY"}} {
		if n&f.bit != 0 {
			kw = append(kw, f.name)
		}
	}
	return strings.Join(kw, ",")
}

// NotifyWanted reports whether the recipient requested this DSN action. A recipient without
// NOTIFY (0) gets the default, FAILURE and DELAY (RFC 3461 4.1).
func NotifyWanted(n NotifyFlags, action DSNAction) bool {
	if n == 0 {
		n = NotifyDefault
	}
	if n&NotifyNever != 0 {
		return false
	}
	switch action {
	case DSNActionFailed:
		return n&NotifyFailure != 0
	case DSNActionDelayed:
		return n&NotifyDelay != 0
	case DSNActionDelivered, DSNActionRelayed:
		return n&NotifySuccess != 0
	default:
		return false
	}
}

// ShouldSendDSN applies RFC rules and backscatter guards before generating a DSN.
func ShouldSendDSN(returnPath string, notify NotifyFlags, action DSNAction, localReturnPath bool, remoteAvailable bool) bool {
	if strings.TrimSpace(returnPath) == "" {
		return false
	}
	if !NotifyWanted(notify, action) {
		return false
	}
	if !localReturnPath && !remoteAvailable {
		return false
	}
	return true
}

// NotifyToStorage encodes NotifyFlags for queue persistence.
func NotifyToStorage(n NotifyFlags) uint8 {
	if n&NotifyNever != 0 {
		return notifyStorageNever
	}
	if n == 0 {
		return 0
	}
	return uint8(n &^ NotifyNever)
}

// NotifyFlagsFromStorage decodes persisted notify bitmask.
func NotifyFlagsFromStorage(n uint8) NotifyFlags {
	if n == notifyStorageNever {
		return NotifyNever
	}
	if n == 0 {
		return NotifyDefault
	}
	return NotifyFlags(n)
}

// MarkDelayNotified sets the per-recipient flag after a DELAY DSN was sent.
func MarkDelayNotified(msg *storage.QueueMessage, i int) {
	msg.Recipients[i].Flags |= rcptDelayNotifiedFlag
}

// DelayNotified reports whether a DELAY DSN was already sent for this recipient.
func DelayNotified(rcpt storage.QueueRecipient) bool {
	return rcpt.Flags&rcptDelayNotifiedFlag != 0
}

// DecodeXtext decodes an xtext (RFC 3461 4): characters "!" to "~" except "+" and "=" stand for
// themselves, "+" and two upper-case hex digits for any octet. ok is false for anything else.
func DecodeXtext(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '+':
			if i+2 >= len(s) || !isUpperHex(s[i+1]) || !isUpperHex(s[i+2]) {
				return "", false
			}
			b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
			i += 2
		case c < '!' || c > '~' || c == '=':
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

func isUpperHex(c byte) bool { return '0' <= c && c <= '9' || 'A' <= c && c <= 'F' }

func unhex(c byte) byte {
	if c <= '9' {
		return c - '0'
	}
	return c - 'A' + 10
}

// printableASCII reports whether s is printable US-ASCII (graphic and space), what ENVID and
// ORCPT must decode to (RFC 3461 4.2, 4.4): nothing that could break a notification line.
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}
	return true
}

// ValidEnvid reports whether v is a valid ENVID value: xtext of at most 100 printable characters
// once decoded (RFC 3461 4.4).
func ValidEnvid(v string) bool {
	d, ok := DecodeXtext(v)
	return ok && len(d) <= 100 && printableASCII(d)
}

// ValidOrcpt reports whether v is a valid ORCPT value: addr-type ";" xtext, at most 500
// characters with "ORCPT=", decoding to printable text (RFC 3461 4.2).
func ValidOrcpt(v string) bool {
	typ, addr, ok := strings.Cut(v, ";")
	if !ok || typ == "" || len("ORCPT=")+len(v) > 500 {
		return false
	}
	for i := 0; i < len(typ); i++ {
		if c := typ[i]; !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	d, ok := DecodeXtext(addr)
	return ok && printableASCII(d)
}

// OrcptText is the Original-Recipient field value for an ORCPT parameter: its addr-type and the
// decoded address (RFC 3461 6.3 (d)).
func OrcptText(v string) string {
	typ, addr, _ := strings.Cut(v, ";")
	d, ok := DecodeXtext(addr)
	if !ok {
		d = addr
	}
	return typ + ";" + d
}

// EnvidText is the Original-Envelope-Id field value: the ENVID decoded from xtext (RFC 3461 6.3 (a)).
func EnvidText(v string) string {
	if d, ok := DecodeXtext(v); ok {
		return d
	}
	return v
}
