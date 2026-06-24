// DSN envelope metadata and NOTIFY decision logic (RFC 3461).
package mail

import (
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// NotifyFlags is the NOTIFY= bitmask requested on RCPT TO.
type NotifyFlags uint8

const (
	NotifyFailure  NotifyFlags = 1 << 0
	NotifyDelay    NotifyFlags = 1 << 1
	NotifySuccess  NotifyFlags = 1 << 2
	NotifyNever    NotifyFlags = 1 << 3
	NotifyDefault  NotifyFlags = NotifyFailure | NotifyDelay
	notifyStorageNever uint8 = 255
	rcptDelayNotifiedFlag uint64 = 1 << 2
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
	Ret        RetMode
	Envid      string
	Recipients []RcptDSN
}

// DSNAction classifies the delivery event for a status notification.
type DSNAction string

const (
	DSNActionFailed    DSNAction = "failed"
	DSNActionDelayed   DSNAction = "delayed"
	DSNActionDelivered DSNAction = "delivered"
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

// NotifyWanted reports whether the recipient requested this DSN action.
func NotifyWanted(n NotifyFlags, action DSNAction) bool {
	if n&NotifyNever != 0 {
		return false
	}
	switch action {
	case DSNActionFailed:
		return n&NotifyFailure != 0
	case DSNActionDelayed:
		return n&NotifyDelay != 0
	case DSNActionDelivered:
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
