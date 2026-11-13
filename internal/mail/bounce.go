// Delivery failure notifications (RFC 3464 multipart/report).
package mail

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// DSNBuildOpts configures one delivery status notification message.
type DSNBuildOpts struct {
	ReturnPath  string
	FinalRcpt   string
	Orcpt       string
	Envid       string
	Ret         RetMode
	Action      DSNAction
	Status      string
	Diagnostic  string
	QueueID     uint32
	OriginalRaw []byte
	Hostname    string // Reporting-MTA and From; "localhost" when unset
}

// dsnText makes a value safe for one line of the notification: CR, LF and other control
// characters become spaces. The diagnostic is the remote server's reply and the addresses and
// ENVID/ORCPT come from clients; a line break in any of them would add fields to the report
// (a forged Final-Recipient, Action or header of the notification itself).
func dsnText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// BuildDSN returns an RFC 3464 multipart/report delivery status notification.
func BuildDSN(opts DSNBuildOpts) []byte {
	opts.ReturnPath, opts.FinalRcpt = dsnText(opts.ReturnPath), dsnText(opts.FinalRcpt)
	opts.Orcpt, opts.Envid = dsnText(opts.Orcpt), dsnText(opts.Envid)
	opts.Status, opts.Diagnostic = dsnText(opts.Status), dsnText(opts.Diagnostic)
	// RFC 6533: the notification of an internationalized message (UTF-8 addresses or header
	// fields) uses the message/global* types.
	global := !printableASCII(opts.ReturnPath) || !printableASCII(opts.FinalRcpt) ||
		!printableASCII(OrcptText(opts.Orcpt, true)) || Has8BitHeaders(opts.OriginalRaw)
	boundary := dsnBoundary()
	subjectAction := dsnSubjectAction(opts.Action)
	human := dsnHumanText(opts)

	var b strings.Builder
	host := dsnText(opts.Hostname)
	if host == "" {
		host = "localhost"
	}
	// RFC 3464 2.1: From is someone responsible for the mail system, reachable for replies.
	b.WriteString("From: Mail Delivery System <MAILER-DAEMON@" + host + ">\r\n")
	b.WriteString("To: ")
	b.WriteString(opts.ReturnPath)
	b.WriteString("\r\nSubject: Delivery Status Notification (")
	b.WriteString(subjectAction)
	b.WriteString(")\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Auto-Submitted: auto-replied\r\n")
	b.WriteString("Message-ID: <dsn.")
	b.WriteString(dsnMessageID())
	b.WriteString("@" + host + ">\r\n")
	b.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=\"")
	b.WriteString(boundary)
	b.WriteString("\"\r\n\r\n")

	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(human)
	if !strings.HasSuffix(human, "\r\n") {
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")

	b.WriteString("--")
	b.WriteString(boundary)
	status := dsnStatusPart(opts, host, global)
	switch {
	case global && Has8Bit([]byte(status)):
		b.WriteString("\r\nContent-Type: message/global-delivery-status\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	case global:
		b.WriteString("\r\nContent-Type: message/global-delivery-status\r\n\r\n")
	default:
		b.WriteString("\r\nContent-Type: message/delivery-status\r\n\r\n")
	}
	b.WriteString(status)
	b.WriteString("\r\n")

	if part, headersOnly := dsnReturnPart(opts); len(part) > 0 {
		b.WriteString("--")
		b.WriteString(boundary)
		if global {
			// RFC 6533 4.2, 4.3. base64 (4.5): the return path's next hop may lack SMTPUTF8.
			typ := "message/global"
			if headersOnly {
				typ = "message/global-headers"
			}
			b.WriteString("\r\nContent-Type: " + typ + "\r\nContent-Transfer-Encoding: base64\r\n\r\n")
			part = base64Lines(CRLF(part))
		} else if headersOnly {
			b.WriteString("\r\nContent-Type: text/rfc822-headers\r\n\r\n") // RFC 6522 4
		} else {
			b.WriteString("\r\nContent-Type: message/rfc822\r\n\r\n")
		}
		b.Write(part)
		if !bytesHasSuffixCRLF(part) {
			b.WriteString("\r\n")
		}
		b.WriteString("\r\n")
	}

	b.WriteString("--")
	b.WriteString(boundary)
	b.WriteString("--\r\n")
	return []byte(b.String())
}

// BuildExpireBounce returns a failure DSN for an expired queue entry.
func BuildExpireBounce(returnPath, failedRcpt string, queueID uint32) []byte {
	return BuildDSN(DSNBuildOpts{
		ReturnPath: returnPath,
		FinalRcpt:  failedRcpt,
		Action:     DSNActionFailed,
		Status:     "5.4.7",
		Diagnostic: "delivery time expired",
		QueueID:    queueID,
	})
}

func dsnSubjectAction(action DSNAction) string {
	switch action {
	case DSNActionDelivered:
		return "Success"
	case DSNActionDelayed:
		return "Delay"
	case DSNActionRelayed:
		return "Relayed"
	default:
		return "Failure"
	}
}

func dsnHumanText(opts DSNBuildOpts) string {
	switch opts.Action {
	case DSNActionDelivered:
		return fmt.Sprintf("Your message was successfully delivered to <%s>.\r\n", opts.FinalRcpt)
	case DSNActionDelayed:
		return fmt.Sprintf("Delivery to <%s> has been delayed.\r\n%s\r\n", opts.FinalRcpt, opts.Diagnostic)
	case DSNActionRelayed:
		return fmt.Sprintf("Your message was relayed to <%s>; the next server sends no delivery notifications.\r\n", opts.FinalRcpt)
	default:
		if opts.QueueID != 0 {
			return fmt.Sprintf("Your message (queue id %d) could not be delivered to <%s>.\r\n%s\r\n",
				opts.QueueID, opts.FinalRcpt, opts.Diagnostic)
		}
		return fmt.Sprintf("Your message could not be delivered to <%s>.\r\n%s\r\n", opts.FinalRcpt, opts.Diagnostic)
	}
}

func dsnStatusPart(opts DSNBuildOpts, host string, global bool) string {
	var b strings.Builder
	// RFC 3461 6.3 (b): "dns" with the fully-qualified name, another type when it is not one.
	if strings.Contains(host, ".") {
		b.WriteString("Reporting-MTA: dns; " + host + "\r\n")
	} else {
		b.WriteString("Reporting-MTA: x-local-hostname; " + host + "\r\n")
	}
	// ENVID and ORCPT arrive as xtext and appear decoded (RFC 3461 6.3 (a), (d)); dsnText already
	// kept any line break out, and the SMTP server refuses values that decode to one.
	if opts.Envid != "" {
		b.WriteString("Original-Envelope-Id: ")
		b.WriteString(dsnText(EnvidText(opts.Envid)))
		b.WriteString("\r\n")
	}
	if opts.Orcpt != "" {
		b.WriteString("Original-Recipient: ")
		b.WriteString(dsnText(OrcptText(opts.Orcpt, global)))
		b.WriteString("\r\n")
	}
	if printableASCII(opts.FinalRcpt) {
		b.WriteString("Final-Recipient: rfc822; ")
	} else {
		b.WriteString("Final-Recipient: utf-8; ") // RFC 6533 3: utf-8-address form in a global status
	}
	b.WriteString(opts.FinalRcpt)
	b.WriteString("\r\n")
	b.WriteString("Action: ")
	b.WriteString(string(opts.Action))
	b.WriteString("\r\n")
	b.WriteString("Status: ")
	if opts.Status != "" {
		b.WriteString(opts.Status)
	} else {
		switch opts.Action {
		case DSNActionDelivered, DSNActionRelayed:
			b.WriteString("2.0.0")
		case DSNActionDelayed:
			b.WriteString("4.0.0")
		default:
			b.WriteString("5.0.0")
		}
	}
	b.WriteString("\r\n")
	if opts.Diagnostic != "" {
		b.WriteString("Diagnostic-Code: smtp; ")
		b.WriteString(opts.Diagnostic)
		b.WriteString("\r\n")
	}
	return b.String()
}

// dsnReturnPart is the copy of the message the notification carries, and whether it is only the
// header. RET=FULL returns the whole message only with a failure: other notifications SHOULD
// carry only the header (RFC 3461 6.2).
func dsnReturnPart(opts DSNBuildOpts) ([]byte, bool) {
	switch {
	case opts.Ret == RetFull && opts.Action == DSNActionFailed:
		return opts.OriginalRaw, false
	case opts.Ret == RetFull, opts.Ret == RetHdrs:
		return extractHeaders(opts.OriginalRaw), true
	default:
		return nil, false
	}
}

func extractHeaders(raw []byte) []byte {
	if len(raw) == 0 {
		return nil
	}
	end := bytesIndexHeadersEnd(raw)
	if end < 0 {
		return raw
	}
	return raw[:end]
}

func bytesIndexHeadersEnd(raw []byte) int {
	// Blank line separates headers from body (CRLF CRLF or LF LF).
	if idx := strings.Index(string(raw), "\r\n\r\n"); idx >= 0 {
		return idx + 4
	}
	if idx := strings.Index(string(raw), "\n\n"); idx >= 0 {
		return idx + 2
	}
	return -1
}

func bytesHasSuffixCRLF(b []byte) bool {
	return len(b) >= 2 && b[len(b)-2] == '\r' && b[len(b)-1] == '\n'
}

func dsnBoundary() string {
	var buf [12]byte
	_, _ = rand.Read(buf[:])
	return "beaver-dsn-" + hex.EncodeToString(buf[:])
}

func dsnMessageID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}

// SMTPStatusFromError maps a delivery error to an enhanced status code string.
func SMTPStatusFromError(err error) string {
	if errors.Is(err, ErrNeeds7Bit) {
		return "5.6.3" // conversion required and not possible (RFC 3463)
	}
	if errors.Is(err, ErrNeedsSMTPUTF8) {
		return "5.6.7" // non-ASCII addresses not permitted (RFC 6531 4.2)
	}
	// The precise code when the error carries one: a remote reply's enhanced code (550 5.1.1), or
	// 5.1.10 for a null MX (RFC 7505). RFC 3464 2.3.4: Status is the RFC 3463 code of the outcome.
	var enhanced interface{ EnhancedStatus() string }
	if errors.As(err, &enhanced) {
		if s := enhanced.EnhancedStatus(); s != "" {
			return s
		}
	}
	type coded interface {
		error
		Permanent() bool
		Temporary() bool
	}
	if c, ok := err.(coded); ok {
		if c.Permanent() {
			return "5.0.0"
		}
		if c.Temporary() {
			return "4.0.0"
		}
	}
	return "5.0.0"
}

// base64Lines is b in base64, in lines of 76 characters (RFC 2045 6.8).
func base64Lines(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	for len(enc) > 76 {
		out.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	out.WriteString(enc + "\r\n")
	return []byte(out.String())
}
