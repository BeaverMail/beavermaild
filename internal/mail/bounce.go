// Delivery failure notifications (RFC 3464 multipart/report).
package mail

import (
	"crypto/rand"
	"encoding/hex"
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
}

// BuildDSN returns an RFC 3464 multipart/report delivery status notification.
func BuildDSN(opts DSNBuildOpts) []byte {
	boundary := dsnBoundary()
	subjectAction := dsnSubjectAction(opts.Action)
	human := dsnHumanText(opts)

	var b strings.Builder
	b.WriteString("From: Mail Delivery Subsystem <mailer-daemon@localhost>\r\n")
	b.WriteString("To: ")
	b.WriteString(opts.ReturnPath)
	b.WriteString("\r\nSubject: Delivery Status Notification (")
	b.WriteString(subjectAction)
	b.WriteString(")\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Auto-Submitted: auto-replied\r\n")
	b.WriteString("Message-ID: <dsn.")
	b.WriteString(dsnMessageID())
	b.WriteString("@localhost>\r\n")
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
	b.WriteString("\r\nContent-Type: message/delivery-status\r\n\r\n")
	b.WriteString(dsnStatusPart(opts))
	b.WriteString("\r\n")

	if part := dsnReturnPart(opts); len(part) > 0 {
		b.WriteString("--")
		b.WriteString(boundary)
		b.WriteString("\r\nContent-Type: message/rfc822\r\n\r\n")
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
	default:
		if opts.QueueID != 0 {
			return fmt.Sprintf("Your message (queue id %d) could not be delivered to <%s>.\r\n%s\r\n",
				opts.QueueID, opts.FinalRcpt, opts.Diagnostic)
		}
		return fmt.Sprintf("Your message could not be delivered to <%s>.\r\n%s\r\n", opts.FinalRcpt, opts.Diagnostic)
	}
}

func dsnStatusPart(opts DSNBuildOpts) string {
	var b strings.Builder
	b.WriteString("Reporting-MTA: dns; localhost\r\n")
	if opts.Envid != "" {
		b.WriteString("Original-Envelope-Id: ")
		b.WriteString(opts.Envid)
		b.WriteString("\r\n")
	}
	if opts.Orcpt != "" {
		b.WriteString("Original-Recipient: ")
		b.WriteString(opts.Orcpt)
		b.WriteString("\r\n")
	}
	b.WriteString("Final-Recipient: rfc822; ")
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
		case DSNActionDelivered:
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

func dsnReturnPart(opts DSNBuildOpts) []byte {
	switch opts.Ret {
	case RetFull:
		return opts.OriginalRaw
	case RetHdrs:
		return extractHeaders(opts.OriginalRaw)
	default:
		return nil
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
