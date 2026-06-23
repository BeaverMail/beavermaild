// Minimal delivery failure notifications (DSN-style plain text).
package mail

import (
	"fmt"
	"strings"
)

// BuildExpireBounce returns a simple failure notice for an expired queue entry.
func BuildExpireBounce(returnPath, failedRcpt string, queueID uint32) []byte {
	returnPath = strings.TrimSpace(returnPath)
	var b strings.Builder
	b.WriteString("From: mailer-daemon@localhost\r\n")
	b.WriteString("To: ")
	b.WriteString(returnPath)
	b.WriteString("\r\nSubject: Delivery Status Notification (Failure)\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(fmt.Sprintf("Your message (queue id %d) could not be delivered to <%s> within the allowed time.\r\n", queueID, failedRcpt))
	return []byte(b.String())
}
