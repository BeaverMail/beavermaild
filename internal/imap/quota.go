// IMAP QUOTA extension (RFC 9208): GETQUOTA and GETQUOTAROOT, resources STORAGE and MESSAGE.
package imap

import (
	"context"
	"fmt"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// cmdGetQuotaRoot returns the quotaroot for a mailbox name.
func (s *session) cmdGetQuotaRoot(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	name, ok := parseQuotaMailboxArg(arg)
	if !ok {
		return s.tagged(tag, "BAD GETQUOTAROOT syntax")
	}
	if err := mail.ValidateMailboxName(name); err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	// The mailbox need not exist: the reply names the root it would get (RFC 9208 4.1.2).
	st, err := s.inbox.QuotaStatus(ctx, s.principal.AccountID)
	if err != nil {
		return err
	}
	line := fmt.Sprintf(`QUOTAROOT %s %s`, formatListMailbox(name), formatQuotaRoot(mail.QuotaRoot))
	if err := s.untagged(line); err != nil {
		return err
	}
	if err := s.untagged(formatQuota(st)); err != nil {
		return err
	}
	return s.tagged(tag, "OK GETQUOTAROOT completed")
}

// cmdGetQuota returns STORAGE and MESSAGE usage for a quotaroot.
func (s *session) cmdGetQuota(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	root, ok := parseQuotaRootArg(arg)
	if !ok {
		return s.tagged(tag, "BAD GETQUOTA syntax")
	}
	if root != mail.QuotaRoot {
		return s.tagged(tag, "NO no such quota root")
	}
	st, err := s.inbox.QuotaStatus(ctx, s.principal.AccountID)
	if err != nil {
		return err
	}
	if err := s.untagged(formatQuota(st)); err != nil {
		return err
	}
	return s.tagged(tag, "OK GETQUOTA completed")
}

func parseQuotaMailboxArg(arg string) (name string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", false
	}
	return onlyAString(arg)
}

func parseQuotaRootArg(arg string) (root string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", false
	}
	return onlyAString(arg)
}

func formatQuotaRoot(root string) string {
	if root == "" {
		return `""`
	}
	return `"` + strings.ReplaceAll(root, `"`, `\"`) + `"`
}

// formatQuota writes one list of "resource usage limit" triplets, only for limited resources (RFC
// 9208 4.2.1: an unlisted resource is unlimited, a limit of 0 forbids any use). STORAGE is in KiB
// (5.1), rounded up so a small message does not read as 0 and a sub-KiB limit not as "forbidden".
func formatQuota(st mail.QuotaStatus) string {
	var res []string
	if st.StorageLimit > 0 {
		res = append(res, fmt.Sprintf("STORAGE %d %d", kib(st.StorageUsed), kib(st.StorageLimit)))
	}
	if st.MessagesLimit > 0 {
		res = append(res, fmt.Sprintf("MESSAGE %d %d", st.MessagesUsed, st.MessagesLimit))
	}
	return fmt.Sprintf("QUOTA %s (%s)", formatQuotaRoot(st.Root), strings.Join(res, " "))
}

func kib(bytes uint64) uint64 { return bytes/1024 + min(bytes%1024, 1) }
