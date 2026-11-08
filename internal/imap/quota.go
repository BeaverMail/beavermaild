// IMAP QUOTA extension (RFC 2087): GETQUOTA and GETQUOTAROOT.
package imap

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
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
	if _, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, name); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		return err
	}
	line := fmt.Sprintf(`QUOTAROOT %s %s`, formatListMailbox(name), formatQuotaRoot(mail.QuotaRoot))
	if err := s.untagged(line); err != nil {
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
	if !ok || root != mail.QuotaRoot {
		return s.tagged(tag, "BAD GETQUOTA syntax")
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
	if arg[0] == '"' {
		name, _, ok = parseQuoted(arg)
		return name, ok
	}
	return arg, true
}

func parseQuotaRootArg(arg string) (root string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", false
	}
	if arg[0] == '"' {
		root, rest, ok := parseQuoted(arg)
		return root, ok && strings.TrimSpace(rest) == ""
	}
	return arg, true
}

func formatQuotaRoot(root string) string {
	if root == "" {
		return `""`
	}
	return `"` + strings.ReplaceAll(root, `"`, `\"`) + `"`
}

func formatQuota(st mail.QuotaStatus) string {
	var parts []string
	parts = append(parts, formatQuotaRoot(st.Root))
	parts = append(parts, formatQuotaResource("STORAGE", st.StorageUsed, st.StorageLimit))
	if st.MessagesLimit > 0 || st.MessagesUsed > 0 {
		parts = append(parts, formatQuotaResource("MESSAGE", uint64(st.MessagesUsed), uint64(st.MessagesLimit)))
	}
	return "QUOTA " + strings.Join(parts, " ")
}

func formatQuotaResource(name string, used, limit uint64) string {
	if limit == 0 {
		return fmt.Sprintf("(%s %s)", name, strconv.FormatUint(used, 10))
	}
	return fmt.Sprintf("(%s %s %s)", name, strconv.FormatUint(used, 10), strconv.FormatUint(limit, 10))
}
