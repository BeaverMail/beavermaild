// IMAP APPEND command parsing and handling.
package imap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
)

func (s *session) cmdAppend(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	mboxName, flags, internalDate, size, nonsync, ok := parseAppendArg(arg)
	if !ok || size <= 0 || size > mail.MaxAppendBytes {
		return s.tagged(tag, "BAD APPEND syntax")
	}
	if err := mail.ValidateMailboxName(mboxName); err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	if !nonsync {
		if err := s.continuation(); err != nil {
			return err
		}
	}
	raw, err := s.readLiteral(size)
	if err != nil {
		return err
	}

	mbox, err := s.resolveOrCreateMailbox(ctx, mboxName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		return err
	}

	uid, err := s.inbox.Append(ctx, s.principal.AccountID, mbox.ID, raw, flags, internalDate)
	if err != nil {
		return err
	}

	if s.selected && s.mbox.ID == mbox.ID {
		meta, err := s.inbox.GetMeta(ctx, s.principal.AccountID, uid)
		if err != nil {
			return err
		}
		s.messages = append(s.messages, mail.Message{UID: uid, Meta: meta})
		if err := s.untagged(fmt.Sprintf("%d EXISTS", len(s.messages))); err != nil {
			return err
		}
	}

	return s.tagged(tag, fmt.Sprintf("OK [%s] APPEND completed", formatAppendUID(mbox.UIDValidity, uid)))
}

func (s *session) readLiteral(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func parseAppendArg(arg string) (mailbox string, flags uint32, internalDate int64, size int, nonsync bool, ok bool) {
	arg = strings.TrimSpace(arg)
	litStart := strings.LastIndexByte(arg, '{')
	if litStart < 0 || len(arg) == 0 || arg[len(arg)-1] != '}' {
		return "", 0, 0, 0, false, false
	}
	lit := strings.TrimSpace(arg[litStart+1 : len(arg)-1])
	if strings.HasSuffix(lit, "+") {
		nonsync = true
		lit = strings.TrimSuffix(lit, "+")
	}
	size, err := strconv.Atoi(strings.TrimSpace(lit))
	if err != nil {
		return "", 0, 0, 0, false, false
	}

	rest := strings.TrimSpace(arg[:litStart])
	if rest == "" {
		return "", 0, 0, 0, false, false
	}
	mboxName, rest, ok := parseAppendMailboxToken(rest)
	if !ok {
		return "", 0, 0, 0, false, false
	}
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") {
		close := strings.IndexByte(rest, ')')
		if close < 0 {
			return "", 0, 0, 0, false, false
		}
		flags = parseAppendFlags(rest[:close+1])
		rest = strings.TrimSpace(rest[close+1:])
	}
	if strings.HasPrefix(rest, "\"") {
		dateStr, tail, ok := parseQuoted(rest)
		if !ok {
			return "", 0, 0, 0, false, false
		}
		t, ok := parseIMAPInternalDate(dateStr)
		if !ok {
			return "", 0, 0, 0, false, false
		}
		internalDate = t.Unix()
		rest = strings.TrimSpace(tail)
	}
	if rest != "" {
		return "", 0, 0, 0, false, false
	}
	return mboxName, flags, internalDate, size, nonsync, true
}

// parseIMAPInternalDate parses an APPEND date-time / INTERNALDATE string.
func parseIMAPInternalDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("02-Jan-2006 15:04:05 -0700", s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func parseAppendMailboxToken(rest string) (name string, tail string, ok bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", false
	}
	if rest[0] == '"' {
		name, tail, ok = parseQuoted(rest)
		return name, tail, ok
	}
	i := strings.IndexByte(rest, ' ')
	if i < 0 {
		return rest, "", true
	}
	return rest[:i], rest[i+1:], true
}

func parseAppendFlags(s string) uint32 {
	s = strings.TrimSpace(s)
	if len(s) < 2 || s[0] != '(' || s[len(s)-1] != ')' {
		return 0
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	if inner == "" {
		return 0
	}
	var bits uint32
	for _, f := range strings.Fields(inner) {
		if b, ok := mail.ParseIMAPFlagName(f); ok {
			bits |= b
		}
	}
	return bits
}
