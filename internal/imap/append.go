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

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

// appendSpec is one message of an APPEND: "[flags] [date-time] {n}" (MULTIAPPEND repeats it).
type appendSpec struct {
	flags        uint32
	internalDate int64
	size         int
	nonsync      bool
	binary       bool // literal8 (~{n}, RFC 3516)
}

// cmdAppend appends one message, or several with MULTIAPPEND (RFC 3502): all of them or none.
// Literals may be literal8 (~{n}, RFC 3516 BINARY).
func (s *session) cmdAppend(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	mboxName, rest, ok := parseAppendMailboxToken(strings.TrimSpace(arg))
	spec, specOK := parseAppendSpec(rest)
	if !ok || !specOK {
		return s.tagged(tag, "BAD APPEND syntax")
	}
	// Check the mailbox before the literal: a client must not create folders by APPENDing (RFC 3501
	// says NO [TRYCREATE]), and a sync literal is then never uploaded.
	var mbox mail.Mailbox
	var refuse string
	if err := mail.ValidateMailboxName(mboxName); err != nil {
		refuse = "BAD mailbox name syntax"
	} else if mbox, err = s.inbox.ResolveMailbox(ctx, s.principal.AccountID, mboxName); errors.Is(err, storage.ErrNotFound) {
		refuse = "NO [TRYCREATE] mailbox does not exist"
	} else if err != nil {
		return err
	}
	if refuse != "" && spec.size <= mail.MaxAppendBytes {
		if spec.nonsync {
			// The client already sends a {n+} literal: drop it, or its bytes would be read as commands.
			s.bumpReadDeadline()
			if _, err := io.CopyN(io.Discard, s.r, int64(spec.size)); err != nil {
				return err
			}
			if _, err := s.readLine(); err != nil { // the rest of the command line
				return err
			}
		}
		return s.tagged(tag, refuse)
	}

	// Read every message first: MULTIAPPEND is all or nothing. The size cap covers them all, so
	// one command holds at most MaxAppendBytes in memory.
	var raws [][]byte
	var specs []appendSpec
	total := 0
	for {
		total += spec.size
		if total > mail.MaxAppendBytes {
			if spec.nonsync {
				// The client is already sending the bytes, which would otherwise be read as commands
				// (RFC 7888 4): say why and hang up rather than read megabytes to throw away.
				_ = s.untagged("BYE [TOOBIG] APPEND literal too large")
				return errLiteralTooLarge
			}
			if len(raws) > 0 {
				// The command line still expects this literal; ending the connection is the only clean exit.
				_ = s.untagged("BYE [TOOBIG] APPEND too large")
				return errLiteralTooLarge
			}
			return s.tagged(tag, "NO [TOOBIG] message too large")
		}
		if !spec.nonsync {
			if err := s.continuation(); err != nil {
				return err
			}
		}
		raw, err := s.readLiteral(spec.size)
		if err != nil {
			return err
		}
		if spec.binary {
			raw = base64NULParts(raw)
		}
		raws, specs = append(raws, raw), append(specs, spec)
		line, err := s.readLine()
		if err != nil {
			return err
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		if spec, ok = parseAppendSpec(line); !ok {
			return s.tagged(tag, "BAD APPEND syntax")
		}
	}

	var ids, uids []uint32
	for i, raw := range raws {
		emailID, err := s.inbox.Append(ctx, s.principal.AccountID, mbox.ID, raw, specs[i].flags, specs[i].internalDate)
		if err == nil {
			var meta storage.EmailMeta
			if meta, err = s.inbox.GetMeta(ctx, s.principal.AccountID, emailID); err == nil {
				ids, uids = append(ids, emailID), append(uids, mail.IMAPUID(emailID, meta))
				continue
			}
			ids = append(ids, emailID)
		}
		for _, id := range ids { // undo the ones already stored
			_ = s.inbox.DeleteMessage(ctx, s.principal.AccountID, id)
		}
		if errors.Is(err, mail.ErrOverQuota) {
			return s.tagged(tag, "NO [OVERQUOTA] APPEND failed")
		}
		return err
	}
	// Into the selected mailbox: EXISTS and \Recent come from the sync before the tagged reply.
	return s.tagged(tag, fmt.Sprintf("OK [%s] APPEND completed", formatAppendUID(mbox.UIDValidity, uids)))
}

func (s *session) readLiteral(n int) ([]byte, error) {
	s.bumpReadDeadline()
	buf := make([]byte, n)
	if _, err := io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func parseAppendArg(arg string) (mailbox string, flags uint32, internalDate int64, size int, nonsync bool, ok bool) {
	mailbox, rest, ok := parseAppendMailboxToken(strings.TrimSpace(arg))
	if !ok {
		return "", 0, 0, 0, false, false
	}
	spec, ok := parseAppendSpec(rest)
	if !ok {
		return "", 0, 0, 0, false, false
	}
	return mailbox, spec.flags, spec.internalDate, spec.size, spec.nonsync, true
}

// parseAppendSpec parses "[(flags)] ["date-time"] {n}" (or {n+}, ~{n}, ~{n+}).
func parseAppendSpec(rest string) (appendSpec, bool) {
	var spec appendSpec
	rest = strings.TrimSpace(rest)
	litStart := strings.LastIndexByte(rest, '{')
	if litStart < 0 || rest[len(rest)-1] != '}' {
		return spec, false
	}
	lit := strings.TrimSpace(rest[litStart+1 : len(rest)-1])
	if strings.HasSuffix(lit, "+") {
		spec.nonsync = true
		lit = strings.TrimSuffix(lit, "+")
	}
	size, err := strconv.Atoi(strings.TrimSpace(lit))
	if err != nil || size <= 0 {
		return spec, false
	}
	spec.size = size
	rest = strings.TrimSpace(rest[:litStart])
	rest, spec.binary = strings.CutSuffix(rest, "~") // literal8 (RFC 3516)
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") {
		close := strings.IndexByte(rest, ')')
		if close < 0 {
			return spec, false
		}
		spec.flags = parseAppendFlags(rest[:close+1])
		rest = strings.TrimSpace(rest[close+1:])
	}
	if strings.HasPrefix(rest, "\"") {
		dateStr, tail, ok := parseQuoted(rest)
		if !ok {
			return spec, false
		}
		t, ok := parseIMAPInternalDate(dateStr)
		if !ok {
			return spec, false
		}
		spec.internalDate = t.Unix()
		rest = strings.TrimSpace(tail)
	}
	return spec, rest == ""
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
