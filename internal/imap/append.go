// IMAP APPEND command parsing and handling.
package imap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/storage"
)

// appendSpec is one message of an APPEND: "[flags] [date-time]" then a literal ({n}, {n+}, ~{n})
// or a CATENATE list (RFC 4469). MULTIAPPEND repeats it.
type appendSpec struct {
	flags        uint32
	internalDate int64
	keywords     []string // set on the new message after it is stored
	size         int
	nonsync      bool
	binary       bool // literal8 (~{n}, RFC 3516)
	catenate     bool
}

// errNULLiteral refuses NUL in a plain literal: a literal is CHAR8 (RFC 3501 9); binary content
// goes in a literal8 (~{n}, RFC 3516), which APPEND accepts.
const errNULLiteral = "BAD NUL in a literal: send binary content as literal8 (~{n})"

// maxMailboxLiteralBytes bounds a mailbox name sent as a literal to APPEND.
const maxMailboxLiteralBytes = 1 << 10

// cmdAppend appends one message, or several with MULTIAPPEND (RFC 3502): all of them or none.
// Literals may be literal8 (~{n}, RFC 3516 BINARY); a message may be built with CATENATE.
func (s *session) cmdAppend(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.rejectCommand(tag, arg, "NO LOGIN required")
	}
	// The mailbox may itself be a literal ("APPEND {5}", then "INBOX (\Seen) {310}"): read that one
	// here; the message literals are read below, under MaxAppendBytes.
	if t := strings.TrimSpace(arg); strings.HasPrefix(t, "{") && !strings.Contains(t, " ") {
		if n, nonSync, isLit := literalMarker(t); isLit {
			if n > maxMailboxLiteralBytes {
				if nonSync {
					_ = s.untagged("BYE [TOOBIG] mailbox name too long")
					return errLiteralTooLarge
				}
				return s.tagged(tag, "BAD mailbox name too long")
			}
			if !nonSync {
				if err := s.continuation(); err != nil {
					return err
				}
			}
			lit, err := s.readLiteral(n)
			if err != nil {
				return err
			}
			line, err := s.readLine()
			if err != nil {
				return err
			}
			arg = t + "\r\n" + string(lit) + line
		}
	}
	mboxName, cur, ok := parseAppendMailboxToken(strings.TrimSpace(arg))
	if !ok {
		return s.rejectCommand(tag, arg, "BAD APPEND syntax")
	}
	// Check the mailbox before any literal: a client must not create folders by APPENDing (RFC 3501
	// says NO [TRYCREATE]), and a sync literal is then never uploaded.
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, mboxName)
	switch {
	case mail.ValidateMailboxName(mboxName) != nil:
		return s.rejectCommand(tag, cur, "BAD mailbox name syntax")
	case errors.Is(err, storage.ErrNotFound):
		return s.rejectCommand(tag, cur, "NO [TRYCREATE] mailbox does not exist")
	case err != nil:
		return err
	}

	// Read every message first: MULTIAPPEND is all or nothing. The size cap covers them all, so
	// one command holds at most MaxAppendBytes in memory.
	var raws [][]byte
	var specs []appendSpec
	total := 0
	for strings.TrimSpace(cur) != "" {
		spec, after, ok := parseAppendHead(cur)
		if !ok {
			return s.rejectCommand(tag, cur, "BAD APPEND syntax")
		}
		var raw []byte
		if !spec.catenate {
			if raw, ok, err = s.readAppendLiteral(tag, spec, &total); !ok || err != nil {
				return err
			}
			if cur, err = s.readLine(); err != nil {
				return err
			}
			if len(raw) == 0 { // {0} is valid syntax; there is no message to store
				return s.rejectCommand(tag, cur, "NO [CANNOT] empty message")
			}
			if spec.binary {
				raw = base64NULParts(raw)
			} else if bytes.IndexByte(raw, 0) >= 0 {
				return s.rejectCommand(tag, cur, errNULLiteral)
			}
		} else if raw, cur, ok, err = s.readCatenate(ctx, tag, after, &total); !ok || err != nil {
			return err
		}
		raws, specs = append(raws, raw), append(specs, spec)
	}
	if len(raws) == 0 {
		return s.tagged(tag, "BAD APPEND syntax")
	}

	var ids, uids []uint32
	for i, raw := range raws {
		emailID, err := s.inbox.Append(ctx, s.principal.AccountID, mbox.ID, raw, specs[i].flags, specs[i].internalDate)
		if err == nil && len(specs[i].keywords) > 0 {
			if _, err = s.inbox.SetFlagsMany(ctx, s.principal.AccountID, []uint32{emailID}, 0, 0, specs[i].keywords, nil, 0); err != nil {
				ids = append(ids, emailID) // stored: undone with the others below
			}
		}
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

// readAppendLiteral reads the message literal spec announces, counting it in *total. ok is false
// when the command was refused instead (the reply or BYE is already sent).
// appendMessageCost is what each message of a MULTIAPPEND counts toward MaxAppendBytes besides its
// bytes: the per-message bookkeeping is ~100 bytes, so a million 1-byte messages would otherwise
// hold far more memory than the cap (CVE-2024-34055 class). It bounds a command to 8192 messages.
const appendMessageCost = 4 << 10

func (s *session) readAppendLiteral(tag string, spec appendSpec, total *int) (raw []byte, ok bool, err error) {
	if *total += spec.size + appendMessageCost; *total > mail.MaxAppendBytes {
		if spec.nonsync {
			// The client is already sending the bytes, which would otherwise be read as commands
			// (RFC 7888 4): say why and hang up rather than read megabytes to throw away.
			_ = s.untagged("BYE [TOOBIG] APPEND literal too large")
			return nil, false, errLiteralTooLarge
		}
		// Refusing a sync literal ends the command: the client never sends it.
		return nil, false, s.tagged(tag, "NO [TOOBIG] message too large")
	}
	if !spec.nonsync {
		if err := s.continuation(); err != nil {
			return nil, false, err
		}
	}
	raw, err = s.readLiteral(spec.size)
	return raw, err == nil, err
}

// readCatenate builds a CATENATE message (RFC 4469) from its parts, rest being the line after
// "CATENATE (": TEXT literals and URLs of messages this user may read. It returns the line left
// after the closing parenthesis; ok is false when the command was refused.
func (s *session) readCatenate(ctx context.Context, tag, rest string, total *int) (msg []byte, tail string, ok bool, err error) {
	if *total += appendMessageCost; *total > mail.MaxAppendBytes {
		return nil, "", false, s.rejectCommand(tag, rest, "NO [TOOBIG] message too large")
	}
	for {
		rest = strings.TrimLeft(rest, " ")
		word, arg, _ := strings.Cut(rest, " ")
		switch {
		case strings.HasPrefix(rest, ")"):
			return msg, rest[1:], true, nil
		case strings.EqualFold(word, "URL"):
			var raw string
			if strings.HasPrefix(arg, "\"") {
				raw, rest, ok = parseQuoted(arg)
			} else {
				i := strings.IndexAny(arg, " )")
				if i < 0 {
					i = len(arg)
				}
				raw, rest, ok = arg[:i], arg[i:], i > 0
			}
			if !ok {
				return nil, "", false, s.rejectCommand(tag, rest, "BAD CATENATE syntax")
			}
			data, err := s.catenateURL(ctx, raw)
			if errors.Is(err, errBadURL) {
				return nil, "", false, s.rejectCommand(tag, rest, "NO [BADURL "+raw+"] CATENATE URL refused")
			} else if err != nil {
				return nil, "", false, err
			}
			if *total += len(data); *total > mail.MaxAppendBytes {
				return nil, "", false, s.rejectCommand(tag, rest, "NO [TOOBIG] message too large")
			}
			msg = append(msg, data...)
		case strings.EqualFold(word, "TEXT"):
			spec, after, ok := parseAppendHead(arg)
			if !ok || spec.catenate || after != "" || spec.flags != 0 || spec.internalDate != 0 || spec.binary {
				return nil, "", false, s.rejectCommand(tag, rest, "BAD CATENATE syntax")
			}
			data, ok, err := s.readAppendLiteral(tag, spec, total)
			if !ok || err != nil {
				return nil, "", false, err
			}
			msg = append(msg, data...)
			if rest, err = s.readLine(); err != nil {
				return nil, "", false, err
			}
			if bytes.IndexByte(data, 0) >= 0 {
				return nil, "", false, s.rejectCommand(tag, rest, errNULLiteral)
			}
		default:
			return nil, "", false, s.rejectCommand(tag, rest, "BAD CATENATE syntax")
		}
	}
}

// catenateURL returns the bytes a CATENATE URL names: a message or part in this user's mailboxes.
func (s *session) catenateURL(ctx context.Context, raw string) ([]byte, error) {
	u, ok := parseIMAPURL(raw)
	if !ok || u.access != "" || u.absolute && !strings.EqualFold(u.owner(), s.principal.Email()) {
		return nil, errBadURL
	}
	release, err := acquireRawLoad(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return s.resolveURL(ctx, s.principal.AccountID, u)
}

// rejectCommand answers resp to a command whose last line read is line. Non-synchronizing literals
// the client is already sending are read and dropped; a synchronizing one is refused unsent.
func (s *session) rejectCommand(tag, line, resp string) error {
	for {
		n, nonsync, found := literalMarker(line)
		if !found || !nonsync {
			return s.tagged(tag, resp)
		}
		if n > mail.MaxAppendBytes {
			_ = s.untagged("BYE [TOOBIG] literal too large")
			return errLiteralTooLarge
		}
		s.bumpReadDeadline()
		if _, err := io.CopyN(io.Discard, s.r, int64(n)); err != nil {
			return err
		}
		var err error
		if line, err = s.readLine(); err != nil {
			return err
		}
	}
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
	spec, after, ok := parseAppendHead(rest)
	if !ok || spec.catenate || after != "" {
		return "", 0, 0, 0, false, false
	}
	return mailbox, spec.flags, spec.internalDate, spec.size, spec.nonsync, true
}

// parseAppendHead parses "[(flags)] ["date-time"]" then either a literal ending the line ({n},
// {n+}, ~{n}, ~{n+}) or "CATENATE (", whose parts start in after.
func parseAppendHead(rest string) (spec appendSpec, after string, ok bool) {
	rest = strings.TrimSpace(rest)
	if strings.HasPrefix(rest, "(") {
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return spec, "", false
		}
		// The same flag list as STORE (RFC 3501 6.3.11: the flags SHOULD be set): keywords kept,
		// \Recent ignored, a malformed flag refused.
		var kwOK bool
		if spec.flags, spec.keywords, kwOK = parseIMAPFlagList(rest[:end+1]); !kwOK {
			return spec, "", false
		}
		rest = strings.TrimSpace(rest[end+1:])
	}
	if strings.HasPrefix(rest, "\"") {
		dateStr, tail, ok := parseQuoted(rest)
		if !ok {
			return spec, "", false
		}
		t, ok := parseIMAPInternalDate(dateStr)
		if !ok {
			return spec, "", false
		}
		spec.internalDate = t.Unix()
		rest = strings.TrimSpace(tail)
	}
	if len(rest) >= 8 && strings.EqualFold(rest[:8], "CATENATE") {
		after, found := strings.CutPrefix(strings.TrimLeft(rest[8:], " "), "(")
		spec.catenate = true
		return spec, after, found
	}
	n, nonsync, found := literalMarker(rest)
	if !found {
		return spec, "", false
	}
	lit := rest[:strings.LastIndexByte(rest, '{')]
	lit, spec.binary = strings.CutSuffix(lit, "~") // literal8 (RFC 3516)
	spec.size, spec.nonsync = n, nonsync
	return spec, "", lit == ""
}

// parseIMAPInternalDate parses an APPEND date-time / INTERNALDATE string.
func parseIMAPInternalDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	// date-day-fixed is (SP DIGIT) / 2DIGIT (RFC 3501 9): "_2" takes " 5", "5" and "05".
	t, err := time.Parse("_2-Jan-2006 15:04:05 -0700", s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func parseAppendMailboxToken(rest string) (name string, tail string, ok bool) {
	return cutAString(rest)
}
