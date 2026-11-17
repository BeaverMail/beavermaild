// IMAP CONDSTORE: ENABLE and STORE UNCHANGEDSINCE parsing.
package imap

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// cmdEnable activates optional IMAP extensions requested by the client (RFC 5162).
func (s *session) cmdEnable(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return s.tagged(tag, "BAD ENABLE syntax")
	}
	// RFC 5161 3.1: unknown names are ignored; ENABLED lists only what this command enabled (3.1,
	// SHOULD), possibly nothing (3.2).
	var enabled []string
	wasCondstore := s.condstore
	for _, tok := range strings.Fields(strings.ToUpper(arg)) {
		switch {
		case tok == "CONDSTORE" && !wasCondstore && !slices.Contains(enabled, tok):
			enabled = append(enabled, tok)
		case tok == "QRESYNC" && !s.qresync:
			s.qresync = true // QRESYNC implies CONDSTORE (RFC 7162 3.2.3)
			enabled = append(enabled, tok)
		}
	}
	if len(enabled) > 0 {
		if err := s.enableCondstore(ctx); err != nil {
			return err
		}
	}
	if err := s.untagged(strings.TrimSpace("ENABLED " + strings.Join(enabled, " "))); err != nil {
		return err
	}
	return s.tagged(tag, "OK ENABLE completed")
}

// enableCondstore runs on a CONDSTORE enabling command (RFC 7162 3.1): from then on FETCH
// responses carry MODSEQ, and the first one with a mailbox selected reports its HIGHESTMODSEQ.
func (s *session) enableCondstore(ctx context.Context) error {
	if s.condstore {
		return nil
	}
	s.condstore = true
	if !s.selected {
		return nil
	}
	highest, err := s.inbox.HighestModSeq(ctx, s.principal.AccountID, s.mbox.ID)
	if err != nil {
		return err
	}
	_, _, highest = mail.MailboxSelectState(s.messages, highest)
	return s.untagged(fmt.Sprintf("OK [HIGHESTMODSEQ %d] Highest", reportedModSeq(highest)))
}

// reportedModSeq is a mod-sequence as sent to the client: at least 1 (RFC 7162 7, mod-sequence-value),
// for an untouched mailbox (stored 0) or a message stored before mod-sequences.
func reportedModSeq(v uint64) uint64 { return max(v, 1) }

// highestModSeqCode is the "[HIGHESTMODSEQ n] " of the tagged OK after messages left the mailbox
// (RFC 7162 3.2.7, 3.2.9, RFC 6851 4.4), once CONDSTORE is enabled; "" otherwise. It syncs first,
// so the client has every change up to that value when it caches it (RFC 7162 3.2).
func (s *session) highestModSeqCode(ctx context.Context, removed bool) (string, error) {
	if !removed || !s.condstore {
		return "", nil
	}
	if err := s.pushIdleMailboxChanges(ctx); err != nil {
		return "", err
	}
	highest, err := s.inbox.HighestModSeq(ctx, s.principal.AccountID, s.mbox.ID)
	if err != nil {
		return "", err
	}
	_, _, highest = mail.MailboxSelectState(s.messages, highest)
	return fmt.Sprintf("[HIGHESTMODSEQ %d] ", reportedModSeq(highest)), nil
}

// parseUnchangedSince extracts a leading (UNCHANGEDSINCE n) or UNCHANGEDSINCE n clause.
func parseUnchangedSince(rest string) (since uint64, remaining string, ok bool) {
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return 0, rest, false
	}
	upper := strings.ToUpper(rest)
	const paren = "(UNCHANGEDSINCE "
	if strings.HasPrefix(upper, paren) {
		end := strings.IndexByte(rest, ')')
		if end < 0 {
			return 0, rest, false
		}
		num := strings.TrimSpace(rest[len(paren):end])
		n, err := strconv.ParseUint(num, 10, 64)
		if err != nil {
			return 0, rest, false
		}
		return n, strings.TrimSpace(rest[end+1:]), true
	}
	if strings.HasPrefix(upper, "UNCHANGEDSINCE ") {
		fields := strings.Fields(rest)
		if len(fields) < 2 {
			return 0, rest, false
		}
		n, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, rest, false
		}
		remaining = strings.TrimSpace(rest[len(fields[0])+len(fields[1])+1:])
		return n, remaining, true
	}
	return 0, rest, false
}

// parseTrailingUnchangedSince extracts a trailing (UNCHANGEDSINCE n) clause after STORE flags.
func parseTrailingUnchangedSince(rest string) (since uint64, remaining string, ok bool) {
	rest = strings.TrimSpace(rest)
	upper := strings.ToUpper(rest)
	const paren = "(UNCHANGEDSINCE "
	idx := strings.LastIndex(upper, paren)
	if idx < 0 {
		return 0, rest, false
	}
	tail := strings.TrimSpace(rest[idx:])
	if us, _, ok := parseUnchangedSince(tail); ok {
		return us, strings.TrimSpace(rest[:idx]), true
	}
	return 0, rest, false
}

func formatModSeq(modSeq uint64) string {
	return "MODSEQ (" + strconv.FormatUint(modSeq, 10) + ")"
}

// parseChangedSince strips a trailing FETCH modifier list "(CHANGEDSINCE n [VANISHED])" (RFC 7162
// 3.1.4, 3.2.6), in any order. found reports the modifiers; ok is false when they are malformed
// (VANISHED needs CHANGEDSINCE).
func parseChangedSince(rest string) (items string, since uint64, vanished, found, ok bool) {
	rest = strings.TrimSpace(rest)
	open := matchingOpenParen(rest)
	if open < 0 {
		return rest, 0, false, false, true
	}
	mods := strings.Fields(strings.ToUpper(rest[open+1 : len(rest)-1]))
	if len(mods) == 0 || (mods[0] != "CHANGEDSINCE" && mods[0] != "VANISHED") {
		return rest, 0, false, false, true // the item list itself
	}
	hasSince := false
	for i := 0; i < len(mods); i++ {
		switch {
		case mods[i] == "VANISHED" && !vanished:
			vanished = true
		case mods[i] == "CHANGEDSINCE" && !hasSince && i+1 < len(mods):
			n, err := strconv.ParseUint(mods[i+1], 10, 63)
			if err != nil {
				return rest, 0, false, true, false
			}
			since, hasSince = n, true
			i++
		default:
			return rest, 0, false, true, false
		}
	}
	if !hasSince {
		return rest, 0, false, true, false
	}
	return strings.TrimSpace(rest[:open]), since, vanished, true, true
}

// selectMailboxArg parses the SELECT/EXAMINE argument: a mailbox name optionally followed by
// RFC 4466 select parameters: CONDSTORE (condstore reports it) and QRESYNC (...), which needs
// ENABLE QRESYNC first (qresync).
func selectMailboxArg(arg string, qresync bool) (name string, qr *qresyncParams, condstore bool, err error) {
	arg = strings.TrimSpace(arg)
	if open := matchingOpenParen(arg); open > 0 && arg[open-1] == ' ' {
		params := strings.TrimSpace(arg[open+1 : len(arg)-1])
		arg = arg[:open-1]
		for params != "" {
			upper := strings.ToUpper(params)
			switch {
			case strings.HasPrefix(upper, "CONDSTORE"):
				params, condstore = strings.TrimSpace(params[len("CONDSTORE"):]), true
			case strings.HasPrefix(upper, "QRESYNC") && qresync && qr == nil:
				rest := strings.TrimSpace(params[len("QRESYNC"):])
				end := closingParen(rest)
				if end < 0 {
					return "", nil, false, errUnknownSelectParam
				}
				p, ok := parseQResyncParams(rest[1:end])
				if !ok {
					return "", nil, false, errUnknownSelectParam
				}
				qr, params = p, strings.TrimSpace(rest[end+1:])
			default:
				return "", nil, false, errUnknownSelectParam
			}
		}
	}
	name, err = mailboxNameFromArg(arg)
	return name, qr, condstore, err
}

// matchingOpenParen returns the index of the "(" that the final ")" of s closes, or -1.
func matchingOpenParen(s string) int {
	if !strings.HasSuffix(s, ")") {
		return -1
	}
	depth := 0
	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case ')':
			depth++
		case '(':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

// closingParen returns the index of the ")" closing the "(" that starts s, or -1.
func closingParen(s string) int {
	if !strings.HasPrefix(s, "(") {
		return -1
	}
	depth := 0
	for i := range len(s) {
		switch s[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i
			}
		}
	}
	return -1
}

var errUnknownSelectParam = errors.New("imap: unknown SELECT parameter")

// selectNameError answers a SELECT/EXAMINE argument that names no possible mailbox: an unknown
// select parameter is a syntax error; an invalid name just does not exist (CREATE refuses it).
func selectNameError(err error) string {
	if errors.Is(err, errUnknownSelectParam) {
		return "BAD unknown SELECT parameter"
	}
	return "NO mailbox does not exist"
}
