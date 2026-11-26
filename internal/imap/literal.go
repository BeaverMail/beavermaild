// Literals ({n} / {n+}) inside command lines.
package imap

import (
	"errors"
	"strconv"
	"strings"
)

// maxCommandLiteralBytes caps the literal bytes one command may carry (APPEND reads its messages
// itself, under MaxAppendBytes). Before login a client only needs room for a user name and a
// password, so an anonymous connection cannot make the server hold more than a few KiB.
const (
	maxCommandLiteralBytes = 64 << 10
	maxPreAuthLiteralBytes = 8 << 10
)

// errLiteralTooLarge ends a connection whose non-synchronizing literal is refused.
var errLiteralTooLarge = errors.New("imap: literal too large")

const errLiteral8 = "BAD literal8 is valid in APPEND only"

// readsOwnLiterals reports whether cmd reads its literals itself: APPEND streams its messages under
// MaxAppendBytes. Every other command gets its literals read here, whatever it is: a literal left
// unread would be taken for the next command (command smuggling).
func readsOwnLiterals(cmd string) bool { return cmd == "APPEND" }

// readCommandLiterals completes a command line ending in a literal marker: it sends the
// continuation for synchronizing literals, reads the literal bytes and the following line,
// and repeats. Each literal stays in arg as "{n}\r\n" plus its bytes, which tokenizeSearchArg
// reads back. ok is false when the command was refused (the tagged reply is already sent).
func (s *session) readCommandLiterals(tag, arg string) (out string, ok bool, err error) {
	total, limit := 0, maxCommandLiteralBytes
	if s.principal.AccountID == 0 {
		limit = maxPreAuthLiteralBytes
	}
	line, lit8 := arg, false
	for {
		n, nonSync, found := literalMarker(line)
		if !found {
			// Refused only once every literal is read, so none is taken for a command. No string
			// holds NUL (RFC 3501 9 CHAR8; CVE-2019-11500, CVE-2007-5740 class).
			switch {
			case lit8:
				return "", false, s.tagged(tag, errLiteral8)
			case strings.IndexByte(arg, 0) >= 0:
				return "", false, s.tagged(tag, "BAD NUL in a command")
			}
			return arg, true, nil
		}
		// literal8 (~{n}) is APPEND data only (RFC 3516 7).
		if strings.HasSuffix(line[:strings.LastIndexByte(line, '{')], "~") {
			if !nonSync {
				return "", false, s.tagged(tag, errLiteral8)
			}
			lit8 = true
		}
		total += n
		if total > limit {
			if nonSync {
				// The client is already sending the bytes: there is no way to resync.
				_ = s.untagged("BYE [TOOBIG] command literal too large")
				return "", false, errLiteralTooLarge
			}
			return "", false, s.tagged(tag, "BAD literal too large")
		}
		if !nonSync {
			if err := s.continuation(); err != nil {
				return "", false, err
			}
		}
		lit, err := s.readLiteral(n)
		if err != nil {
			return "", false, err
		}
		if line, err = s.readLine(); err != nil {
			return "", false, err
		}
		arg += "\r\n" + string(lit) + line
	}
}

// literalMarker parses a trailing "{n}" or "{n+}" on one command line.
func literalMarker(line string) (n int, nonSync, ok bool) {
	if !strings.HasSuffix(line, "}") {
		return 0, false, false
	}
	start := strings.LastIndexByte(line, '{')
	if start < 0 {
		return 0, false, false
	}
	num := line[start+1 : len(line)-1]
	if strings.HasSuffix(num, "+") {
		nonSync = true
		num = num[:len(num)-1]
	}
	if !isDigits(num) {
		return 0, false, false
	}
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, false, false
	}
	return n, nonSync, true
}
