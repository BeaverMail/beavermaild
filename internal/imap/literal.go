// Literals ({n} / {n+}) inside SEARCH, SORT and THREAD command lines.
package imap

import (
	"fmt"
	"strconv"
	"strings"
)

// maxCommandLiteralBytes caps the literal bytes one search command may carry.
const maxCommandLiteralBytes = 64 << 10

// takesSearchLiterals reports whether cmd (with arg) is a search command whose strings may be literals.
func takesSearchLiterals(cmd, arg string) bool {
	if cmd == "UID" {
		cmd, _ = splitCommand(arg)
	}
	switch cmd {
	case "SEARCH", "SORT", "THREAD":
		return true
	}
	return false
}

// readCommandLiterals completes a command line ending in a literal marker: it sends the
// continuation for synchronizing literals, reads the literal bytes and the following line,
// and repeats. Each literal stays in arg as "{n}\r\n" plus its bytes, which tokenizeSearchArg
// reads back. ok is false when the command was refused (the tagged reply is already sent).
func (s *session) readCommandLiterals(tag, arg string) (out string, ok bool, err error) {
	total := 0
	line := arg
	for {
		n, nonSync, found := literalMarker(line)
		if !found {
			return arg, true, nil
		}
		total += n
		if total > maxCommandLiteralBytes {
			if nonSync {
				// The client is already sending the bytes: there is no way to resync.
				return "", false, fmt.Errorf("imap: command literal too large")
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
