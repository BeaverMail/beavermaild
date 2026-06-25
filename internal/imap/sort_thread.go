// IMAP SORT and THREAD command handlers (RFC 5256 / RFC 5255).
package imap

import (
	"context"
	"strconv"
	"strings"

	"github.com/BeaverMail/beaver/internal/mail"
)

// cmdSort returns sequence numbers or UIDs sorted by RFC 5256 criteria.
func (s *session) cmdSort(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	keys, reverse, searchArg, ok := parseSortArg(arg)
	if !ok {
		return s.tagged(tag, "BAD SORT syntax")
	}
	expr, ok := parseSearchExpr(searchArg)
	if !ok {
		return s.tagged(tag, "BAD SORT syntax")
	}
	load := mail.RawLoader(func(m mail.Message) ([]byte, error) {
		return s.inbox.LoadRaw(ctx, m.Meta)
	})
	var nums []uint32
	if byUID {
		nums = mail.SortUIDs(s.messages, keys, reverse, expr, load)
	} else {
		nums = mail.SortMessages(s.messages, keys, reverse, expr, load)
	}
	if err := s.untagged(formatSort(nums)); err != nil {
		return err
	}
	return s.tagged(tag, "OK SORT completed")
}

// cmdThread returns THREAD REFERENCES groups for the selected mailbox.
func (s *session) cmdThread(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	algo, searchArg, ok := parseThreadArg(arg)
	if !ok {
		return s.tagged(tag, "BAD THREAD syntax")
	}
	if algo != "REFERENCES" {
		return s.tagged(tag, "BAD THREAD algorithm not supported")
	}
	expr, ok := parseSearchExpr(searchArg)
	if !ok {
		return s.tagged(tag, "BAD THREAD syntax")
	}
	load := mail.RawLoader(func(m mail.Message) ([]byte, error) {
		return s.inbox.LoadRaw(ctx, m.Meta)
	})
	var threads [][]uint32
	if byUID {
		threads = mail.ThreadReferencesUIDs(s.messages, expr, load)
	} else {
		threads = mail.ThreadReferences(s.messages, expr, load)
	}
	if err := s.untagged(formatThread(threads)); err != nil {
		return err
	}
	return s.tagged(tag, "OK THREAD completed")
}

// parseSortArg splits sort criteria "(...)" from the optional SEARCH program.
func parseSortArg(arg string) (keys []mail.SortKey, reverse bool, searchArg string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" || arg[0] != '(' {
		return nil, false, "", false
	}
	depth := 0
	end := -1
	for i := 0; i < len(arg); i++ {
		switch arg[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
			}
		}
	}
	if end < 0 {
		return nil, false, "", false
	}
	keys, reverse, ok = parseSortKeyList(strings.TrimSpace(arg[1:end]))
	if !ok || len(keys) == 0 {
		return nil, false, "", false
	}
	searchArg = strings.TrimSpace(arg[end+1:])
	if searchArg == "" {
		searchArg = "ALL"
	}
	return keys, reverse, searchArg, true
}

func parseSortKeyList(inner string) ([]mail.SortKey, bool, bool) {
	tokens := strings.Fields(strings.ToUpper(inner))
	if len(tokens) == 0 {
		return nil, false, false
	}
	var reverse bool
	var keys []mail.SortKey
	for _, tok := range tokens {
		if tok == "REVERSE" {
			reverse = !reverse
			continue
		}
		key, ok := parseSortKey(tok)
		if !ok {
			return nil, false, false
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, reverse, false
	}
	return keys, reverse, true
}

func parseSortKey(tok string) (mail.SortKey, bool) {
	switch tok {
	case "ARRIVAL":
		return mail.SortArrival, true
	case "CC":
		return mail.SortCC, true
	case "DATE":
		return mail.SortDate, true
	case "FROM":
		return mail.SortFrom, true
	case "SIZE":
		return mail.SortSize, true
	case "SUBJECT":
		return mail.SortSubject, true
	case "TO":
		return mail.SortTo, true
	default:
		return 0, false
	}
}

func parseThreadArg(arg string) (algo, searchArg string, ok bool) {
	algo, rest := splitCommand(arg)
	algo = strings.Trim(algo, "()")
	algo = strings.ToUpper(strings.TrimSpace(algo))
	if algo != "REFERENCES" && algo != "ORDEREDSUBJECT" && algo != "REFS" {
		return "", "", false
	}
	searchArg = strings.TrimSpace(rest)
	if searchArg == "" {
		searchArg = "ALL"
	}
	return algo, searchArg, true
}

func formatSort(nums []uint32) string {
	if len(nums) == 0 {
		return "SORT"
	}
	return "SORT " + joinUints(nums)
}

func formatThread(threads [][]uint32) string {
	if len(threads) == 0 {
		return "THREAD"
	}
	var b strings.Builder
	b.WriteString("THREAD")
	for _, th := range threads {
		b.WriteString(" (")
		b.WriteString(joinUints(th))
		b.WriteByte(')')
	}
	return b.String()
}

func joinUints(nums []uint32) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, " ")
}
