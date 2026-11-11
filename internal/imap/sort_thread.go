// IMAP SORT and THREAD command handlers (RFC 5256 / RFC 5255).
package imap

import (
	"context"
	"strconv"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// cmdSort returns sequence numbers or UIDs sorted by RFC 5256 criteria.
func (s *session) cmdSort(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	ret, arg, extended, ok := cutReturnOpts(arg)
	if !ok {
		return s.tagged(tag, "BAD SORT RETURN syntax")
	}
	if ret.update && s.hasSearchContext(tag) {
		return s.tagged(tag, "BAD tag already names an updating search")
	}
	crits, searchArg, ok := parseSortArg(arg)
	if !ok {
		return s.tagged(tag, "BAD SORT syntax")
	}
	expr, st := parseSortSearch(searchArg)
	switch st {
	case searchBadCharset:
		return s.tagged(tag, "NO [BADCHARSET ("+searchCharsets+")] charset not supported")
	case searchSyntaxError:
		return s.tagged(tag, "BAD SORT syntax")
	}
	if expr.UsesModSeq() {
		if err := s.enableCondstore(ctx); err != nil {
			return err
		}
	}
	w := s.watchCommand(ctx)
	load := mail.RawLoader(func(m mail.Message) ([]byte, error) {
		return s.inbox.LoadRaw(w.ctx, m.Meta)
	})
	seqs, _ := mail.SortMessagesContext(w.ctx, s.messages, crits, expr, load)
	if cause := w.end(); cause != nil {
		return s.abortCommand(tag, cause)
	}
	resp := formatSort(s.seqsOrUIDs(seqs, byUID)) + s.searchModSeqSuffix(&expr, seqs)
	if extended {
		resp = s.esearchLine(tag, byUID, seqs, ret, expr.UsesModSeq())
	}
	if err := s.untagged(resp); err != nil {
		return err
	}
	if ret.update {
		if err := s.addSearchContext(tag, byUID, crits, expr, seqs); err != nil {
			return err
		}
	}
	return s.tagged(tag, "OK SORT completed")
}

// cmdThread returns the REFERENCES or ORDEREDSUBJECT threads of the selected mailbox.
func (s *session) cmdThread(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	algo, searchArg, ok := parseThreadArg(arg)
	if !ok {
		return s.tagged(tag, "BAD THREAD syntax")
	}
	thread := mail.ThreadReferencesContext
	switch algo {
	case "REFERENCES":
	case "ORDEREDSUBJECT":
		thread = mail.ThreadOrderedSubjectContext
	default:
		return s.tagged(tag, "BAD THREAD algorithm not supported")
	}
	expr, st := parseSortSearch(searchArg)
	switch st {
	case searchBadCharset:
		return s.tagged(tag, "NO [BADCHARSET ("+searchCharsets+")] charset not supported")
	case searchSyntaxError:
		return s.tagged(tag, "BAD THREAD syntax")
	}
	w := s.watchCommand(ctx)
	load := mail.RawLoader(func(m mail.Message) ([]byte, error) {
		return s.inbox.LoadRaw(w.ctx, m.Meta)
	})
	threads, _ := thread(w.ctx, s.messages, expr, load)
	if cause := w.end(); cause != nil {
		return s.abortCommand(tag, cause)
	}
	num := func(seq uint32) uint32 {
		if byUID {
			return s.messages[seq-1].UID
		}
		return seq
	}
	if err := s.untagged(formatThread(threads, num)); err != nil {
		return err
	}
	return s.tagged(tag, "OK THREAD completed")
}

// parseSortArg splits sort criteria "(...)" from the optional SEARCH program.
func parseSortArg(arg string) (crits []mail.SortCriterion, searchArg string, ok bool) {
	arg = strings.TrimLeft(arg, " ")
	if arg == "" || arg[0] != '(' {
		return nil, "", false
	}
	depth := 0
	end := -1
	for i := 0; i < len(arg); i++ {
		switch arg[i] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 {
			end = i
			break
		}
	}
	if end < 0 {
		return nil, "", false
	}
	crits, ok = parseSortKeyList(strings.TrimSpace(arg[1:end]))
	if !ok {
		return nil, "", false
	}
	searchArg = strings.TrimLeft(arg[end+1:], " ")
	if strings.TrimSpace(searchArg) == "" {
		searchArg = "ALL"
	}
	return crits, searchArg, true
}

// parseSortKeyList parses sort keys; REVERSE applies to the key that follows it (RFC 5256).
func parseSortKeyList(inner string) ([]mail.SortCriterion, bool) {
	var crits []mail.SortCriterion
	reverse := false
	for _, tok := range strings.Fields(strings.ToUpper(inner)) {
		if tok == "REVERSE" {
			if reverse {
				return nil, false
			}
			reverse = true
			continue
		}
		key, ok := parseSortKey(tok)
		if !ok {
			return nil, false
		}
		crits = append(crits, mail.SortCriterion{Key: key, Reverse: reverse})
		reverse = false
	}
	if len(crits) == 0 || reverse {
		return nil, false
	}
	return crits, true
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
	case "DISPLAYFROM":
		return mail.SortDisplayFrom, true
	case "DISPLAYTO":
		return mail.SortDisplayTo, true
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
	return algo, rest, true
}

func formatSort(nums []uint32) string {
	if len(nums) == 0 {
		return "SORT"
	}
	return "SORT " + joinUints(nums)
}

// formatThread writes thread-data (RFC 5256): "THREAD" then one parenthesized list per thread,
// lists back to back with no space. num maps a sequence number to the number to send.
func formatThread(threads []*mail.ThreadNode, num func(uint32) uint32) string {
	if len(threads) == 0 {
		return "THREAD"
	}
	var b strings.Builder
	b.WriteString("THREAD ")
	for _, th := range threads {
		b.WriteByte('(')
		writeThreadMembers(&b, th, num)
		b.WriteByte(')')
	}
	return b.String()
}

// writeThreadMembers writes a chain of single replies as "1 2 3", then the branches of the node
// where the chain forks as nested lists: "1 (2 4)(3)". A dummy contributes no number.
func writeThreadMembers(b *strings.Builder, n *mail.ThreadNode, num func(uint32) uint32) {
	first := true
	for {
		if n.Seq != 0 {
			if !first {
				b.WriteByte(' ')
			}
			b.WriteString(strconv.FormatUint(uint64(num(n.Seq)), 10))
			first = false
		}
		if n.Seq == 0 || len(n.Children) != 1 {
			break
		}
		n = n.Children[0]
	}
	if len(n.Children) == 0 {
		return
	}
	if !first {
		b.WriteByte(' ')
	}
	for _, ch := range n.Children {
		b.WriteByte('(')
		writeThreadMembers(b, ch, num)
		b.WriteByte(')')
	}
}

func joinUints(nums []uint32) string {
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, " ")
}
