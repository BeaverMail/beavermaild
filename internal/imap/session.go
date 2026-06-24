// IMAP session state machine for one client connection.
package imap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/mail"
	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/BeaverMail/beaver/internal/tlsload"
)

type session struct {
	log   *slog.Logger
	conn  net.Conn
	r     *bufio.Reader
	dir   *directory.Local
	inbox *mail.Inbox
	tls   *tlsload.Certs

	secure      bool
	tlsRequired bool

	principal directory.Principal
	selected  bool
	readOnly  bool
	mbox      mail.Mailbox
	messages  []mail.Message
}

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox, certs *tlsload.Certs, secure, tlsRequired bool) *session {
	return &session{
		log:         log,
		conn:        conn,
		r:           bufio.NewReader(conn),
		dir:         dir,
		inbox:       inbox,
		tls:         certs,
		secure:      secure,
		tlsRequired: tlsRequired,
	}
}

func (s *session) run(ctx context.Context) error {
	if err := s.untagged("OK BeaverMail IMAP4rev1 ready"); err != nil {
		return err
	}
	for {
		line, err := s.readLine()
		if err != nil {
			return err
		}
		if line == "" {
			continue
		}
		tag, cmd, arg := parseTagged(line)
		if tag == "" {
			continue
		}
		switch cmd {
		case "CAPABILITY":
			if err := s.untagged(s.capabilityLine()); err != nil {
				return err
			}
			if err := s.tagged(tag, "OK CAPABILITY completed"); err != nil {
				return err
			}
		case "NOOP":
			if err := s.tagged(tag, "OK NOOP completed"); err != nil {
				return err
			}
		case "LOGIN":
			if s.tlsRequired && !s.secure {
				if err := s.tagged(tag, "NO TLS required"); err != nil {
					return err
				}
				continue
			}
			user, pass, ok := parseLogin(arg)
			if !ok {
				if err := s.tagged(tag, "BAD LOGIN requires user and password"); err != nil {
					return err
				}
				continue
			}
			p, err := s.dir.Authenticate(ctx, user, pass)
			if err != nil {
				if errors.Is(err, directory.ErrInvalidCredentials) || errors.Is(err, directory.ErrInactive) {
					if err := s.tagged(tag, "NO LOGIN failed"); err != nil {
						return err
					}
					continue
				}
				return err
			}
			s.principal = p
			s.selected = false
			s.messages = nil
			if err := s.tagged(tag, "OK LOGIN completed"); err != nil {
				return err
			}
		case "LIST":
			if s.principal.AccountID == 0 {
				if err := s.tagged(tag, "NO LOGIN required"); err != nil {
					return err
				}
				continue
			}
			mboxes, err := s.inbox.ListMailboxes(ctx, s.principal.AccountID)
			if err != nil {
				return err
			}
			for _, mb := range mboxes {
				if err := s.untagged(fmt.Sprintf(`LIST (\HasNoChildren) "/" %s`, formatListMailbox(mb.Name))); err != nil {
					return err
				}
			}
			if err := s.tagged(tag, "OK LIST completed"); err != nil {
				return err
			}
		case "SELECT":
			if err := s.openMailbox(ctx, tag, parseMailboxName(arg), false); err != nil {
				return err
			}
		case "EXAMINE":
			if err := s.openMailbox(ctx, tag, parseMailboxName(arg), true); err != nil {
				return err
			}
		case "STATUS":
			if err := s.cmdStatus(ctx, tag, arg); err != nil {
				return err
			}
		case "CREATE":
			if err := s.cmdCreate(ctx, tag, arg); err != nil {
				return err
			}
		case "DELETE":
			if err := s.cmdDelete(ctx, tag, arg); err != nil {
				return err
			}
		case "COPY":
			if err := s.cmdCopy(ctx, tag, arg, false); err != nil {
				return err
			}
		case "MOVE":
			if err := s.cmdMove(ctx, tag, arg, false); err != nil {
				return err
			}
		case "FETCH":
			if err := s.cmdFetch(ctx, tag, arg, false); err != nil {
				return err
			}
		case "STORE":
			if err := s.cmdStore(ctx, tag, arg, false); err != nil {
				return err
			}
		case "EXPUNGE":
			if err := s.cmdExpunge(ctx, tag); err != nil {
				return err
			}
		case "SEARCH":
			if err := s.cmdSearch(ctx, tag, arg, false); err != nil {
				return err
			}
		case "UID":
			sub, rest := splitCommand(arg)
			switch sub {
			case "FETCH":
				if err := s.cmdFetch(ctx, tag, rest, true); err != nil {
					return err
				}
			case "STORE":
				if err := s.cmdStore(ctx, tag, rest, true); err != nil {
					return err
				}
			case "SEARCH":
				if err := s.cmdSearch(ctx, tag, rest, true); err != nil {
					return err
				}
			case "COPY":
				if err := s.cmdCopy(ctx, tag, rest, true); err != nil {
					return err
				}
			case "MOVE":
				if err := s.cmdMove(ctx, tag, rest, true); err != nil {
					return err
				}
			default:
				if err := s.tagged(tag, "BAD command not supported"); err != nil {
					return err
				}
			}
		case "APPEND":
			if err := s.cmdAppend(ctx, tag, arg); err != nil {
				return err
			}
		case "STARTTLS":
			if err := s.cmdStartTLS(tag); err != nil {
				return err
			}
		case "LOGOUT":
			_ = s.untagged("BYE logging out")
			_ = s.tagged(tag, "OK LOGOUT completed")
			return nil
		default:
			if err := s.tagged(tag, "BAD command not supported"); err != nil {
				return err
			}
		}
	}
}

func (s *session) capabilityLine() string {
	caps := "IMAP4rev1 MOVE"
	if s.tls != nil && !s.secure {
		caps += " STARTTLS"
	}
	return "CAPABILITY " + caps
}

func (s *session) cmdStartTLS(tag string) error {
	if s.secure {
		return s.tagged(tag, "BAD TLS already active")
	}
	if s.tls == nil {
		return s.tagged(tag, "BAD TLS not available")
	}
	if err := s.tagged(tag, "OK Begin TLS negotiation now"); err != nil {
		return err
	}
	tlsConn := s.tls.WrapServer(s.conn)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	s.conn = tlsConn
	s.r = bufio.NewReader(tlsConn)
	s.secure = true
	return nil
}

func (s *session) openMailbox(ctx context.Context, tag, name string, examine bool) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	mbox, err := s.resolveOrCreateMailbox(ctx, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		return err
	}
	recent, err := s.inbox.ClearRecentFlags(ctx, s.principal.AccountID, mbox.ID)
	if err != nil {
		return err
	}
	msgs, err := s.inbox.List(ctx, s.principal.AccountID, mbox.ID)
	if err != nil {
		return err
	}
	s.messages = msgs
	s.mbox = mbox
	s.selected = true
	s.readOnly = examine
	if err := s.untagged(mail.IMAPCapabilityFlags); err != nil {
		return err
	}
	if err := s.untagged(fmt.Sprintf("%d EXISTS", len(msgs))); err != nil {
		return err
	}
	if err := s.untagged(fmt.Sprintf("%d RECENT", recent)); err != nil {
		return err
	}
	if err := s.untagged(fmt.Sprintf("OK [UIDVALIDITY %d] [PERMANENTFLAGS %s]", mbox.UIDValidity, mail.IMAPPermanentFlags)); err != nil {
		return err
	}
	if examine {
		return s.tagged(tag, "OK [READ-ONLY] EXAMINE completed")
	}
	return s.tagged(tag, "OK [READ-WRITE] SELECT completed")
}

func (s *session) cmdFetch(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	setStr, items, ok := parseFetchArg(arg)
	if !ok {
		return s.tagged(tag, "BAD FETCH syntax")
	}
	set, err := parseSeqSet(setStr)
	if err != nil {
		return s.tagged(tag, "BAD FETCH syntax")
	}
	indices := s.resolveIndices(set, byUID)
	for _, idx := range indices {
		if err := s.writeFetch(ctx, idx+1, s.messages[idx], items); err != nil {
			return err
		}
	}
	return s.tagged(tag, "OK FETCH completed")
}

func (s *session) cmdStore(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	setStr, mode, set, clear, ok := parseStoreArg(arg)
	if !ok {
		return s.tagged(tag, "BAD STORE syntax")
	}
	setParsed, err := parseSeqSet(setStr)
	if err != nil {
		return s.tagged(tag, "BAD STORE syntax")
	}
	indices := s.resolveIndices(setParsed, byUID)
	for _, idx := range indices {
		msg := s.messages[idx]
		if err := s.inbox.SetFlags(ctx, s.principal.AccountID, msg.UID, set, clear); err != nil {
			return err
		}
		meta, err := s.inbox.GetMeta(ctx, s.principal.AccountID, msg.UID)
		if err != nil {
			return err
		}
		s.messages[idx].Meta = meta
		if mode != storeSilent {
			if err := s.untagged(fmt.Sprintf("%d FETCH (FLAGS %s)", idx+1, mail.FormatIMAPFlags(meta.Flags))); err != nil {
				return err
			}
		}
	}
	return s.tagged(tag, "OK STORE completed")
}

// cmdExpunge permanently removes messages marked \Deleted in the selected mailbox.
func (s *session) cmdExpunge(ctx context.Context, tag string) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	for {
		var found bool
		for i, m := range s.messages {
			if m.Meta.Flags&mail.FlagDeleted == 0 {
				continue
			}
			if err := s.inbox.DeleteMessage(ctx, s.principal.AccountID, m.UID); err != nil {
				return err
			}
			if err := s.untagged(fmt.Sprintf("%d EXPUNGE", i+1)); err != nil {
				return err
			}
			s.messages = append(s.messages[:i], s.messages[i+1:]...)
			found = true
			break
		}
		if !found {
			break
		}
	}
	return s.tagged(tag, "OK EXPUNGE completed")
}

func (s *session) cmdSearch(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	_ = ctx
	criteria, ok := parseSearchCriteria(arg)
	if !ok {
		return s.tagged(tag, "BAD SEARCH syntax")
	}
	var nums []uint32
	if byUID {
		nums = mail.MatchSearchUID(s.messages, criteria)
	} else {
		nums = mail.MatchSearch(s.messages, criteria)
	}
	if err := s.untagged(formatSearch(nums)); err != nil {
		return err
	}
	return s.tagged(tag, "OK SEARCH completed")
}

func (s *session) cmdStatus(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	name, fields, ok := parseStatusArg(arg)
	if !ok {
		return s.tagged(tag, "BAD STATUS syntax")
	}
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		return err
	}
	st, err := s.inbox.Status(ctx, s.principal.AccountID, mbox.ID)
	if err != nil {
		return err
	}
	if err := s.untagged(formatStatus(mbox.Name, fields, st)); err != nil {
		return err
	}
	return s.tagged(tag, "OK STATUS completed")
}

func (s *session) cmdCreate(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	_, err := s.inbox.CreateMailbox(ctx, s.principal.AccountID, parseMailboxName(arg))
	if err != nil {
		if errors.Is(err, mail.ErrMailboxExists) {
			return s.tagged(tag, "NO mailbox already exists")
		}
		return err
	}
	return s.tagged(tag, "OK CREATE completed")
}

func (s *session) cmdDelete(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, parseMailboxName(arg))
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		return err
	}
	if err := s.inbox.DeleteMailbox(ctx, s.principal.AccountID, mbox.ID); err != nil {
		if errors.Is(err, mail.ErrSystemMailbox) {
			return s.tagged(tag, "NO cannot delete system mailbox")
		}
		if errors.Is(err, mail.ErrMailboxNotEmpty) {
			return s.tagged(tag, "NO mailbox not empty")
		}
		return err
	}
	if s.selected && s.mbox.ID == mbox.ID {
		s.selected = false
		s.messages = nil
	}
	return s.tagged(tag, "OK DELETE completed")
}

func (s *session) cmdCopy(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	setStr, destName, ok := parseSeqSetAndMailbox(arg)
	if !ok {
		return s.tagged(tag, "BAD COPY syntax")
	}
	dest, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, destName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO [TRYCREATE] mailbox does not exist")
		}
		return err
	}
	set, err := parseSeqSet(setStr)
	if err != nil {
		return s.tagged(tag, "BAD COPY syntax")
	}
	ids := s.emailIDsFromIndices(s.resolveIndices(set, byUID))
	if _, err := s.inbox.CopyMessages(ctx, s.principal.AccountID, ids, dest.ID); err != nil {
		return err
	}
	return s.tagged(tag, "OK COPY completed")
}

func (s *session) cmdMove(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	setStr, destName, ok := parseSeqSetAndMailbox(arg)
	if !ok {
		return s.tagged(tag, "BAD MOVE syntax")
	}
	dest, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, destName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO [TRYCREATE] mailbox does not exist")
		}
		return err
	}
	set, err := parseSeqSet(setStr)
	if err != nil {
		return s.tagged(tag, "BAD MOVE syntax")
	}
	ids := s.emailIDsFromIndices(s.resolveIndices(set, byUID))
	if err := s.inbox.MoveMessages(ctx, s.principal.AccountID, ids, dest.ID); err != nil {
		return err
	}
	msgs, err := s.inbox.List(ctx, s.principal.AccountID, s.mbox.ID)
	if err != nil {
		return err
	}
	s.messages = msgs
	return s.tagged(tag, "OK MOVE completed")
}

func (s *session) emailIDsFromIndices(indices []int) []uint32 {
	ids := make([]uint32, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		ids = append(ids, s.messages[idx].UID)
	}
	return ids
}

func (s *session) resolveIndices(set seqSet, byUID bool) []int {
	if byUID {
		refs := make([]messageRef, len(s.messages))
		for i, m := range s.messages {
			refs[i] = messageRef{uid: m.UID}
		}
		return set.expandUID(refs)
	}
	seqs := set.expandSeq(uint32(len(s.messages)))
	out := make([]int, len(seqs))
	for i, seq := range seqs {
		out[i] = int(seq) - 1
	}
	return out
}

func (s *session) writeFetch(ctx context.Context, seq int, msg mail.Message, items fetchItems) error {
	needRaw := items.body || items.envelope || items.headerFields != nil
	var raw []byte
	if needRaw {
		var err error
		raw, err = s.inbox.LoadRaw(ctx, msg.Meta)
		if err != nil {
			return err
		}
	}

	var parts []string
	if items.uid {
		parts = append(parts, fmt.Sprintf("UID %d", msg.UID))
	}
	if items.flags {
		parts = append(parts, "FLAGS "+mail.FormatIMAPFlags(msg.Meta.Flags))
	}
	if items.size {
		parts = append(parts, fmt.Sprintf("RFC822.SIZE %d", msg.Meta.Size))
	}
	if items.envelope {
		parts = append(parts, "ENVELOPE "+formatEnvelope(raw))
	}

	hasLiteral := items.body || items.headerFields != nil
	if !hasLiteral {
		return s.untagged(fmt.Sprintf("%d FETCH (%s)", seq, strings.Join(parts, " ")))
	}

	if _, err := fmt.Fprintf(s.conn, "* %d FETCH (", seq); err != nil {
		return err
	}
	if len(parts) > 0 {
		if _, err := fmt.Fprintf(s.conn, "%s", strings.Join(parts, " ")); err != nil {
			return err
		}
	}
	sep := ""
	if len(parts) > 0 {
		sep = " "
	}
	if items.headerFields != nil {
		hdr := extractHeaderFields(raw, items.headerFields)
		if _, err := fmt.Fprintf(s.conn, "%s%s {%d}\r\n", sep, headerFieldsItemName(items.headerFields), len(hdr)); err != nil {
			return err
		}
		if _, err := s.conn.Write(hdr); err != nil {
			return err
		}
		sep = " "
	}
	if items.body {
		if _, err := fmt.Fprintf(s.conn, "%sBODY[] {%d}\r\n", sep, len(raw)); err != nil {
			return err
		}
		if _, err := s.conn.Write(raw); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(s.conn, ")\r\n")
	return err
}

func formatSearch(nums []uint32) string {
	if len(nums) == 0 {
		return "SEARCH"
	}
	parts := make([]string, len(nums))
	for i, n := range nums {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return "SEARCH " + strings.Join(parts, " ")
}

func formatListMailbox(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "INBOX"
	}
	return `"` + strings.ReplaceAll(name, `"`, `\"`) + `"`
}

func parseMailboxName(arg string) string {
	arg = strings.TrimSpace(arg)
	if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
		return arg[1 : len(arg)-1]
	}
	return arg
}

func splitCommand(arg string) (cmd, rest string) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return strings.ToUpper(arg), ""
	}
	return strings.ToUpper(strings.TrimSpace(arg[:i])), strings.TrimSpace(arg[i+1:])
}

func (s *session) continuation() error {
	_, err := fmt.Fprintf(s.conn, "+ Ready for additional command text\r\n")
	return err
}

// resolveOrCreateMailbox opens a folder, creating it when missing (IMAP clients often skip CREATE).
func (s *session) resolveOrCreateMailbox(ctx context.Context, name string) (mail.Mailbox, error) {
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, name)
	if errors.Is(err, storage.ErrNotFound) {
		mbox, err = s.inbox.CreateMailbox(ctx, s.principal.AccountID, name)
		if errors.Is(err, mail.ErrMailboxExists) {
			mbox, err = s.inbox.ResolveMailbox(ctx, s.principal.AccountID, name)
		}
	}
	return mbox, err
}

func (s *session) untagged(line string) error {
	_, err := fmt.Fprintf(s.conn, "* %s\r\n", line)
	return err
}

func (s *session) tagged(tag, resp string) error {
	_, err := fmt.Fprintf(s.conn, "%s %s\r\n", tag, resp)
	return err
}

func (s *session) readLine() (string, error) {
	line, err := s.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) > 8192 {
		return "", fmt.Errorf("imap: line too long")
	}
	return line, nil
}

func parseTagged(line string) (tag, cmd, arg string) {
	line = strings.TrimSpace(line)
	i := strings.IndexByte(line, ' ')
	if i < 0 {
		return "", strings.ToUpper(line), ""
	}
	tag = line[:i]
	rest := strings.TrimSpace(line[i+1:])
	j := strings.IndexByte(rest, ' ')
	if j < 0 {
		return tag, strings.ToUpper(rest), ""
	}
	return tag, strings.ToUpper(rest[:j]), strings.TrimSpace(rest[j+1:])
}

func parseLogin(arg string) (user, pass string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", false
	}
	if arg[0] == '"' {
		user, rest, found := parseQuoted(arg)
		if !found {
			return "", "", false
		}
		rest = strings.TrimSpace(rest)
		if rest == "" {
			return "", "", false
		}
		if rest[0] == '"' {
			pass, _, found = parseQuoted(rest)
			if !found {
				return "", "", false
			}
			return user, pass, true
		}
		return user, rest, true
	}
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return "", "", false
	}
	return arg[:i], strings.TrimSpace(arg[i+1:]), true
}

func parseQuoted(s string) (val, rest string, ok bool) {
	if len(s) < 2 || s[0] != '"' {
		return "", "", false
	}
	end := 1
	for end < len(s) {
		if s[end] == '\\' && end+1 < len(s) {
			end += 2
			continue
		}
		if s[end] == '"' {
			return s[1:end], strings.TrimSpace(s[end+1:]), true
		}
		end++
	}
	return "", "", false
}

type fetchItems struct {
	uid, flags, size, body, envelope bool
	headerFields                    []string // non-nil when HEADER.FIELDS was requested
}

func parseFetchArg(arg string) (setStr string, items fetchItems, ok bool) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		if _, err := strconv.ParseUint(arg, 10, 32); err != nil {
			return "", items, false
		}
		return arg, fetchItems{body: true}, true
	}
	setStr = strings.TrimSpace(arg[:i])
	items, ok = parseFetchItems(arg[i+1:])
	return setStr, items, ok
}

func parseFetchItems(rest string) (fetchItems, bool) {
	upper := strings.ToUpper(rest)
	var items fetchItems
	items.uid = strings.Contains(upper, "UID")
	items.flags = strings.Contains(upper, "FLAGS")
	items.size = strings.Contains(upper, "RFC822.SIZE")
	items.body = wantsFullBody(upper)
	items.envelope = strings.Contains(upper, "ENVELOPE")
	if fields, ok := parseHeaderFieldsFetch(rest); ok {
		items.headerFields = fields
	}
	if !items.uid && !items.flags && !items.size && !items.body && !items.envelope && items.headerFields == nil {
		return items, false
	}
	return items, true
}

func wantsFullBody(upper string) bool {
	if strings.Contains(upper, "RFC822") && !strings.Contains(upper, "RFC822.SIZE") && !strings.Contains(upper, "RFC822.HEADER") {
		return true
	}
	return strings.Contains(upper, "BODY[]") || strings.Contains(upper, "BODY.PEEK[]")
}

type storeMode int

const (
	storeSilent storeMode = iota
	storeAdd
	storeRemove
)

func parseStoreArg(arg string) (setStr string, mode storeMode, set, clear uint32, ok bool) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return "", storeSilent, 0, 0, false
	}
	setStr = strings.TrimSpace(arg[:i])
	mode, set, clear, ok = parseStoreFlags(strings.TrimSpace(arg[i+1:]))
	return setStr, mode, set, clear, ok
}

func parseStoreFlags(rest string) (mode storeMode, set, clear uint32, ok bool) {
	upper := strings.ToUpper(rest)
	switch {
	case strings.HasPrefix(upper, "+FLAGS.SILENT"):
		mode = storeAdd
		rest = strings.TrimSpace(rest[len("+FLAGS.SILENT"):])
	case strings.HasPrefix(upper, "+FLAGS"):
		mode = storeAdd
		rest = strings.TrimSpace(rest[len("+FLAGS"):])
	case strings.HasPrefix(upper, "-FLAGS.SILENT"):
		mode = storeRemove
		rest = strings.TrimSpace(rest[len("-FLAGS.SILENT"):])
	case strings.HasPrefix(upper, "-FLAGS"):
		mode = storeRemove
		rest = strings.TrimSpace(rest[len("-FLAGS"):])
	case strings.HasPrefix(upper, "FLAGS.SILENT"):
		mode = storeSilent
		rest = strings.TrimSpace(rest[len("FLAGS.SILENT"):])
	case strings.HasPrefix(upper, "FLAGS"):
		mode = storeSilent
		rest = strings.TrimSpace(rest[len("FLAGS"):])
	default:
		return storeSilent, 0, 0, false
	}
	bits, ok := parseIMAPFlagList(rest)
	if !ok {
		return storeSilent, 0, 0, false
	}
	switch mode {
	case storeAdd:
		set = bits
	case storeRemove:
		clear = bits
	case storeSilent:
		set = bits
		clear = ^uint32(0) &^ bits
	}
	return mode, set, clear, true
}

// parseIMAPFlagList parses a parenthesized or bare IMAP flag list into a bitset.
func parseIMAPFlagList(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, true
	}
	if s[0] == '(' {
		close := strings.IndexByte(s, ')')
		if close < 0 {
			return 0, false
		}
		s = strings.TrimSpace(s[1:close])
	}
	var bits uint32
	for _, f := range strings.Fields(s) {
		b, known := mail.ParseIMAPFlagName(f)
		if known && mail.IsStoreableFlag(b) {
			bits |= b
		}
	}
	return bits, true
}

func parseStatusArg(arg string) (name string, fields []string, ok bool) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return "", nil, false
	}
	name = parseMailboxName(strings.TrimSpace(arg[:i]))
	rest := strings.TrimSpace(arg[i+1:])
	if len(rest) < 2 || rest[0] != '(' || rest[len(rest)-1] != ')' {
		return "", nil, false
	}
	inner := strings.TrimSpace(rest[1 : len(rest)-1])
	if inner == "" {
		return "", nil, false
	}
	for _, f := range strings.Fields(strings.ToUpper(inner)) {
		switch f {
		case "MESSAGES", "UNSEEN", "UIDNEXT", "UIDVALIDITY":
			fields = append(fields, f)
		default:
			return "", nil, false
		}
	}
	if len(fields) == 0 {
		return "", nil, false
	}
	return name, fields, true
}

func formatStatus(name string, fields []string, st mail.MailboxStatus) string {
	parts := make([]string, 0, len(fields))
	for _, f := range fields {
		switch f {
		case "MESSAGES":
			parts = append(parts, fmt.Sprintf("MESSAGES %d", st.Messages))
		case "UNSEEN":
			parts = append(parts, fmt.Sprintf("UNSEEN %d", st.Unseen))
		case "UIDNEXT":
			parts = append(parts, fmt.Sprintf("UIDNEXT %d", st.UIDNext))
		case "UIDVALIDITY":
			parts = append(parts, fmt.Sprintf("UIDVALIDITY %d", st.UIDValidity))
		}
	}
	return fmt.Sprintf("STATUS %s (%s)", formatListMailbox(name), strings.Join(parts, " "))
}

func parseSeqSetAndMailbox(arg string) (setStr, mboxName string, ok bool) {
	arg = strings.TrimSpace(arg)
	i := strings.LastIndexByte(arg, ' ')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(arg[:i]), parseMailboxName(arg[i+1:]), true
}
