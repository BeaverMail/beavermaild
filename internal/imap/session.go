// IMAP session state machine for one client connection.
package imap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/BeaverMail/beavermaild/internal/directory"
	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/security"
	"github.com/BeaverMail/beavermaild/internal/storage"
	"github.com/BeaverMail/beavermaild/internal/storage/blob"
	"github.com/BeaverMail/beavermaild/internal/tlsload"
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

	condstore bool

	principal   directory.Principal
	authGate    security.AuthGate
	readTimeout time.Duration
	selected    bool
	readOnly    bool
	mbox        mail.Mailbox
	messages    []mail.Message
	// recent holds the messages this session saw as \Recent when it selected the mailbox. SELECT
	// clears the flag in storage so no other session sees it, but this session keeps reporting it.
	recent   map[uint32]struct{} // EmailID set
	keywords map[string]struct{} // keywords announced in the last FLAGS response
	// syncCtx/syncPending: the running command reports other sessions' changes before its tagged reply.
	syncCtx         context.Context
	syncPending     bool
	lastCmd         string // command being run, for logs; never its arguments (LOGIN carries a password)
	lastTag         string
	idleWatchModSeq uint64       // mailbox HighestModSeq at last IDLE sync
	stopping        *atomic.Bool // server shutdown flag (nil when not served by a Server)
}

func newSession(log *slog.Logger, conn net.Conn, dir *directory.Local, inbox *mail.Inbox, certs *tlsload.Certs, secure, tlsRequired bool, gate security.AuthGate, readTimeout time.Duration) *session {
	if gate == nil {
		gate = security.NopGate{}
	}
	return &session{
		log:         log,
		conn:        conn,
		r:           bufio.NewReader(conn),
		dir:         dir,
		inbox:       inbox,
		tls:         certs,
		secure:      secure,
		tlsRequired: tlsRequired,
		authGate:    gate,
		readTimeout: readTimeout,
	}
}

func (s *session) run(ctx context.Context) error {
	if err := s.untagged("OK BeaverMail IMAP4rev1 ready"); err != nil {
		return err
	}
	for {
		err := s.serveCommands(ctx)
		if !errors.Is(err, mail.ErrContention) {
			return err
		}
		// Too many concurrent writers on the account: the command failed, the session goes on.
		s.syncPending = false
		s.log.Warn("imap command failed", append(s.logAttrs(), slog.Any("err", err))...)
		if err := s.tagged(s.lastTag, "NO [INUSE] Mailbox busy, try again"); err != nil {
			return err
		}
	}
}

// serveCommands reads and runs commands until the session ends or a command fails.
func (s *session) serveCommands(ctx context.Context) error {
	for {
		line, err := s.readLine()
		if err != nil {
			if s.isStopping() {
				_ = s.untagged("BYE [UNAVAILABLE] Server shutting down")
				return nil
			}
			return err
		}
		if line == "" {
			continue
		}
		tag, cmd, arg := parseTagged(line)
		if tag == "" {
			continue
		}
		if !validIMAPTag(tag) {
			if err := s.rejectBadTag(); err != nil {
				return err
			}
			continue
		}
		if takesSearchLiterals(cmd, arg) {
			var ok bool
			if arg, ok, err = s.readCommandLiterals(tag, arg); err != nil {
				return err
			} else if !ok {
				continue
			}
		}
		s.syncCtx, s.syncPending = ctx, syncsBeforeReply(cmd)
		s.lastCmd, s.lastTag = cmd, tag
		if cmd == "UID" {
			if sub, _, _ := strings.Cut(arg, " "); sub != "" {
				s.lastCmd += " " + strings.ToUpper(sub)
			}
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
			if err := s.finishAuth(ctx, tag, user, pass, "OK LOGIN completed"); err != nil {
				return err
			}
		case "AUTHENTICATE":
			if err := s.cmdAuthenticate(ctx, tag, arg); err != nil {
				return err
			}
		case "LIST":
			if s.principal.AccountID == 0 {
				if err := s.tagged(tag, "NO LOGIN required"); err != nil {
					return err
				}
				continue
			}
			if err := s.cmdList(ctx, tag, arg); err != nil {
				return err
			}
		case "LSUB":
			if s.principal.AccountID == 0 {
				if err := s.tagged(tag, "NO LOGIN required"); err != nil {
					return err
				}
				continue
			}
			if err := s.cmdLsub(ctx, tag, arg); err != nil {
				return err
			}
		case "SUBSCRIBE":
			if s.principal.AccountID == 0 {
				if err := s.tagged(tag, "NO LOGIN required"); err != nil {
					return err
				}
				continue
			}
			if err := s.cmdSubscribe(ctx, tag, arg); err != nil {
				return err
			}
		case "UNSUBSCRIBE":
			if s.principal.AccountID == 0 {
				if err := s.tagged(tag, "NO LOGIN required"); err != nil {
					return err
				}
				continue
			}
			if err := s.cmdUnsubscribe(ctx, tag, arg); err != nil {
				return err
			}
		case "SELECT":
			name, err := selectMailboxArg(arg)
			if err != nil {
				if err := s.tagged(tag, selectNameError(err)); err != nil {
					return err
				}
				continue
			}
			if err := s.openMailbox(ctx, tag, name, false); err != nil {
				return err
			}
		case "EXAMINE":
			name, err := selectMailboxArg(arg)
			if err != nil {
				if err := s.tagged(tag, selectNameError(err)); err != nil {
					return err
				}
				continue
			}
			if err := s.openMailbox(ctx, tag, name, true); err != nil {
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
		case "RENAME":
			if err := s.cmdRename(ctx, tag, arg); err != nil {
				return err
			}
		case "NAMESPACE":
			if err := s.cmdNamespace(tag); err != nil {
				return err
			}
		case "ENABLE":
			if err := s.cmdEnable(tag, arg); err != nil {
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
		case "CLOSE":
			if err := s.cmdClose(ctx, tag); err != nil {
				return err
			}
		case "UNSELECT":
			if err := s.cmdUnselect(tag); err != nil {
				return err
			}
		case "CHECK":
			if err := s.cmdCheck(tag); err != nil {
				return err
			}
		case "SEARCH":
			if err := s.cmdSearch(ctx, tag, arg, false); err != nil {
				return err
			}
		case "SORT":
			if err := s.cmdSort(ctx, tag, arg, false); err != nil {
				return err
			}
		case "THREAD":
			if err := s.cmdThread(ctx, tag, arg, false); err != nil {
				return err
			}
		case "GETQUOTA":
			if err := s.cmdGetQuota(ctx, tag, arg); err != nil {
				return err
			}
		case "GETQUOTAROOT":
			if err := s.cmdGetQuotaRoot(ctx, tag, arg); err != nil {
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
			case "SORT":
				if err := s.cmdSort(ctx, tag, rest, true); err != nil {
					return err
				}
			case "THREAD":
				if err := s.cmdThread(ctx, tag, rest, true); err != nil {
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
			case "EXPUNGE":
				if err := s.cmdUIDExpunge(ctx, tag, rest); err != nil {
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
		case "IDLE":
			if err := s.cmdIdle(ctx, tag); err != nil {
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
	caps := []string{"IMAP4rev1", "MOVE", "LITERAL+", "SASL-IR", "AUTH=PLAIN"}
	if s.tls != nil && !s.secure {
		caps = append(caps, "STARTTLS")
	}
	if s.tlsRequired && !s.secure {
		caps = append(caps, "LOGINDISABLED")
	}
	if s.principal.AccountID != 0 {
		caps = append(caps, "ENABLE", "IDLE", "NAMESPACE", "UIDPLUS", "UNSELECT", "SPECIAL-USE", "LIST-EXTENDED", "CONDSTORE", "SORT", "THREAD=REFERENCES", "QUOTA")
	}
	return "CAPABILITY " + strings.Join(caps, " ")
}

// finishAuth validates credentials and resets mailbox selection state.
func (s *session) finishAuth(ctx context.Context, tag, user, pass, resp string) error {
	ip := security.ClientIP(s.conn)
	if !s.authGate.AllowAuth(ip, user) {
		return s.tagged(tag, "NO [LIMIT] Too many login attempts, try again later")
	}
	p, err := s.dir.Authenticate(ctx, user, pass)
	if err != nil {
		if errors.Is(err, directory.ErrInvalidCredentials) || errors.Is(err, directory.ErrInactive) {
			// Only a wrong password counts toward the IP limit: a suspended client retrying with the right one
			// (often via a shared webmail IP) must not lock out everyone else.
			if errors.Is(err, directory.ErrInvalidCredentials) {
				s.authGate.RecordAuthFailure(ip, user)
			}
			return s.tagged(tag, "NO LOGIN failed")
		}
		return err
	}
	s.authGate.RecordAuthSuccess(ip, user)
	s.principal = p
	s.selected = false
	s.messages = nil
	s.idleWatchModSeq = 0
	s.condstore = true
	return s.tagged(tag, resp)
}

// cmdAuthenticate handles AUTHENTICATE PLAIN with optional SASL-IR initial response.
func (s *session) cmdAuthenticate(ctx context.Context, tag, arg string) error {
	if s.tlsRequired && !s.secure {
		return s.tagged(tag, "NO TLS required")
	}
	mech, initial := splitCommand(arg)
	if !strings.EqualFold(mech, "PLAIN") {
		return s.tagged(tag, "BAD unsupported mechanism")
	}
	cred := strings.TrimSpace(initial)
	if cred == "" {
		if err := s.continuation(); err != nil {
			return err
		}
		line, err := s.readLine()
		if err != nil {
			return err
		}
		cred = line
	}
	user, pass, ok := decodeAuthPlain(cred)
	if !ok {
		return s.tagged(tag, "BAD invalid credentials")
	}
	return s.finishAuth(ctx, tag, user, pass, "OK AUTHENTICATE completed")
}

// cmdNamespace returns the personal namespace for the logged-in account.
func (s *session) cmdNamespace(tag string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	if err := s.untagged(`NAMESPACE (("" "/")) NIL NIL`); err != nil {
		return err
	}
	return s.tagged(tag, "OK NAMESPACE completed")
}

// cmdRename renames a user mailbox and clears selection when the open folder is renamed.
func (s *session) cmdRename(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	oldName, newName, ok := parseRenameArg(arg)
	if !ok {
		return s.tagged(tag, "BAD RENAME syntax")
	}
	if err := mail.ValidateMailboxName(oldName); err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	if err := mail.ValidateMailboxName(newName); err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	renamed, err := s.inbox.RenameMailbox(ctx, s.principal.AccountID, oldName, newName)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		if errors.Is(err, mail.ErrMailboxExists) {
			return s.tagged(tag, "NO mailbox already exists")
		}
		if errors.Is(err, mail.ErrSystemMailbox) {
			return s.tagged(tag, "NO cannot rename mailbox")
		}
		return err
	}
	if s.selected && strings.EqualFold(s.mbox.Name, oldName) {
		s.mbox = renamed
	}
	return s.tagged(tag, "OK RENAME completed")
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
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		return err
	}
	msgs, err := s.inbox.List(ctx, s.principal.AccountID, mbox.ID)
	if err != nil {
		return err
	}
	// EXAMINE leaves \Recent alone; SELECT takes the recent messages for this session (RFC 3501).
	s.readOnly = examine
	s.recent = map[uint32]struct{}{}
	if err := s.claimRecent(ctx, mbox.ID, msgs); err != nil {
		return err
	}
	s.keepRecent(msgs)
	s.keywords = nil
	s.trackKeywords(msgs)
	recent := countRecentFlags(msgs)
	highest, err := s.inbox.HighestModSeq(ctx, s.principal.AccountID, mbox.ID)
	if err != nil {
		return err
	}
	uidNext, err := s.inbox.MailboxUIDNext(ctx, s.principal.AccountID, mbox.ID)
	if err != nil {
		return err
	}
	_, _, highestMod := mail.MailboxSelectState(msgs, highest)
	mbox.HighestModSeq = highestMod
	s.messages = msgs
	s.mbox = mbox
	s.selected = true
	s.idleWatchModSeq = highestMod
	if err := s.untagged(s.flagsLine()); err != nil {
		return err
	}
	if err := s.untagged(fmt.Sprintf("%d EXISTS", len(msgs))); err != nil {
		return err
	}
	if err := s.untagged(fmt.Sprintf("%d RECENT", recent)); err != nil {
		return err
	}
	// RFC 3501 resp-text carries one response code, so each goes on its own "* OK" line.
	okLines := []string{
		fmt.Sprintf("OK [UIDVALIDITY %d] UIDs valid", mbox.UIDValidity),
		fmt.Sprintf("OK [UIDNEXT %d] Predicted next UID", uidNext),
	}
	// UNSEEN is the sequence number of the first unseen message, omitted when all are seen.
	for i, m := range msgs {
		if m.Meta.Flags&mail.FlagSeen == 0 {
			okLines = append(okLines, fmt.Sprintf("OK [UNSEEN %d] First unseen", i+1))
			break
		}
	}
	if s.condstore {
		okLines = append(okLines, fmt.Sprintf("OK [HIGHESTMODSEQ %d] Highest", highestMod))
	}
	okLines = append(okLines, fmt.Sprintf("OK [PERMANENTFLAGS %s] Limited", mail.IMAPPermanentFlags))
	for _, line := range okLines {
		if err := s.untagged(line); err != nil {
			return err
		}
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
	gone := false
	for _, idx := range indices {
		if items.hasChangedSince && max(s.messages[idx].Meta.ModSeq, 1) <= items.changedSince {
			continue
		}
		msgItems, err := s.markSeenOnFetch(ctx, idx, items)
		if err != nil {
			return err
		}
		err = s.writeFetch(ctx, idx+1, s.messages[idx], msgItems, byUID)
		if errors.Is(err, storage.ErrNotFound) || errors.Is(err, blob.ErrNotFound) {
			gone = true // expunged by another session, body already removed
			continue
		}
		if err != nil {
			return err
		}
	}
	if gone {
		return s.tagged(tag, "NO Some of the requested messages no longer exist") // RFC 2180 4.1.2
	}
	return s.tagged(tag, "OK FETCH completed")
}

// markSeenOnFetch sets \Seen when a FETCH reads a body without PEEK (RFC 3501) and adds FLAGS to
// the response so the client learns about the change.
func (s *session) markSeenOnFetch(ctx context.Context, idx int, items fetchItems) (fetchItems, error) {
	msg := s.messages[idx]
	if s.readOnly || msg.Meta.Flags&mail.FlagSeen != 0 ||
		!slices.ContainsFunc(items.bodySections, func(bs bodySectionFetch) bool { return bs.setsSeen }) {
		return items, nil
	}
	_, meta, err := s.inbox.SetFlagsIfUnchanged(ctx, s.principal.AccountID, msg.StorageID(), mail.FlagSeen, 0, nil, nil, 0)
	if errors.Is(err, storage.ErrNotFound) {
		return items, nil // expunged by another session
	}
	if err != nil {
		return items, err
	}
	s.messages[idx].Meta = meta
	s.keepRecent(s.messages[idx : idx+1])
	items.flags = true
	return items, nil
}

func (s *session) cmdStore(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	if s.readOnly {
		return s.tagged(tag, "NO mailbox is read-only")
	}
	setStr, _, set, clear, kwAdd, kwRemove, silent, unchangedSince, hasUnchanged, ok := parseStoreArg(arg)
	if !ok {
		return s.tagged(tag, "BAD STORE syntax")
	}
	setParsed, err := parseSeqSet(setStr)
	if err != nil {
		return s.tagged(tag, "BAD STORE syntax")
	}
	indices := s.resolveIndices(setParsed, byUID)
	var failed []uint32
	for _, idx := range indices {
		msg := s.messages[idx]
		var unchanged uint64
		if hasUnchanged {
			unchanged = unchangedSince
		}
		applied, meta, err := s.inbox.SetFlagsIfUnchanged(ctx, s.principal.AccountID, msg.StorageID(), set, clear, kwAdd, kwRemove, unchanged)
		if errors.Is(err, storage.ErrNotFound) {
			continue // expunged by another session: its EXPUNGE comes with the next sync (RFC 2180 4.2)
		}
		if err != nil {
			return err
		}
		if !applied {
			failed = append(failed, s.seqsOrUIDs([]uint32{uint32(idx + 1)}, byUID)...)
			continue
		}
		s.messages[idx].Meta = meta
		s.keepRecent(s.messages[idx : idx+1])
		if err := s.announceKeywords(s.messages[idx : idx+1]); err != nil {
			return err
		}
		meta = s.messages[idx].Meta
		if !silent {
			line := fmt.Sprintf("%d FETCH (FLAGS %s", idx+1, mail.FormatMessageFlags(meta))
			if byUID {
				line = fmt.Sprintf("%d FETCH (UID %d FLAGS %s", idx+1, msg.UID, mail.FormatMessageFlags(meta))
			}
			if s.condstore {
				modSeq := meta.ModSeq
				if modSeq == 0 {
					modSeq = 1
				}
				line += " " + formatModSeq(modSeq)
			}
			line += ")"
			if err := s.untagged(line); err != nil {
				return err
			}
		}
	}
	if len(failed) > 0 {
		return s.tagged(tag, "OK [MODIFIED "+formatUIDSet(failed)+"] Conditional STORE failed")
	}
	return s.tagged(tag, "OK STORE completed")
}

func (s *session) cmdSearch(ctx context.Context, tag, arg string, byUID bool) error {
	if !s.selected {
		return s.tagged(tag, "NO not selected")
	}
	expr, st := parseSearchCommand(arg)
	switch st {
	case searchBadCharset:
		return s.tagged(tag, "NO [BADCHARSET ("+searchCharsets+")] charset not supported")
	case searchSyntaxError:
		return s.tagged(tag, "BAD SEARCH syntax")
	}
	w := s.watchCommand(ctx)
	load := mail.RawLoader(func(m mail.Message) ([]byte, error) {
		return s.inbox.LoadRaw(w.ctx, m.Meta)
	})
	seqs, _ := mail.MatchSearchExprContext(w.ctx, s.messages, expr, load)
	if cause := w.end(); cause != nil {
		return s.abortCommand(tag, cause)
	}
	resp := formatSearch(s.seqsOrUIDs(seqs, byUID)) + s.searchModSeqSuffix(&expr, seqs)
	if err := s.untagged(resp); err != nil {
		return err
	}
	return s.tagged(tag, "OK SEARCH completed")
}

// seqsOrUIDs maps 1-based sequence numbers to UIDs for the UID form of a command.
func (s *session) seqsOrUIDs(seqs []uint32, byUID bool) []uint32 {
	if !byUID {
		return seqs
	}
	out := make([]uint32, len(seqs))
	for i, seq := range seqs {
		out[i] = s.messages[seq-1].UID
	}
	return out
}

// searchModSeqSuffix returns " (MODSEQ n)" for a SEARCH/SORT response whose program used MODSEQ
// and matched something (RFC 7162 section 3.1.5), else "".
func (s *session) searchModSeqSuffix(expr *mail.SearchExpr, seqs []uint32) string {
	if len(seqs) == 0 || !expr.UsesModSeq() {
		return ""
	}
	return fmt.Sprintf(" (MODSEQ %d)", mail.HighestModSeq(s.messages, seqs))
}

func (s *session) cmdStatus(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	name, fields, ok := parseStatusArg(arg)
	if !ok {
		return s.tagged(tag, "BAD STATUS syntax")
	}
	if err := mail.ValidateMailboxName(name); err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, name)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return s.tagged(tag, "NO mailbox does not exist")
		}
		return err
	}
	st, err := s.inbox.Status(ctx, s.principal.AccountID, mbox.ID, fields)
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
	name, err := mailboxNameFromArg(arg)
	if err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	_, err = s.inbox.CreateMailbox(ctx, s.principal.AccountID, name, false)
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
	name, err := mailboxNameFromArg(arg)
	if err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	mbox, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, name)
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
		s.idleWatchModSeq = 0
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
	if err := mail.ValidateMailboxName(destName); err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
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
	srcUIDs := s.imapUIDsFromIndices(s.resolveIndices(set, byUID))
	_, destUIDs, err := s.inbox.CopyMessages(ctx, s.principal.AccountID, ids, dest.ID)
	if errors.Is(err, storage.ErrNotFound) {
		// Expunged by another session: nothing was copied (RFC 2180 4.4.1).
		return s.tagged(tag, "NO Some of the requested messages no longer exist")
	}
	if err != nil {
		return err
	}
	return s.tagged(tag, fmt.Sprintf("OK [%s] COPY completed", formatCopyUID(dest.UIDValidity, srcUIDs, destUIDs)))
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
	if err := mail.ValidateMailboxName(destName); err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
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
	indices := s.resolveIndices(set, byUID)
	ids := s.emailIDsFromIndices(indices)
	srcUIDs := s.imapUIDsFromIndices(indices)
	destUIDs, err := s.inbox.MoveMessages(ctx, s.principal.AccountID, ids, dest.ID)
	if errors.Is(err, storage.ErrNotFound) {
		// Expunged by another session: nothing was copied (RFC 2180 4.4.1).
		return s.tagged(tag, "NO Some of the requested messages no longer exist")
	}
	if err != nil {
		return err
	}
	// RFC 6851: COPYUID in an untagged OK, then an EXPUNGE per moved message. Highest sequence
	// number first, so the numbers still to send stay valid.
	if len(destUIDs) > 0 {
		if err := s.untagged(fmt.Sprintf("OK [%s] Moved UIDs", formatCopyUID(dest.UIDValidity, srcUIDs, destUIDs))); err != nil {
			return err
		}
	}
	slices.SortFunc(indices, func(a, b int) int { return b - a })
	for _, idx := range slices.Compact(indices) {
		if err := s.untagged(fmt.Sprintf("%d EXPUNGE", idx+1)); err != nil {
			return err
		}
		s.messages = slices.Delete(s.messages, idx, idx+1)
	}
	if dest.ID == s.mbox.ID {
		// Moved within the mailbox: the messages come back with new UIDs.
		msgs, err := s.inbox.List(ctx, s.principal.AccountID, s.mbox.ID)
		if err != nil {
			return err
		}
		if err := s.claimRecent(ctx, s.mbox.ID, msgs); err != nil {
			return err
		}
		s.keepRecent(msgs)
		if err := s.announceKeywords(msgs); err != nil {
			return err
		}
		s.messages = msgs
		if err := s.untagged(fmt.Sprintf("%d EXISTS", len(msgs))); err != nil {
			return err
		}
	}
	return s.tagged(tag, "OK MOVE completed")
}

// claimRecent takes for this session the messages of msgs still \Recent in storage. Only the
// session whose clear succeeds reports them, so a message is \Recent in one session at most.
func (s *session) claimRecent(ctx context.Context, mailboxID uint32, msgs []mail.Message) error {
	if s.readOnly {
		return nil
	}
	var ids []uint32
	for _, m := range msgs {
		if m.Meta.Flags&mail.FlagRecent != 0 {
			ids = append(ids, m.EmailID)
		}
	}
	claimed, err := s.inbox.ClearRecentFlagsOf(ctx, s.principal.AccountID, mailboxID, ids)
	for _, id := range claimed {
		s.recent[id] = struct{}{}
	}
	return err
}

// keepRecent makes \Recent on msgs, freshly loaded from storage, mean "taken by this session":
// the stored flag only says nobody took it yet. EXAMINE shows the stored flag.
func (s *session) keepRecent(msgs []mail.Message) {
	if s.readOnly {
		return
	}
	for i := range msgs {
		if _, ok := s.recent[msgs[i].EmailID]; ok {
			msgs[i].Meta.Flags |= mail.FlagRecent
		} else {
			msgs[i].Meta.Flags &^= mail.FlagRecent
		}
	}
}

// trackKeywords adds the keywords of msgs to the announced set and reports whether any was new.
func (s *session) trackKeywords(msgs []mail.Message) bool {
	if s.keywords == nil {
		s.keywords = map[string]struct{}{}
	}
	added := false
	for _, m := range msgs {
		for _, kw := range m.Meta.Keywords {
			if _, ok := s.keywords[kw]; !ok {
				s.keywords[kw] = struct{}{}
				added = true
			}
		}
	}
	return added
}

// announceKeywords sends FLAGS again when msgs carry a keyword the client was not told about:
// a client may reject a FETCH FLAGS with a keyword missing from the last FLAGS (RFC 3501 7.2.6).
func (s *session) announceKeywords(msgs []mail.Message) error {
	if !s.trackKeywords(msgs) {
		return nil
	}
	if err := s.untagged(s.flagsLine()); err != nil {
		return err
	}
	return s.untagged(fmt.Sprintf("OK [PERMANENTFLAGS %s] Limited", mail.IMAPPermanentFlags))
}

// flagsLine is the FLAGS response: the system flags plus the keywords in use in the mailbox.
func (s *session) flagsLine() string {
	kws := slices.Sorted(maps.Keys(s.keywords))
	if len(kws) == 0 {
		return mail.IMAPCapabilityFlags
	}
	return strings.TrimSuffix(mail.IMAPCapabilityFlags, ")") + " " + strings.Join(kws, " ") + ")"
}

func (s *session) emailIDsFromIndices(indices []int) []uint32 {
	ids := make([]uint32, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		ids = append(ids, s.messages[idx].StorageID())
	}
	return ids
}

func (s *session) imapUIDsFromIndices(indices []int) []uint32 {
	uids := make([]uint32, 0, len(indices))
	for _, idx := range indices {
		if idx < 0 || idx >= len(s.messages) {
			continue
		}
		uids = append(uids, s.messages[idx].UID)
	}
	return uids
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

func (s *session) writeFetch(ctx context.Context, seq int, msg mail.Message, items fetchItems, byUID bool) error {
	needRaw := len(items.bodySections) > 0 || items.envelope || items.bodystructure || items.body
	var raw []byte
	if needRaw {
		var err error
		raw, err = s.inbox.LoadRaw(ctx, msg.Meta)
		if err != nil {
			return err
		}
	}

	var parts []string
	if byUID || items.uid {
		parts = append(parts, fmt.Sprintf("UID %d", msg.UID))
	}
	if items.flags {
		parts = append(parts, "FLAGS "+mail.FormatMessageFlags(msg.Meta))
	}
	if items.size {
		parts = append(parts, fmt.Sprintf("RFC822.SIZE %d", msg.Meta.Size))
	}
	if items.envelope {
		parts = append(parts, "ENVELOPE "+formatEnvelope(raw))
	}
	if items.bodystructure {
		parts = append(parts, "BODYSTRUCTURE "+formatBodyStructure(raw))
	}
	if items.body {
		parts = append(parts, "BODY "+formatBody(raw))
	}
	if items.internalDate {
		parts = append(parts, "INTERNALDATE "+formatInternalDate(msg.Meta.ReceivedAt))
	}
	// MODSEQ only when requested, or on FLAGS-only UID sync (not with BODY literals; TB parser rejects that).
	flagsOnly := items.flags && !items.size && !items.envelope && !items.bodystructure && !items.body &&
		!items.internalDate && len(items.bodySections) == 0
	if s.condstore && (items.modseq || flagsOnly) {
		modSeq := msg.Meta.ModSeq
		if modSeq == 0 {
			modSeq = 1
		}
		parts = append(parts, formatModSeq(modSeq))
	}

	if len(items.bodySections) == 0 {
		return s.untagged(fmt.Sprintf("%d FETCH (%s)", seq, strings.Join(parts, " ")))
	}
	// One FETCH response per message, literals after the other items (as Dovecot/Gmail do):
	// a UID FETCH response must carry UID, so splitting the literals into a second response
	// left them without one and strict clients dropped the headers.
	return s.writeFetchWithLiterals(seq, parts, items.bodySections, raw)
}

// writeFetchWithLiterals emits one FETCH response: the plain items, then BODY section literals (PEEK omitted per RFC 3501).
func (s *session) writeFetchWithLiterals(seq int, parts []string, sections []bodySectionFetch, raw []byte) error {
	prefix := ""
	if len(parts) > 0 {
		prefix = strings.Join(parts, " ") + " "
	}
	if _, err := fmt.Fprintf(s.conn, "* %d FETCH (%s", seq, prefix); err != nil {
		return err
	}
	sep := ""
	for _, bs := range sections {
		data := bs.partialData(extractBodySection(raw, bs.section, bs.hdrFields))
		if _, err := fmt.Fprintf(s.conn, "%s%s {%d}\r\n", sep, bs.responseName(), len(data)); err != nil {
			return err
		}
		if _, err := s.conn.Write(data); err != nil {
			return err
		}
		sep = " "
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

// splitCommand splits off the first word. The rest keeps trailing bytes, which may belong to a literal.
func splitCommand(arg string) (cmd, rest string) {
	arg = strings.TrimLeft(arg, " ")
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return strings.ToUpper(strings.TrimSpace(arg)), ""
	}
	return strings.ToUpper(strings.TrimSpace(arg[:i])), strings.TrimLeft(arg[i+1:], " ")
}

func (s *session) continuation() error {
	_, err := fmt.Fprintf(s.conn, "+ Ready for additional command text\r\n")
	return err
}

func (s *session) untagged(line string) error {
	_, err := fmt.Fprintf(s.conn, "* %s\r\n", line)
	return err
}

func (s *session) tagged(tag, resp string) error {
	if s.syncPending {
		s.syncPending = false
		if s.selected {
			if err := s.pushIdleMailboxChanges(s.syncCtx); err != nil {
				return err
			}
		}
	}
	_, err := fmt.Fprintf(s.conn, "%s %s\r\n", tag, resp)
	return err
}

// syncsBeforeReply reports whether cmd reports the selected mailbox's changes (EXISTS, EXPUNGE,
// FLAGS) before its tagged reply. RFC 3501 7.4.1 forbids EXPUNGE during FETCH, STORE and SEARCH
// (not their UID forms); SELECT/EXAMINE load a fresh view and IDLE pushes its own updates.
func syncsBeforeReply(cmd string) bool {
	switch cmd {
	case "FETCH", "STORE", "SEARCH", "SORT", "THREAD", "SELECT", "EXAMINE", "IDLE", "LOGOUT", "CLOSE", "UNSELECT":
		return false
	}
	return true
}

func (s *session) isStopping() bool { return s.stopping != nil && s.stopping.Load() }

// bumpReadDeadline restores the idle timeout, or expires reads at once during shutdown.
func (s *session) bumpReadDeadline() {
	if s.isStopping() {
		_ = s.conn.SetReadDeadline(time.Now())
		return
	}
	if s.readTimeout > 0 {
		_ = s.conn.SetReadDeadline(time.Now().Add(s.readTimeout))
	}
}

func (s *session) readLine() (string, error) {
	s.bumpReadDeadline()
	return s.readLineNoDeadline()
}

// readLineNoDeadline reads one line under whatever read deadline the caller set.
func (s *session) readLineNoDeadline() (string, error) {
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
	var rest string
	if arg[0] == '"' {
		var found bool
		if user, rest, found = parseQuoted(arg); !found {
			return "", "", false
		}
		user = unescapeQuoted(user)
	} else {
		i := strings.IndexByte(arg, ' ')
		if i < 0 {
			return "", "", false
		}
		user, rest = arg[:i], arg[i+1:]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", false
	}
	// A quoted password is unquoted whatever the user form (clients send `alice "pass word"`).
	if rest[0] == '"' {
		pass, _, found := parseQuoted(rest)
		if !found {
			return "", "", false
		}
		return user, unescapeQuoted(pass), true
	}
	return user, rest, true
}

// unescapeQuoted resolves the \" and \\ escapes of an IMAP quoted string (RFC 3501 §4.3).
func unescapeQuoted(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
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
	uid, flags, size, envelope, bodystructure, body, internalDate, modseq bool
	bodySections                                                          []bodySectionFetch
	changedSince                                                          uint64
	hasChangedSince                                                       bool
}

func parseFetchArg(arg string) (setStr string, items fetchItems, ok bool) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		if _, err := strconv.ParseUint(arg, 10, 32); err != nil {
			return "", items, false
		}
		return arg, fetchItems{bodySections: []bodySectionFetch{{itemName: "BODY[]", section: ""}}}, true
	}
	setStr = strings.TrimSpace(arg[:i])
	rest, since, found, ok := parseChangedSince(arg[i+1:])
	if !ok {
		return "", items, false
	}
	items, ok = parseFetchItems(rest)
	if found {
		// CHANGEDSINCE implies MODSEQ in every response (RFC 7162 3.1.4.1).
		items.changedSince, items.hasChangedSince, items.modseq = since, true, true
	}
	return setStr, items, ok
}

func parseFetchItems(rest string) (fetchItems, bool) {
	upper := strings.ToUpper(rest)
	var items fetchItems
	// RFC 3501 macros, alone and without parentheses.
	switch strings.TrimSpace(upper) {
	case "FAST":
		return fetchItems{flags: true, internalDate: true, size: true}, true
	case "ALL":
		return fetchItems{flags: true, internalDate: true, size: true, envelope: true}, true
	case "FULL":
		return fetchItems{flags: true, internalDate: true, size: true, envelope: true, body: true}, true
	}
	// BODY alone is the non-extensible BODYSTRUCTURE; BODY[...] and BODY.PEEK[...] are sections.
	items.body = slices.Contains(strings.Fields(strings.NewReplacer("(", " ", ")", " ").Replace(upper)), "BODY")
	items.uid = strings.Contains(upper, "UID")
	items.flags = strings.Contains(upper, "FLAGS")
	items.size = strings.Contains(upper, "RFC822.SIZE")
	items.bodySections = parseAllBodyFetches(rest)
	items.envelope = strings.Contains(upper, "ENVELOPE")
	items.bodystructure = strings.Contains(upper, "BODYSTRUCTURE")
	items.internalDate = strings.Contains(upper, "INTERNALDATE")
	items.modseq = strings.Contains(upper, "MODSEQ")
	if !items.uid && !items.flags && !items.size && len(items.bodySections) == 0 && !items.envelope &&
		!items.bodystructure && !items.body && !items.internalDate && !items.modseq {
		return items, false
	}
	return items, true
}

type storeMode int

const (
	storeReplace storeMode = iota
	storeAdd
	storeRemove
)

func parseStoreArg(arg string) (setStr string, mode storeMode, set, clear uint32, kwAdd, kwRemove []string, silent bool, unchangedSince uint64, hasUnchanged bool, ok bool) {
	arg = strings.TrimSpace(arg)
	i := strings.IndexByte(arg, ' ')
	if i < 0 {
		return "", storeReplace, 0, 0, nil, nil, false, 0, false, false
	}
	setStr = strings.TrimSpace(arg[:i])
	rest := strings.TrimSpace(arg[i+1:])
	for {
		changed := false
		if us, rem, okUS := parseUnchangedSince(rest); okUS {
			unchangedSince, hasUnchanged = us, true
			rest = rem
			changed = true
		}
		if us, rem, okUS := parseTrailingUnchangedSince(rest); okUS {
			unchangedSince, hasUnchanged = us, true
			rest = rem
			changed = true
		}
		if !changed {
			break
		}
	}
	mode, set, clear, kwAdd, kwRemove, silent, ok = parseStoreFlags(rest)
	if !ok {
		return setStr, storeReplace, 0, 0, nil, nil, false, 0, false, false
	}
	return setStr, mode, set, clear, kwAdd, kwRemove, silent, unchangedSince, hasUnchanged, true
}

func parseStoreFlags(rest string) (mode storeMode, set, clear uint32, kwAdd, kwRemove []string, silent bool, ok bool) {
	upper := strings.ToUpper(rest)
	switch {
	case strings.HasPrefix(upper, "+FLAGS.SILENT"):
		mode = storeAdd
		silent = true
		rest = strings.TrimSpace(rest[len("+FLAGS.SILENT"):])
	case strings.HasPrefix(upper, "+FLAGS"):
		mode = storeAdd
		rest = strings.TrimSpace(rest[len("+FLAGS"):])
	case strings.HasPrefix(upper, "-FLAGS.SILENT"):
		mode = storeRemove
		silent = true
		rest = strings.TrimSpace(rest[len("-FLAGS.SILENT"):])
	case strings.HasPrefix(upper, "-FLAGS"):
		mode = storeRemove
		rest = strings.TrimSpace(rest[len("-FLAGS"):])
	case strings.HasPrefix(upper, "FLAGS.SILENT"):
		mode = storeReplace
		silent = true
		rest = strings.TrimSpace(rest[len("FLAGS.SILENT"):])
	case strings.HasPrefix(upper, "FLAGS"):
		mode = storeReplace
		rest = strings.TrimSpace(rest[len("FLAGS"):])
	default:
		return storeReplace, 0, 0, nil, nil, false, false
	}
	bits, kws, ok := parseIMAPFlagList(rest)
	if !ok {
		return storeReplace, 0, 0, nil, nil, false, false
	}
	switch mode {
	case storeAdd:
		set = bits
		kwAdd = kws
	case storeRemove:
		clear = bits
		kwRemove = kws
	case storeReplace:
		set = bits
		clear = mail.StoreableIMAPFlags &^ bits // \Recent is not the client's to change (RFC 3501)
		kwAdd = kws
		kwRemove = []string{mail.AllKeywords}
	}
	return mode, set, clear, kwAdd, kwRemove, silent, true
}

// parseIMAPFlagList parses an IMAP flag list into system flag bits and custom keywords.
func parseIMAPFlagList(s string) (uint32, []string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil, true
	}
	if s[0] == '(' {
		close := strings.IndexByte(s, ')')
		if close < 0 {
			return 0, nil, false
		}
		s = strings.TrimSpace(s[1:close])
	}
	var bits uint32
	var keywords []string
	for _, f := range strings.Fields(s) {
		if b, known := mail.ParseIMAPFlagName(f); known && mail.IsStoreableFlag(b) {
			bits |= b
			continue
		}
		if _, known := mail.ParseIMAPFlagName(f); known {
			continue
		}
		if kw := mail.NormalizeKeyword(f); kw != "" {
			keywords = append(keywords, kw)
		}
	}
	return bits, keywords, true
}

func parseStatusArg(arg string) (name string, fields []string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", nil, false
	}
	var rest string
	if arg[0] == '"' {
		var okQuote bool
		name, rest, okQuote = parseQuoted(arg)
		if !okQuote {
			return "", nil, false
		}
	} else {
		i := strings.IndexByte(arg, ' ')
		if i < 0 {
			return "", nil, false
		}
		name = parseMailboxName(strings.TrimSpace(arg[:i]))
		rest = strings.TrimSpace(arg[i+1:])
	}
	rest = strings.TrimSpace(rest)
	if len(rest) < 2 || rest[0] != '(' || rest[len(rest)-1] != ')' {
		return "", nil, false
	}
	inner := strings.TrimSpace(rest[1 : len(rest)-1])
	if inner == "" {
		return "", nil, false
	}
	for _, f := range strings.Fields(strings.ToUpper(inner)) {
		switch f {
		case "MESSAGES", "RECENT", "UNSEEN", "UIDNEXT", "UIDVALIDITY", "HIGHESTMODSEQ":
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
		case "RECENT":
			parts = append(parts, fmt.Sprintf("RECENT %d", st.Recent))
		case "UNSEEN":
			parts = append(parts, fmt.Sprintf("UNSEEN %d", st.Unseen))
		case "UIDNEXT":
			parts = append(parts, fmt.Sprintf("UIDNEXT %d", st.UIDNext))
		case "UIDVALIDITY":
			parts = append(parts, fmt.Sprintf("UIDVALIDITY %d", st.UIDValidity))
		case "HIGHESTMODSEQ":
			parts = append(parts, fmt.Sprintf("HIGHESTMODSEQ %d", st.HighestModSeq))
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

func parseRenameArg(arg string) (oldName, newName string, ok bool) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return "", "", false
	}
	var rest string
	if arg[0] == '"' {
		oldName, rest, ok = parseQuoted(arg)
		if !ok {
			return "", "", false
		}
	} else {
		i := strings.IndexByte(arg, ' ')
		if i < 0 {
			return "", "", false
		}
		oldName = arg[:i]
		rest = arg[i+1:]
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return "", "", false
	}
	if rest[0] == '"' {
		newName, tail, ok := parseQuoted(rest)
		if !ok || strings.TrimSpace(tail) != "" {
			return "", "", false
		}
		return oldName, newName, true
	}
	if strings.Contains(rest, " ") {
		return "", "", false
	}
	return oldName, rest, true
}
