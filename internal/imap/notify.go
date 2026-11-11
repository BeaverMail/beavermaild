// IMAP NOTIFY (RFC 5465): events pushed while no command is running.
package imap

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/mail"
)

// notifyPollInterval is how often a NOTIFY session looks for changes between commands.
const notifyPollInterval = time.Second

// notifySupportedEvents is the BADEVENT list (RFC 5465 3.1): no ANNOTATE, no METADATA.
const notifySupportedEvents = "MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange"

type notifyEvents struct {
	messageNew, messageExpunge, flagChange bool
	mailboxName, subscriptionChange        bool
	newFetch                               *fetchItems // MessageNew (fetch-att ...) for the selected mailbox
}

func (e notifyEvents) messages() bool { return e.messageNew || e.messageExpunge || e.flagChange }

// notifyGroup is one "(filter events)" of NOTIFY SET for mailboxes other than the selected one.
type notifyGroup struct {
	filter string   // PERSONAL, INBOXES, SUBSCRIBED, SUBTREE or MAILBOXES
	names  []string // for SUBTREE and MAILBOXES
	events notifyEvents
}

// notifyState is the session's NOTIFY setting and what it last reported.
type notifyState struct {
	selected        *notifyEvents // nil: no message events for the selected mailbox
	selectedDelayed bool          // SELECTED-DELAYED: selected-mailbox events wait for a command
	groups          []notifyGroup

	mboxes map[uint32]mail.Mailbox       // mailbox names, subscriptions and HIGHESTMODSEQ last seen
	status map[uint32]mail.MailboxStatus // last STATUS reported per watched mailbox
}

// errNotifyBadEvent marks a NOTIFY naming an event this server does not support.
var errNotifyBadEvent = errors.New("imap: unsupported NOTIFY event")

func (s *session) cmdNotify(ctx context.Context, tag, arg string) error {
	if s.principal.AccountID == 0 {
		return s.tagged(tag, "NO LOGIN required")
	}
	toks, ok := notifyTokens(arg)
	if !ok || len(toks) == 0 {
		return s.tagged(tag, "BAD NOTIFY syntax")
	}
	if strings.EqualFold(toks[0], "NONE") && len(toks) == 1 {
		s.notify = &notifyState{}
		return s.tagged(tag, "OK NOTIFY completed")
	}
	st, sendStatus, err := parseNotifySet(toks)
	if errors.Is(err, errNotifyBadEvent) {
		return s.tagged(tag, "NO [BADEVENT ("+notifySupportedEvents+")] unsupported event")
	}
	if err != nil {
		return s.tagged(tag, "BAD NOTIFY syntax")
	}
	mboxes, err := s.inbox.ListMailboxes(ctx, s.principal.AccountID)
	if err != nil {
		return err
	}
	st.mboxes = make(map[uint32]mail.Mailbox, len(mboxes))
	st.status = map[uint32]mail.MailboxStatus{}
	for _, mb := range mboxes {
		st.mboxes[mb.ID] = mb
		ev := st.eventsFor(mb, s.selectedID())
		if !ev.messages() {
			continue
		}
		fields := notifyStatusFields(ev, s.condstore)
		status, err := s.inbox.Status(ctx, s.principal.AccountID, mb.ID, fields)
		if err != nil {
			return err
		}
		st.status[mb.ID] = status
		if sendStatus {
			// What each event needs the client to start from (RFC 5465 3.1).
			initial := []string{"MESSAGES", "UIDNEXT", "UIDVALIDITY"}
			if ev.flagChange {
				initial = append(initial, "HIGHESTMODSEQ")
			}
			if err := s.untagged(formatStatus(mb.Name, initial, status)); err != nil {
				return err
			}
		}
	}
	s.notify = st
	// An implicit NOOP: the sync before the tagged reply reports the selected mailbox's changes.
	return s.tagged(tag, "OK NOTIFY completed")
}

// selectedID is the selected mailbox's ID, 0 when none.
func (s *session) selectedID() uint32 {
	if !s.selected {
		return 0
	}
	return s.mbox.ID
}

// eventsFor merges the events of every group matching mb. Message events never apply to the
// selected mailbox: SELECTED/SELECTED-DELAYED decide those (RFC 5465 3.1).
func (st *notifyState) eventsFor(mb mail.Mailbox, selectedID uint32) notifyEvents {
	var out notifyEvents
	for _, g := range st.groups {
		if !g.matches(mb) {
			continue
		}
		out.messageNew = out.messageNew || g.events.messageNew
		out.messageExpunge = out.messageExpunge || g.events.messageExpunge
		out.flagChange = out.flagChange || g.events.flagChange
		out.mailboxName = out.mailboxName || g.events.mailboxName
		out.subscriptionChange = out.subscriptionChange || g.events.subscriptionChange
	}
	if mb.ID == selectedID {
		out.messageNew, out.messageExpunge, out.flagChange = false, false, false
	}
	return out
}

func (g notifyGroup) matches(mb mail.Mailbox) bool {
	switch g.filter {
	case "PERSONAL", "INBOXES": // every mailbox can receive mail here (RFC 5465 6.3)
		return true
	case "SUBSCRIBED":
		return mb.Subscribed
	}
	for _, n := range g.names {
		if sameMailboxName(mb.Name, n) || g.filter == "SUBTREE" && hasMailboxPrefix(mb.Name, n+"/") {
			return true
		}
	}
	return false
}

// sameMailboxName compares names, INBOX case-insensitively (RFC 3501 5.1).
func sameMailboxName(a, b string) bool {
	if strings.EqualFold(a, "INBOX") {
		return strings.EqualFold(b, "INBOX")
	}
	return a == b
}

func hasMailboxPrefix(name, prefix string) bool {
	if len(prefix) >= 6 && strings.EqualFold(prefix[:6], "INBOX/") {
		return len(name) >= len(prefix) && strings.EqualFold(name[:6], "INBOX/") && name[6:len(prefix)] == prefix[6:]
	}
	return strings.HasPrefix(name, prefix)
}

// notifyStatusFields are the STATUS items a watched mailbox's changes are reported with.
func notifyStatusFields(ev notifyEvents, condstore bool) []string {
	fields := []string{"MESSAGES", "UIDNEXT", "UIDVALIDITY", "HIGHESTMODSEQ"}
	if ev.flagChange && !condstore {
		fields = append(fields, "UNSEEN") // the only flag change a non-CONDSTORE client can see
	}
	return fields
}

// waitCommand waits for the next command, sending NOTIFY events while the client is quiet.
// Peek never consumes input, so a command arriving between polls is read whole afterwards.
func (s *session) waitCommand(ctx context.Context) error {
	if s.notify == nil || (s.notify.selected == nil && len(s.notify.groups) == 0) {
		return nil
	}
	started := time.Now()
	defer func() { _ = s.conn.SetReadDeadline(time.Time{}) }()
	for s.r.Buffered() == 0 {
		if s.readTimeout > 0 && time.Since(started) > s.readTimeout {
			return fmt.Errorf("imap: no command for %s", s.readTimeout)
		}
		if s.isStopping() {
			return nil // readLine reports the shutdown
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(notifyPollInterval))
		_, err := s.r.Peek(1)
		if err == nil {
			return nil
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return err
		}
		if err := s.notifyPoll(ctx, false); err != nil {
			return err
		}
	}
	return nil
}

// notifyPoll sends the events NOTIFY asked for. inIdle allows SELECTED-DELAYED events too: IDLE
// may report expunges (RFC 5465 6.1.2).
func (s *session) notifyPoll(ctx context.Context, inIdle bool) error {
	st := s.notify
	if s.selected && st.selected != nil && (inIdle || !st.selectedDelayed) {
		if err := s.pushSelectedNotify(ctx, st.selected); err != nil {
			return err
		}
	}
	if len(st.groups) == 0 {
		return nil
	}
	mboxes, err := s.inbox.ListMailboxes(ctx, s.principal.AccountID)
	if err != nil {
		return err
	}
	names := make([]string, len(mboxes))
	seen := make(map[uint32]bool, len(mboxes))
	for i, mb := range mboxes {
		names[i] = mb.Name
	}
	for _, mb := range mboxes {
		seen[mb.ID] = true
		old, known := st.mboxes[mb.ID]
		ev := st.eventsFor(mb, s.selectedID())
		oldEv := st.eventsFor(old, s.selectedID())
		switch {
		case !known && ev.mailboxName:
			if err := s.untagged(fmt.Sprintf(`LIST (%s) "/" %s`, listMailboxAttrs(mb, names, true), formatListMailbox(mb.Name))); err != nil {
				return err
			}
		case known && old.Name != mb.Name && (ev.mailboxName || oldEv.mailboxName):
			if err := s.untagged(fmt.Sprintf(`LIST (%s) "/" %s ("OLDNAME" (%s))`, listMailboxAttrs(mb, names, true), formatListMailbox(mb.Name), formatListMailbox(old.Name))); err != nil {
				return err
			}
		case known && old.Subscribed != mb.Subscribed && ev.subscriptionChange:
			if err := s.untagged(fmt.Sprintf(`LIST (%s) "/" %s`, listMailboxAttrs(mb, names, true), formatListMailbox(mb.Name))); err != nil {
				return err
			}
		}
		if ev.messages() && (!known || old.HighestModSeq != mb.HighestModSeq) {
			if err := s.notifyMailboxStatus(ctx, mb, ev); err != nil {
				return err
			}
		}
		st.mboxes[mb.ID] = mb
	}
	for id, old := range st.mboxes {
		if seen[id] {
			continue
		}
		delete(st.mboxes, id)
		delete(st.status, id)
		if st.eventsFor(old, 0).mailboxName {
			if err := s.untagged(fmt.Sprintf(`LIST (\NonExistent) "/" %s`, formatListMailbox(old.Name))); err != nil {
				return err
			}
		}
	}
	return nil
}

// notifyMailboxStatus reports a watched mailbox's change with the STATUS items RFC 5465 5.1-5.3
// ask for, and nothing when the change is not one the client watches.
func (s *session) notifyMailboxStatus(ctx context.Context, mb mail.Mailbox, ev notifyEvents) error {
	st := s.notify
	cur, err := s.inbox.Status(ctx, s.principal.AccountID, mb.ID, notifyStatusFields(ev, s.condstore))
	if err != nil {
		return err
	}
	prev, had := st.status[mb.ID]
	st.status[mb.ID] = cur
	var fields []string
	switch {
	case had && prev.UIDValidity != cur.UIDValidity:
		fields = []string{"MESSAGES", "UIDNEXT", "UIDVALIDITY"}
	case (ev.messageNew || ev.messageExpunge) && (!had || prev.Messages != cur.Messages || prev.UIDNext != cur.UIDNext):
		fields = []string{"MESSAGES", "UIDNEXT"}
	case ev.flagChange && s.condstore:
		fields = []string{"HIGHESTMODSEQ", "UIDVALIDITY"}
	case ev.flagChange && had && prev.Unseen != cur.Unseen:
		fields = []string{"UNSEEN"}
	default:
		return nil
	}
	if s.condstore && fields[0] != "HIGHESTMODSEQ" {
		fields = append(fields, "HIGHESTMODSEQ")
	}
	return s.untagged(formatStatus(mb.Name, fields, cur))
}

// pushSelectedNotify reports the selected mailbox's changes, then the FETCH items MessageNew
// asked for on each new message (RFC 5465 5.2).
func (s *session) pushSelectedNotify(ctx context.Context, ev *notifyEvents) error {
	known := make(map[uint32]bool, len(s.messages))
	for _, m := range s.messages {
		known[m.UID] = true
	}
	if err := s.pushIdleMailboxChanges(ctx); err != nil {
		return err
	}
	if ev.newFetch == nil {
		return nil
	}
	for i, m := range s.messages {
		if known[m.UID] {
			continue
		}
		if err := s.writeFetch(ctx, i+1, m, *ev.newFetch, false); err != nil {
			return err
		}
	}
	return nil
}

// notifyResync takes the current mailbox list as seen, so this session's own CREATE, DELETE,
// RENAME and (UN)SUBSCRIBE are not reported back to it (RFC 5465 5: SHOULD omit).
func (s *session) notifyResync(ctx context.Context) error {
	if s.notify == nil || len(s.notify.groups) == 0 {
		return nil
	}
	mboxes, err := s.inbox.ListMailboxes(ctx, s.principal.AccountID)
	if err != nil {
		return err
	}
	fresh := make(map[uint32]mail.Mailbox, len(mboxes))
	for _, mb := range mboxes {
		old, ok := s.notify.mboxes[mb.ID]
		if ok {
			mb.HighestModSeq = old.HighestModSeq // message changes are still reported
		}
		fresh[mb.ID] = mb
	}
	s.notify.mboxes = fresh
	return nil
}

// parseNotifySet parses "SET [STATUS] event-group..." (RFC 5465 8).
func parseNotifySet(toks []string) (*notifyState, bool, error) {
	if !strings.EqualFold(toks[0], "SET") {
		return nil, false, errors.New("imap: NOTIFY needs SET or NONE")
	}
	toks = toks[1:]
	sendStatus := len(toks) > 0 && strings.EqualFold(toks[0], "STATUS")
	if sendStatus {
		toks = toks[1:]
	}
	st := &notifyState{}
	var badEvent bool
	for len(toks) > 0 {
		if toks[0] != "(" {
			return nil, false, errors.New("imap: NOTIFY event-group")
		}
		toks = toks[1:]
		if len(toks) == 0 {
			return nil, false, errors.New("imap: NOTIFY filter")
		}
		filter := strings.ToUpper(toks[0])
		toks = toks[1:]
		var names []string
		switch filter {
		case "SELECTED", "SELECTED-DELAYED", "PERSONAL", "INBOXES", "SUBSCRIBED":
		case "SUBTREE", "MAILBOXES":
			var ok bool
			if names, toks, ok = notifyMailboxList(toks); !ok {
				return nil, false, errors.New("imap: NOTIFY mailboxes")
			}
		default:
			return nil, false, errors.New("imap: NOTIFY filter")
		}
		ev, rest, bad, err := parseNotifyEvents(toks)
		if err != nil {
			return nil, false, err
		}
		badEvent = badEvent || bad
		if len(rest) == 0 || rest[0] != ")" {
			return nil, false, errors.New("imap: NOTIFY event-group end")
		}
		toks = rest[1:]
		// MessageNew and MessageExpunge go together; FlagChange needs both (RFC 5465 5).
		if ev.messageNew != ev.messageExpunge || ev.flagChange && !ev.messageNew {
			return nil, false, errors.New("imap: NOTIFY message events")
		}
		if strings.HasPrefix(filter, "SELECTED") {
			// One selected filter, with message events only (RFC 5465 6.1).
			if st.selected != nil || ev.mailboxName || ev.subscriptionChange {
				return nil, false, errors.New("imap: NOTIFY selected")
			}
			st.selected, st.selectedDelayed = &ev, filter == "SELECTED-DELAYED"
			continue
		}
		st.groups = append(st.groups, notifyGroup{filter: filter, names: names, events: ev})
	}
	if badEvent {
		return nil, false, errNotifyBadEvent // syntax first: a BAD outranks a NO
	}
	if st.selected != nil && !st.selected.messages() {
		st.selected = nil // SELECTED NONE
	}
	return st, sendStatus, nil
}

// parseNotifyEvents parses "NONE" or "(event ...)". bad reports an unsupported event name.
func parseNotifyEvents(toks []string) (ev notifyEvents, rest []string, bad bool, err error) {
	if len(toks) > 0 && strings.EqualFold(toks[0], "NONE") {
		return ev, toks[1:], false, nil
	}
	if len(toks) == 0 || toks[0] != "(" {
		return ev, nil, false, errors.New("imap: NOTIFY events")
	}
	toks = toks[1:]
	for len(toks) > 0 && toks[0] != ")" {
		name := strings.ToUpper(toks[0])
		toks = toks[1:]
		switch name {
		case "MESSAGENEW":
			ev.messageNew = true
			if len(toks) > 0 && toks[0] == "(" {
				end := closeToken(toks)
				if end < 0 {
					return ev, nil, false, errors.New("imap: NOTIFY fetch-att")
				}
				items, ok := parseFetchItems(strings.Join(toks[1:end], " "))
				if !ok {
					return ev, nil, false, errors.New("imap: NOTIFY fetch-att")
				}
				ev.newFetch, toks = &items, toks[end+1:]
			}
		case "MESSAGEEXPUNGE":
			ev.messageExpunge = true
		case "FLAGCHANGE":
			ev.flagChange = true
		case "MAILBOXNAME":
			ev.mailboxName = true
		case "SUBSCRIPTIONCHANGE":
			ev.subscriptionChange = true
		case "(", "":
			return ev, nil, false, errors.New("imap: NOTIFY event")
		default: // AnnotationChange, the METADATA events, extensions
			bad = true
		}
	}
	if len(toks) == 0 {
		return ev, nil, false, errors.New("imap: NOTIFY events end")
	}
	return ev, toks[1:], bad, nil
}

// notifyMailboxList parses one mailbox or a parenthesized list of them.
func notifyMailboxList(toks []string) (names, rest []string, ok bool) {
	if len(toks) == 0 || toks[0] == ")" {
		return nil, nil, false
	}
	if toks[0] != "(" {
		return toks[:1], toks[1:], true
	}
	end := closeToken(toks)
	if end < 2 {
		return nil, nil, false
	}
	for _, n := range toks[1:end] {
		if n == "(" || n == ")" {
			return nil, nil, false
		}
	}
	return toks[1:end], toks[end+1:], true
}

// closeToken returns the index of the ")" closing toks[0] == "(", or -1.
func closeToken(toks []string) int {
	depth := 0
	for i, t := range toks {
		switch t {
		case "(":
			depth++
		case ")":
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// notifyTokens splits NOTIFY arguments into "(", ")", quoted strings, literals and atoms. An atom
// keeps a bracketed section whole, so BODY.PEEK[HEADER.FIELDS (FROM)] stays one fetch-att.
func notifyTokens(arg string) ([]string, bool) {
	var toks []string
	for {
		arg = strings.TrimLeft(arg, " ")
		if arg == "" {
			return toks, true
		}
		switch arg[0] {
		case '(', ')':
			toks, arg = append(toks, arg[:1]), arg[1:]
			continue
		case '"':
			v, rest, ok := cutQuotedString(arg)
			if !ok {
				return nil, false
			}
			toks, arg = append(toks, v), rest
			continue
		case '{':
			v, rest, ok := cutLiteral(arg)
			if !ok {
				return nil, false
			}
			toks, arg = append(toks, v), rest
			continue
		}
		i, depth := 0, 0
		for ; i < len(arg); i++ {
			c := arg[i]
			if c == '[' {
				depth++
			} else if c == ']' && depth > 0 {
				depth--
			} else if depth == 0 && (c == ' ' || c == '(' || c == ')') {
				break
			}
		}
		toks, arg = append(toks, arg[:i]), arg[i:]
	}
}
