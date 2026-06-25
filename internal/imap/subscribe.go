// IMAP SUBSCRIBE, UNSUBSCRIBE, and LSUB commands.
package imap

import (
	"context"
	"errors"
	"fmt"

	"github.com/BeaverMail/beaver/internal/storage"
)

// cmdSubscribe marks a mailbox as subscribed for LSUB.
func (s *session) cmdSubscribe(ctx context.Context, tag, arg string) error {
	name, err := mailboxNameFromArg(arg)
	if err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	if err := s.inbox.SetMailboxSubscribed(ctx, s.principal.AccountID, name, true); err != nil {
		return s.taggedSubscribeErr(tag, err)
	}
	return s.tagged(tag, "OK SUBSCRIBE completed")
}

// cmdUnsubscribe clears the subscription flag for a mailbox.
func (s *session) cmdUnsubscribe(ctx context.Context, tag, arg string) error {
	name, err := mailboxNameFromArg(arg)
	if err != nil {
		return s.tagged(tag, "BAD mailbox name syntax")
	}
	if err := s.inbox.SetMailboxSubscribed(ctx, s.principal.AccountID, name, false); err != nil {
		return s.taggedSubscribeErr(tag, err)
	}
	return s.tagged(tag, "OK UNSUBSCRIBE completed")
}

// cmdLsub lists subscribed mailboxes matching reference and pattern (RFC 3501).
func (s *session) cmdLsub(ctx context.Context, tag, arg string) error {
	return s.cmdMailboxList(ctx, tag, arg, "LSUB", true)
}

// cmdList returns all mailboxes matching reference and pattern.
func (s *session) cmdList(ctx context.Context, tag, arg string) error {
	return s.cmdMailboxList(ctx, tag, arg, "LIST", false)
}

func (s *session) cmdMailboxList(ctx context.Context, tag, arg, cmd string, subscribedOnly bool) error {
	ref, pattern, ok := parseListArg(arg)
	if !ok {
		return s.tagged(tag, "BAD "+cmd+" syntax")
	}
	if ref != "" && ref != "/" {
		if _, err := s.inbox.ResolveMailbox(ctx, s.principal.AccountID, ref); err != nil {
			return s.tagged(tag, "OK "+cmd+" completed")
		}
	}
	mboxes, err := s.inbox.ListMailboxes(ctx, s.principal.AccountID)
	if err != nil {
		return err
	}
	match := compileListPattern(pattern)
	for _, mb := range mboxes {
		if subscribedOnly && !mb.Subscribed {
			continue
		}
		if !match(mb.Name) {
			continue
		}
		line := fmt.Sprintf(`%s (%s) "/" %s`, cmd, listMailboxAttrs(mb.ID), formatListMailbox(mb.Name))
		if err := s.untagged(line); err != nil {
			return err
		}
	}
	return s.tagged(tag, "OK "+cmd+" completed")
}

func (s *session) taggedSubscribeErr(tag string, err error) error {
	if errors.Is(err, storage.ErrNotFound) {
		return s.tagged(tag, "NO mailbox does not exist")
	}
	return err
}
