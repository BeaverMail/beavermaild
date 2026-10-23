// IMAP SUBSCRIBE, UNSUBSCRIBE, and LSUB commands.
package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	opt, ok := parseListOptions(arg)
	if !ok || (cmd == "LSUB" && opt.extended) {
		return s.tagged(tag, "BAD "+cmd+" syntax")
	}
	// RFC 3501 §6.3.8: an empty LIST pattern returns only the delimiter and the reference's root name.
	if cmd == "LIST" && !opt.extended && opt.patterns[0] == "" {
		root := ""
		if i := strings.IndexByte(opt.ref, '/'); i >= 0 {
			root = opt.ref[:i+1]
		}
		if err := s.untagged(`LIST (\Noselect) "/" ` + formatListMailbox(root)); err != nil {
			return err
		}
		return s.tagged(tag, "OK LIST completed")
	}
	// RFC 3501 §6.3.8: names are matched against reference and pattern joined; a bare "/" reference means the root.
	ref := opt.ref
	if ref == "/" {
		ref = ""
	}
	mboxes, err := s.inbox.ListMailboxes(ctx, s.principal.AccountID)
	if err != nil {
		return err
	}
	filterSubscribed := subscribedOnly || opt.subscribedOnly
	matchers := make([]func(string) bool, len(opt.patterns))
	for i, p := range opt.patterns {
		matchers[i] = compileListPattern(ref + p)
	}
	match := func(name string) bool {
		for _, m := range matchers {
			if m(name) {
				return true
			}
		}
		return false
	}
	var criteria []string
	if filterSubscribed {
		criteria = append(criteria, `"SUBSCRIBED"`)
	}
	if opt.specialUseOnly {
		criteria = append(criteria, `"SPECIAL-USE"`)
	}
	// selected reports whether a folder meets the selection options; missing parents meet none.
	selected := func(c listCandidate) bool {
		if c.virtual {
			return len(criteria) == 0
		}
		return (!filterSubscribed || c.mb.Subscribed) && (!opt.specialUseOnly || specialUseAttr(c.mb) != "")
	}
	names := make([]string, len(mboxes))
	for i, mb := range mboxes {
		names[i] = mb.Name
	}
	cands := listCandidates(mboxes)
	for _, c := range cands {
		if !match(c.mb.Name) {
			continue
		}
		// RFC 5258 §3 RECURSIVEMATCH and RFC 3501 §6.3.9 LSUB "%" both report parents of
		// descendants that meet the selection but not the pattern.
		childInfo := false
		if opt.recursiveMatch || cmd == "LSUB" {
			prefix := strings.ToUpper(c.mb.Name) + "/"
			for _, d := range cands {
				if strings.HasPrefix(strings.ToUpper(d.mb.Name), prefix) && selected(d) && !match(d.mb.Name) {
					childInfo = true
					break
				}
			}
		}
		if !selected(c) && !childInfo {
			continue
		}
		attrs := listMailboxAttrs(c.mb, names, filterSubscribed || opt.markSubscribed)
		switch {
		case c.virtual && opt.extended:
			// RFC 5258: \NonExistent implies \Noselect.
			attrs = `\HasChildren \NonExistent`
		case c.virtual, cmd == "LSUB" && !selected(c):
			attrs = `\HasChildren \Noselect`
		}
		line := fmt.Sprintf(`%s (%s) "/" %s`, cmd, attrs, formatListMailbox(c.mb.Name))
		if childInfo && opt.recursiveMatch {
			line += ` ("CHILDINFO" (` + strings.Join(criteria, " ") + `))`
		}
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
