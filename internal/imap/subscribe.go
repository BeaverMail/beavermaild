// IMAP SUBSCRIBE, UNSUBSCRIBE, and LSUB commands.
package imap

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/BeaverMail/beavermaild/internal/storage"
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
	// selected reports whether a name meets the selection options. A missing parent of existing
	// folders is listed when nothing is selected (RFC 5258 5 example 11); a subscription whose folder
	// is gone only meets SUBSCRIBED; SPECIAL-USE takes existing folders only.
	selected := func(c listCandidate) bool {
		exists := !c.virtual && !c.nonexistent
		if opt.specialUseOnly && (!exists || specialUseAttr(c.mb) == "") {
			return false
		}
		if filterSubscribed {
			return c.mb.Subscribed
		}
		return exists || c.virtual
	}
	names := make([]string, len(mboxes))
	for i, mb := range mboxes {
		names[i] = mb.Name
	}
	parents := newParentSet(names)
	markSubscribed := filterSubscribed || opt.markSubscribed
	cands := listCandidates(mboxes)
	if markSubscribed {
		// A subscription outlives its folder (RFC 3501 6.3.4): LSUB and LIST (SUBSCRIBED) MUST list
		// it, and RETURN (SUBSCRIBED) MUST mark it, also when the name is a missing parent of folders.
		orphans, err := s.inbox.ListOrphanSubscriptions(ctx, s.principal.AccountID)
		if err != nil {
			return err
		}
		cands = addOrphanSubscriptions(cands, orphans)
	}
	// RFC 5258 §3 RECURSIVEMATCH and RFC 3501 §6.3.9 LSUB "%" both report parents of descendants
	// that meet the selection but not the pattern: collect those parents once.
	childInfoOf := parentSet{}
	if opt.recursiveMatch || cmd == "LSUB" {
		for _, d := range cands {
			if selected(d) && !match(d.mb.Name) {
				childInfoOf.addAncestors(d.mb.Name)
			}
		}
	}
	for _, c := range cands {
		if !match(c.mb.Name) {
			continue
		}
		childInfo := childInfoOf.has(c.mb.Name)
		if !selected(c) && !childInfo {
			continue
		}
		attrs := listMailboxAttrs(c.mb, parents, markSubscribed)
		switch {
		case c.nonexistent && cmd == "LSUB":
			attrs = `\Noselect`
		case c.nonexistent || c.virtual && opt.extended:
			// RFC 5258 3: \NonExistent implies \Noselect.
			attrs = childAttr(c.mb, parents) + ` \NonExistent`
			if markSubscribed && c.mb.Subscribed {
				attrs += ` \Subscribed`
			}
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
