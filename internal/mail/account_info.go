// Account folder summaries and tree layout for operator diagnostics.
package mail

import (
	"context"
	"sort"
	"strings"

	"github.com/BeaverMail/beaver/internal/storage"
)

// MailboxSummary is one IMAP mailbox with its message total.
type MailboxSummary struct {
	ID       uint32
	Name     string
	Messages uint32
}

// FolderTreeLine is one row in a hierarchical folder listing.
type FolderTreeLine struct {
	Depth     int
	Segment   string
	Path      string
	Messages  uint32
	IsMailbox bool
}

// ListMailboxSummaries returns every mailbox for accountID with message counts.
func (ib *Inbox) ListMailboxSummaries(ctx context.Context, accountID uint32) ([]MailboxSummary, error) {
	mboxes, err := ib.ListMailboxes(ctx, accountID)
	if err != nil {
		return nil, err
	}
	counts, err := ib.countMessagesByMailbox(ctx, accountID)
	if err != nil {
		return nil, err
	}
	out := make([]MailboxSummary, len(mboxes))
	for i, mb := range mboxes {
		out[i] = MailboxSummary{
			ID:       mb.ID,
			Name:     mb.Name,
			Messages: counts[mb.ID],
		}
	}
	return out, nil
}

// BuildFolderTree turns flat mailbox summaries into depth-indented tree lines.
func BuildFolderTree(summaries []MailboxSummary) []FolderTreeLine {
	root := &folderNode{}
	for _, s := range summaries {
		insertFolderSummary(root, s)
	}
	var out []FolderTreeLine
	for _, child := range sortedFolderNodes(root.children) {
		appendFolderTreeLines(child, 0, &out)
	}
	return out
}

func (ib *Inbox) countMessagesByMailbox(ctx context.Context, accountID uint32) (map[uint32]uint32, error) {
	from := storage.AppendKeyPrefix(nil, storage.SubspaceMail, accountID, 0, byte(storage.CollectionEmail), 6)
	to := storage.AppendKey(nil, storage.SubspaceMail, accountID, ^uint32(0), byte(storage.CollectionEmail), nil)

	counts := make(map[uint32]uint32)
	err := ib.store.Iterate(ctx, from, to, func(k, v []byte) error {
		parts, err := storage.DecodeKey(k)
		if err != nil {
			return err
		}
		if parts.Collection != byte(storage.CollectionEmail) || len(parts.Suffix) > 0 {
			return nil
		}
		var meta storage.EmailMeta
		if err := storage.UnmarshalPersist(v, &meta); err != nil {
			return err
		}
		counts[meta.MailboxID]++
		return nil
	})
	if err != nil {
		return nil, err
	}
	return counts, nil
}

type folderNode struct {
	segment   string
	path      string
	mailboxID uint32
	messages  uint32
	isMailbox bool
	children  map[string]*folderNode
}

func insertFolderSummary(root *folderNode, s MailboxSummary) {
	parts := strings.Split(s.Name, "/")
	cur := root
	pathParts := make([]string, 0, len(parts))
	for i, seg := range parts {
		pathParts = append(pathParts, seg)
		key := strings.ToUpper(seg)
		if cur.children == nil {
			cur.children = make(map[string]*folderNode)
		}
		child, ok := cur.children[key]
		if !ok {
			child = &folderNode{segment: seg}
			cur.children[key] = child
		}
		if i == len(parts)-1 {
			child.path = s.Name
			child.mailboxID = s.ID
			child.messages = s.Messages
			child.isMailbox = true
			child.segment = leafSegment(s.Name)
		}
		cur = child
	}
}

func leafSegment(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

func appendFolderTreeLines(node *folderNode, depth int, out *[]FolderTreeLine) {
	if node.isMailbox {
		*out = append(*out, FolderTreeLine{
			Depth:     depth,
			Segment:   node.segment,
			Path:      node.path,
			Messages:  node.messages,
			IsMailbox: true,
		})
	}
	for _, child := range sortedFolderNodes(node.children) {
		childDepth := depth
		if node.isMailbox {
			childDepth++
		}
		appendFolderTreeLines(child, childDepth, out)
	}
}

func sortedFolderNodes(children map[string]*folderNode) []*folderNode {
	if len(children) == 0 {
		return nil
	}
	out := make([]*folderNode, 0, len(children))
	for _, n := range children {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		inboxI := strings.EqualFold(out[i].segment, "INBOX")
		inboxJ := strings.EqualFold(out[j].segment, "INBOX")
		if inboxI != inboxJ {
			return inboxI
		}
		return strings.ToUpper(out[i].segment) < strings.ToUpper(out[j].segment)
	})
	return out
}
