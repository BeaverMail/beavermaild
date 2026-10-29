// ScanTargets lists on-disk message paths for account_scan dry-run jobs.
package pluginhost

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BeaverMail/beavermaild/internal/mail"
	"github.com/BeaverMail/beavermaild/internal/runtime"
)

// ScanTarget is one message blob to evaluate (mailbox + UID for reporting).
type ScanTarget struct {
	Mailbox  string
	UID      uint32
	BodyPath string
}

// ListAccountScanTargets returns readable RFC 5322 paths for account messages.
// Messages sharing the same blob hash are included once (first mailbox/uid wins).
func ListAccountScanTargets(ctx context.Context, stack *runtime.Stack, accountID uint32) (targets []ScanTarget, cleanup func(), err error) {
	boxes, err := stack.Inbox.ListMailboxes(ctx, accountID)
	if err != nil {
		return nil, nil, err
	}
	seenHash := make(map[string]struct{})
	var temps []string
	cleanup = func() {
		for _, p := range temps {
			_ = os.Remove(p)
		}
	}

	for _, box := range boxes {
		msgs, err := stack.Inbox.List(ctx, accountID, box.ID)
		if err != nil {
			cleanup()
			return nil, nil, err
		}
		for _, m := range msgs {
			path, temp, err := messageBodyPath(ctx, stack, m)
			if err != nil {
				cleanup()
				return nil, nil, fmt.Errorf("mailbox %s uid %d: %w", box.Name, m.UID, err)
			}
			if temp != "" {
				temps = append(temps, temp)
			}
			if m.Meta.HasBlob() {
				key := hex.EncodeToString(m.Meta.BlobHash[:])
				if _, ok := seenHash[key]; ok {
					continue
				}
				seenHash[key] = struct{}{}
			}
			targets = append(targets, ScanTarget{
				Mailbox:  box.Name,
				UID:      m.UID,
				BodyPath: path,
			})
		}
	}
	return targets, cleanup, nil
}

func messageBodyPath(ctx context.Context, stack *runtime.Stack, m mail.Message) (path, temp string, err error) {
	if m.Meta.HasBlob() {
		return stack.Blobs.Path(m.Meta.BlobHash), "", nil
	}
	raw, err := stack.Inbox.LoadRaw(ctx, m.Meta)
	if err != nil {
		return "", "", err
	}
	f, err := os.CreateTemp(filepath.Join(stack.Cfg.DataDir, "tmp"), "filter-scan-*.eml")
	if err != nil {
		return "", "", err
	}
	path = f.Name()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", "", err
	}
	return path, path, nil
}
