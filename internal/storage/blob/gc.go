// Periodic removal of blob files no message or queue entry references.
package blob

import (
	"context"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BeaverMail/beavermaild/internal/storage"
)

// GCGrace is how old an unreferenced blob must be before GC removes it. Put refreshes the mtime
// of a blob it reuses, so a message being stored (blob written, row not yet committed) is never
// older than this unless its transaction hangs for longer.
const GCGrace = time.Hour

// gcInterval is how often RunGC collects.
const gcInterval = time.Hour

// RunGC collects unreferenced blobs every hour until ctx ends. Messages and queue entries drop
// their rows only; their files go here, after one reference scan instead of one per deletion.
func RunGC(ctx context.Context, log *slog.Logger, store storage.Store, fsys *FS) {
	t := time.NewTicker(gcInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		removed, err := GC(ctx, store, fsys, GCGrace)
		if err != nil {
			log.Warn("blob gc", slog.Any("err", err))
			continue
		}
		if removed > 0 {
			log.Info("blob gc", "removed", removed)
		}
	}
}

// GC removes blob files older than grace that no mail or queue row references, and temp files
// older than grace left by an interrupted Put. It returns how many files it removed.
func GC(ctx context.Context, store storage.Store, fsys *FS, grace time.Duration) (int, error) {
	cutoff := time.Now().Add(-grace)
	var candidates []string
	removed := 0
	// 1. Old files first: a blob written after this point is newer than cutoff and is skipped.
	err := filepath.WalkDir(fsys.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() {
			return ctx.Err()
		}
		info, err := d.Info()
		if err != nil || !info.ModTime().Before(cutoff) {
			return nil
		}
		if strings.HasPrefix(d.Name(), "put-") {
			if os.Remove(path) == nil {
				removed++
			}
			return nil
		}
		candidates = append(candidates, path)
		return nil
	})
	if err != nil || len(candidates) == 0 {
		return removed, err
	}
	// 2. One scan of every reference.
	refs, err := ReferencedHashes(ctx, store)
	if err != nil {
		return removed, err
	}
	// 3. Remove the unreferenced ones still old: Put refreshes the mtime of a blob it reuses.
	for _, path := range candidates {
		raw, err := hex.DecodeString(filepath.Base(path))
		if err != nil || len(raw) != storage.Blake3DigestLen {
			continue // not a blob file
		}
		if _, ok := refs[[storage.Blake3DigestLen]byte(raw)]; ok {
			continue
		}
		if info, err := os.Stat(path); err != nil || !info.ModTime().Before(cutoff) {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
