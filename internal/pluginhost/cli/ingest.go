// CLI plugin ingest applies JSONL batch events to the mail store.
package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/BeaverMail/beavermaild/internal/pluginhost"
	"github.com/BeaverMail/beavermaild/plugin"
)

// IngesterOptions configures optional ingest logging behavior.
type IngesterOptions struct {
	Verbose bool
	SkipLog io.Writer // stderr when nil
}

// Ingester applies plugin JSONL events to the mail store via the host mail adapter.
type Ingester struct {
	mail         *pluginhost.HostMail
	accountID    uint32
	dryRun       bool
	verbose      bool
	skipLog      io.Writer
	preloaded    map[string]string
	known        map[string]struct{}
	jobFirstIMAP map[string]string
	mboxCache    map[string]uint32
	touched      map[string]struct{}
	mboxStats    map[string]*plugin.MailboxCounts
	imported     uint32
	skipped      uint32
	errors       uint32
	skipBreakdown plugin.SkipBreakdown
}

// NewIngester builds an ingester for one account job.
func NewIngester(mail *pluginhost.HostMail, accountID uint32, dryRun bool, preloaded map[string]string, opts IngesterOptions) *Ingester {
	known := make(map[string]struct{}, len(preloaded))
	for hash := range preloaded {
		known[hash] = struct{}{}
	}
	skipLog := opts.SkipLog
	if skipLog == nil {
		skipLog = os.Stderr
	}
	return &Ingester{
		mail:         mail,
		accountID:    accountID,
		dryRun:       dryRun,
		verbose:      opts.Verbose,
		skipLog:      skipLog,
		preloaded:    preloaded,
		known:        known,
		jobFirstIMAP: make(map[string]string),
		mboxCache:    make(map[string]uint32),
		touched:      make(map[string]struct{}),
		mboxStats:    make(map[string]*plugin.MailboxCounts),
	}
}

// Apply handles one protocol event.
func (g *Ingester) Apply(ctx context.Context, ev plugin.CliEvent) (done bool, err error) {
	switch ev.Op {
	case plugin.CliOpBatch:
		if err := g.applyBatch(ctx, ev.Messages); err != nil {
			return false, err
		}
	case plugin.CliOpDone:
		return true, nil
	case plugin.CliOpError:
		return false, fmt.Errorf("plugin: %s", ev.Message)
	default:
		return false, fmt.Errorf("pluginhost: unknown op %q", ev.Op)
	}
	return false, nil
}

// Result returns counts accumulated during ingest.
func (g *Ingester) Result() plugin.JobResult {
	byMailbox := make(map[string]plugin.MailboxCounts, len(g.mboxStats))
	for name, c := range g.mboxStats {
		byMailbox[name] = *c
	}
	return plugin.JobResult{
		Imported:      g.imported,
		Skipped:       g.skipped,
		Errors:        g.errors,
		SkipBreakdown: g.skipBreakdown,
		ByMailbox:     byMailbox,
	}
}

// TouchedMailboxes returns IMAP names that received at least one appended message.
func (g *Ingester) TouchedMailboxes() []string {
	out := make([]string, 0, len(g.touched))
	for name := range g.touched {
		out = append(out, name)
	}
	return out
}

func (g *Ingester) applyBatch(ctx context.Context, msgs []plugin.BatchMessage) error {
	for _, m := range msgs {
		if _, ok := g.known[m.BlobHashHex]; ok {
			g.recordSkip(m)
			continue
		}
		raw, cleanup, err := loadMessageRaw(m)
		if err != nil {
			g.errors++
			g.noteMailbox(m.IMAPName, 0, 0, 1, plugin.SkipBreakdown{})
			continue
		}
		imapName := normalizeIMAPName(m.IMAPName)
		if g.dryRun {
			cleanup()
			g.markImported(m.BlobHashHex, imapName)
			g.imported++
			g.noteMailbox(imapName, 1, 0, 0, plugin.SkipBreakdown{})
			continue
		}
		mboxID, err := g.mailboxID(ctx, imapName)
		if err != nil {
			cleanup()
			return err
		}
		if err := g.mail.Append(ctx, g.accountID, mboxID, raw, m.Flags, m.ReceivedAt); err != nil {
			cleanup()
			g.errors++
			g.noteMailbox(imapName, 0, 0, 1, plugin.SkipBreakdown{})
			continue
		}
		cleanup()
		g.markImported(m.BlobHashHex, imapName)
		g.imported++
		g.touched[imapName] = struct{}{}
		g.noteMailbox(imapName, 1, 0, 0, plugin.SkipBreakdown{})
	}
	return nil
}

// recordSkip increments skip counters and optionally logs one verbose line.
func (g *Ingester) recordSkip(m plugin.BatchMessage) {
	g.skipped++
	imapName := normalizeIMAPName(m.IMAPName)
	if _, inAccount := g.preloaded[m.BlobHashHex]; inAccount {
		br := plugin.SkipBreakdown{DuplicateInAccount: 1}
		g.skipBreakdown.DuplicateInAccount++
		g.noteMailbox(imapName, 0, 1, 0, br)
		if g.verbose {
			fmt.Fprintf(g.skipLog, "skip: hash=%s imap=%s reason=duplicate_in_account existing_mailbox=%s\n",
				m.BlobHashHex, imapName, g.preloaded[m.BlobHashHex])
		}
		return
	}
	br := plugin.SkipBreakdown{DuplicateInBatch: 1}
	g.skipBreakdown.DuplicateInBatch++
	g.noteMailbox(imapName, 0, 1, 0, br)
	if g.verbose {
		fmt.Fprintf(g.skipLog, "skip: hash=%s imap=%s reason=duplicate_in_batch first_imap=%s\n",
			m.BlobHashHex, imapName, g.jobFirstIMAP[m.BlobHashHex])
	}
}

// markImported records hash dedup state after a successful import or dry-run append.
func (g *Ingester) markImported(hash, imapName string) {
	g.known[hash] = struct{}{}
	if _, ok := g.jobFirstIMAP[hash]; !ok {
		g.jobFirstIMAP[hash] = imapName
	}
}

func (g *Ingester) noteMailbox(name string, imported, skipped, errors uint32, skipBR plugin.SkipBreakdown) {
	name = normalizeIMAPName(name)
	c := g.mboxStats[name]
	if c == nil {
		c = &plugin.MailboxCounts{}
		g.mboxStats[name] = c
	}
	c.Imported += imported
	c.Skipped += skipped
	c.Errors += errors
	c.SkipBreakdown.DuplicateInAccount += skipBR.DuplicateInAccount
	c.SkipBreakdown.DuplicateInBatch += skipBR.DuplicateInBatch
}

func normalizeIMAPName(name string) string {
	if name == "" {
		return "INBOX"
	}
	return name
}

func loadMessageRaw(m plugin.BatchMessage) (raw []byte, cleanup func(), err error) {
	noCleanup := func() {}
	switch {
	case m.RawPath != "":
		raw, err = os.ReadFile(m.RawPath)
		if err != nil {
			return nil, noCleanup, err
		}
		if plugin.IsPluginTempPath(m.RawPath) {
			return raw, func() { _ = os.Remove(m.RawPath) }, nil
		}
		return raw, noCleanup, nil
	case m.RawB64 != "":
		raw, err = base64.StdEncoding.DecodeString(m.RawB64)
		if err != nil {
			return nil, noCleanup, err
		}
		return raw, noCleanup, nil
	default:
		return nil, noCleanup, fmt.Errorf("pluginhost: batch message missing raw_path and raw_b64")
	}
}

func (g *Ingester) mailboxID(ctx context.Context, imapName string) (uint32, error) {
	if id, ok := g.mboxCache[imapName]; ok {
		return id, nil
	}
	id, err := g.mail.ResolveMailbox(ctx, g.accountID, imapName)
	if err != nil {
		return 0, err
	}
	g.mboxCache[imapName] = id
	return id, nil
}
