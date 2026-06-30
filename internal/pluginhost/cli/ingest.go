// CLI plugin ingest applies JSONL batch events to the mail store.
package cli

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/BeaverMail/beaver/internal/pluginhost"
	"github.com/BeaverMail/beaver/plugin"
)

// Ingester applies plugin JSONL events to the mail store via the host mail adapter.
type Ingester struct {
	mail      *pluginhost.HostMail
	accountID uint32
	dryRun    bool
	known     map[string]struct{}
	mboxCache map[string]uint32
	touched   map[string]struct{}
	mboxStats map[string]*plugin.MailboxCounts
	imported  uint32
	skipped   uint32
	errors    uint32
}

// NewIngester builds an ingester for one account job.
func NewIngester(mail *pluginhost.HostMail, accountID uint32, dryRun bool, known map[string]struct{}) *Ingester {
	return &Ingester{
		mail:      mail,
		accountID: accountID,
		dryRun:    dryRun,
		known:     known,
		mboxCache: make(map[string]uint32),
		touched:   make(map[string]struct{}),
		mboxStats: make(map[string]*plugin.MailboxCounts),
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
		Imported:  g.imported,
		Skipped:   g.skipped,
		Errors:    g.errors,
		ByMailbox: byMailbox,
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
			g.skipped++
			g.noteMailbox(m.IMAPName, 0, 1, 0)
			continue
		}
		raw, cleanup, err := loadMessageRaw(m)
		if err != nil {
			g.errors++
			g.noteMailbox(m.IMAPName, 0, 0, 1)
			continue
		}
		if g.dryRun {
			cleanup()
			g.known[m.BlobHashHex] = struct{}{}
			g.imported++
			g.noteMailbox(m.IMAPName, 1, 0, 0)
			continue
		}
		mboxID, err := g.mailboxID(ctx, m.IMAPName)
		if err != nil {
			cleanup()
			return err
		}
		if err := g.mail.Append(ctx, g.accountID, mboxID, raw, m.Flags, m.ReceivedAt); err != nil {
			cleanup()
			g.errors++
			g.noteMailbox(m.IMAPName, 0, 0, 1)
			continue
		}
		cleanup()
		g.known[m.BlobHashHex] = struct{}{}
		g.imported++
		g.touched[m.IMAPName] = struct{}{}
		g.noteMailbox(m.IMAPName, 1, 0, 0)
	}
	return nil
}

func (g *Ingester) noteMailbox(name string, imported, skipped, errors uint32) {
	if name == "" {
		name = "INBOX"
	}
	c := g.mboxStats[name]
	if c == nil {
		c = &plugin.MailboxCounts{}
		g.mboxStats[name] = c
	}
	c.Imported += imported
	c.Skipped += skipped
	c.Errors += errors
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
