package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeaverMail/beaver/plugin"
)

func TestLoadMessageRawPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := filepath.Join(dir, "mail.eml")
	body := []byte("From: a@b.com\r\n\r\nx\r\n")
	if err := os.WriteFile(src, body, 0o644); err != nil {
		t.Fatal(err)
	}
	raw, cleanup, err := loadMessageRaw(plugin.BatchMessage{RawPath: src})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if string(raw) != string(body) {
		t.Fatalf("got %q", raw)
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatal("source file should remain")
	}
}

func TestLoadMessageRawTempRemoved(t *testing.T) {
	t.Parallel()
	path, err := plugin.WriteTempMessage([]byte("raw"))
	if err != nil {
		t.Fatal(err)
	}
	_, cleanup, err := loadMessageRaw(plugin.BatchMessage{RawPath: path})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("temp file should be removed")
	}
}

func TestLoadMessageRawB64(t *testing.T) {
	t.Parallel()
	raw, cleanup, err := loadMessageRaw(plugin.BatchMessage{RawB64: "aGVsbG8="})
	if err != nil {
		t.Fatal(err)
	}
	cleanup()
	if string(raw) != "hello" {
		t.Fatalf("got %q", raw)
	}
}

func TestIngesterDuplicateInBatch(t *testing.T) {
	t.Parallel()
	const hash = "ca2652657dd3a0cc831ccd68d5213585bb6eb7d407aec67197a0ed657118d94e"
	var skipLog bytes.Buffer
	ing := NewIngester(nil, 1, true, nil, IngesterOptions{Verbose: true, SkipLog: &skipLog})

	msgs := []plugin.BatchMessage{
		{IMAPName: "INBOX", RawB64: "aGVsbG8=", BlobHashHex: hash},
		{IMAPName: "Sent", RawB64: "aGVsbG8=", BlobHashHex: hash},
	}
	if err := ing.applyBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}

	res := ing.Result()
	if res.Imported != 1 || res.Skipped != 1 {
		t.Fatalf("imported=%d skipped=%d", res.Imported, res.Skipped)
	}
	if res.SkipBreakdown.DuplicateInBatch != 1 || res.SkipBreakdown.DuplicateInAccount != 0 {
		t.Fatalf("breakdown: %+v", res.SkipBreakdown)
	}
	mbox := res.ByMailbox["Sent"]
	if mbox.Skipped != 1 || mbox.SkipBreakdown.DuplicateInBatch != 1 {
		t.Fatalf("Sent: %+v", mbox)
	}
	line := skipLog.String()
	if !strings.Contains(line, "reason=duplicate_in_batch") || !strings.Contains(line, "first_imap=INBOX") {
		t.Fatalf("verbose skip log: %q", line)
	}
}

func TestIngesterDuplicateInAccount(t *testing.T) {
	t.Parallel()
	const hash = "deadbeef"
	preloaded := map[string]string{hash: "INBOX"}
	var skipLog bytes.Buffer
	ing := NewIngester(nil, 1, true, preloaded, IngesterOptions{Verbose: true, SkipLog: &skipLog})

	msgs := []plugin.BatchMessage{
		{IMAPName: "Spam", RawB64: "aGVsbG8=", BlobHashHex: hash},
	}
	if err := ing.applyBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}

	res := ing.Result()
	if res.Imported != 0 || res.Skipped != 1 {
		t.Fatalf("imported=%d skipped=%d", res.Imported, res.Skipped)
	}
	if res.SkipBreakdown.DuplicateInAccount != 1 || res.SkipBreakdown.DuplicateInBatch != 0 {
		t.Fatalf("breakdown: %+v", res.SkipBreakdown)
	}
	line := skipLog.String()
	if !strings.Contains(line, "reason=duplicate_in_account") || !strings.Contains(line, "existing_mailbox=INBOX") {
		t.Fatalf("verbose skip log: %q", line)
	}
}

func TestIngesterVerboseOffNoSkipLines(t *testing.T) {
	t.Parallel()
	const hash = "abc"
	preloaded := map[string]string{hash: "INBOX"}
	var skipLog bytes.Buffer
	ing := NewIngester(nil, 1, true, preloaded, IngesterOptions{SkipLog: &skipLog})

	msgs := []plugin.BatchMessage{
		{IMAPName: "Spam", RawB64: "aGVsbG8=", BlobHashHex: hash},
	}
	if err := ing.applyBatch(context.Background(), msgs); err != nil {
		t.Fatal(err)
	}
	if skipLog.Len() != 0 {
		t.Fatalf("expected no skip log without verbose, got %q", skipLog.String())
	}
}

func TestFormatJobTotalsLine(t *testing.T) {
	t.Parallel()
	line := formatJobTotalsLine(plugin.JobResult{
		Imported: 820,
		Skipped:  1,
		SkipBreakdown: plugin.SkipBreakdown{
			DuplicateInBatch: 1,
		},
	})
	want := "imported=820 skipped=1 errors=0 (duplicate_in_batch=1)"
	if line != want {
		t.Fatalf("got %q want %q", line, want)
	}
	line = formatJobTotalsLine(plugin.JobResult{Imported: 10, Skipped: 0})
	if line != "imported=10 skipped=0 errors=0" {
		t.Fatalf("got %q", line)
	}
}

func TestFormatMailboxTotalsLine(t *testing.T) {
	t.Parallel()
	line := formatMailboxTotalsLine("Spam", plugin.MailboxCounts{
		Imported: 627,
		Skipped:  1,
		SkipBreakdown: plugin.SkipBreakdown{
			DuplicateInBatch: 1,
		},
	})
	want := "  Spam: imported=627 skipped=1 errors=0 (duplicate_in_batch=1)"
	if line != want {
		t.Fatalf("got %q want %q", line, want)
	}
}
