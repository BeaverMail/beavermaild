package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIncludeScanRowOnlyNonHam(t *testing.T) {
	ham := filterResp{Action: "accept", Score: 1, Headers: map[string]string{"X-Spam-Status": "No, score=1.0"}}
	spam := filterResp{Action: "accept", Score: 7, Headers: map[string]string{"X-Spam-Flag": "YES", "X-Spam-Status": "Yes, score=7.0"}}
	if includeScanRow(ham, scanReportOpts{Only: "non-ham"}) {
		t.Fatal("ham excluded for non-ham")
	}
	if !includeScanRow(spam, scanReportOpts{Only: "non-ham"}) {
		t.Fatal("spam included for non-ham")
	}
}

func TestIncludeScanRowMinScore(t *testing.T) {
	low := filterResp{Action: "accept", Score: 2}
	high := filterResp{Action: "accept", Score: 8, Headers: map[string]string{"X-Spam-Flag": "YES", "X-Spam-Status": "Yes, score=8.0"}}
	opts := scanReportOpts{MinScore: 5}
	if includeScanRow(low, opts) {
		t.Fatal("low score excluded")
	}
	if !includeScanRow(high, opts) {
		t.Fatal("high score included")
	}
}

func TestParseMessageMeta(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "msg.eml")
	const raw = "From: Alice <alice@example.com>\r\n" +
		"To: Bob <bob@example.com>\r\n" +
		"Subject: Hello world\r\n" +
		"Date: Mon, 6 Jul 2026 10:00:00 +0000\r\n" +
		"Message-ID: <abc@example.com>\r\n" +
		"\r\n" +
		"First line of body.\r\nSecond line.\r\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}
	meta := parseMessageMeta(path)
	if meta.From != "alice@example.com" || meta.To != "bob@example.com" {
		t.Fatalf("addrs: from=%q to=%q", meta.From, meta.To)
	}
	if meta.Subject != "Hello world" || meta.MessageID != "abc@example.com" {
		t.Fatalf("subject/id: %q %q", meta.Subject, meta.MessageID)
	}
	if meta.Snippet == "" || len(meta.Snippet) > scanSnippetMax+1 {
		t.Fatalf("snippet=%q", meta.Snippet)
	}
}
