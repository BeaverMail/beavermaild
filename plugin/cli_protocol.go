package plugin

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
)

// Capability names declared in plugin Descriptor.
const (
	CapCLI  = "cli"
	CapSMTP = "smtp"
	CapWeb  = "web"
)

// CliRequest is the single JSON line the host writes to plugin stdin.
type CliRequest struct {
	APIVersion    uint32          `json:"api_version"`
	BeaverVersion string          `json:"beaver_version,omitempty"`
	Op            string          `json:"op"`
	AccountEmail  string          `json:"account_email"`
	DryRun        bool            `json:"dry_run"`
	Params        json.RawMessage `json:"params,omitempty"`
}

// BatchMessage is one message in a batch event.
// Provide raw bytes via raw_path (preferred) or raw_b64 (small messages only).
type BatchMessage struct {
	IMAPName    string `json:"imap_name"`
	RawPath     string `json:"raw_path,omitempty"`
	RawB64      string `json:"raw_b64,omitempty"`
	Flags       uint32 `json:"flags"`
	ReceivedAt  int64  `json:"received_at"`
	BlobHashHex string `json:"blob_hash_hex"`
}

// CliEvent is one JSONL line from plugin stdout.
type CliEvent struct {
	Op       string         `json:"op"`
	Messages []BatchMessage `json:"messages,omitempty"`
	Message  string         `json:"message,omitempty"`
}

const (
	CliOpBatch = "batch"
	CliOpDone  = "done"
	CliOpError = "error"
)

// MailboxCounts holds per-mailbox ingest totals for one CLI job.
type MailboxCounts struct {
	Imported uint32
	Skipped  uint32
	Errors   uint32
}

// JobResult summarizes a completed CLI job (host-side counts).
type JobResult struct {
	Imported  uint32
	Skipped   uint32
	Errors    uint32
	ByMailbox map[string]MailboxCounts
}

// ReadCliRequest decodes the request JSON line from r (typically stdin).
func ReadCliRequest(r io.Reader) (CliRequest, error) {
	sc := bufio.NewScanner(r)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return CliRequest{}, err
		}
		return CliRequest{}, fmt.Errorf("plugin: empty stdin request")
	}
	var req CliRequest
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		return CliRequest{}, fmt.Errorf("plugin: parse request: %w", err)
	}
	if req.APIVersion != 0 && req.APIVersion != APIVersion {
		return CliRequest{}, fmt.Errorf("plugin: API version mismatch host=%d plugin=%d", req.APIVersion, APIVersion)
	}
	return req, nil
}

// ParseCliEvent decodes one JSONL protocol line from the plugin.
func ParseCliEvent(line []byte) (CliEvent, error) {
	var ev CliEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return CliEvent{}, err
	}
	if ev.Op == "" {
		return CliEvent{}, fmt.Errorf("plugin: missing op")
	}
	return ev, nil
}

// BatchSizeFromEnv returns batch size from BEAVER_CLI_BATCH_SIZE or DefaultBatchSize.
func BatchSizeFromEnv() int {
	v := os.Getenv(EnvBatchSize)
	if v == "" {
		return DefaultBatchSize
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return DefaultBatchSize
	}
	return n
}
