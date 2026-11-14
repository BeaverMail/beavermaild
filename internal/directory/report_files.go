// Report ingest files under data_dir/domains/<id>/reports/<kind>/.
package directory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ReportMeta is the basic ingest metadata stored beside the raw report file.
// The report itself is never parsed at ingest: Format is only presumed.
// ReportLocalParts maps the per-domain report addresses (<local>@<domain>) to their report kind.
// SMTP stores mail to them as reports, so they can never be mailboxes.
var ReportLocalParts = map[string]string{
	"dmarc-reports": "dmarc",
	"tls-reports":   "tls",
}

type ReportMeta struct {
	Kind        string `json:"kind"`         // dmarc|tls
	From        string `json:"from"`         // envelope sender
	To          string `json:"to"`           // envelope recipient
	ReceivedAt  string `json:"received_at"`  // RFC3339
	ContentType string `json:"content_type"` // top-level media type ("" if unreadable)
	Format      string `json:"format"`       // presumed payload format: gzip|xml|json|unknown
	File        string `json:"file"`         // raw message file name
}

// Report store bounds per domain and kind. Anyone can mail dmarc-reports@ and tls-reports@ (RFC 9990
// 8.2): without a bound the store filled the disk. The oldest reports go first, so ingest never stops.
const (
	maxReportsPerKind     = 1000
	maxReportBytesPerKind = 256 << 20
)

// pruneReports deletes the oldest reports in dir (names sort by arrival time) past the bounds.
func pruneReports(dir string, maxCount int, maxBytes int64) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type rep struct {
		name string
		size int64
	}
	var reps []rep
	var total int64
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".eml") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue // removed meanwhile
		}
		reps = append(reps, rep{e.Name(), info.Size()})
		total += info.Size()
	}
	// ReadDir returns names sorted: oldest first.
	for i := 0; len(reps)-i > maxCount || (total > maxBytes && len(reps)-i > 1); i++ {
		base := strings.TrimSuffix(reps[i].name, ".eml")
		for _, f := range []string{base + ".eml", base + ".json", base + ".parsed.json"} {
			if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		total -= reps[i].size
	}
	return nil
}

// SaveDomainReport writes the raw (unparsed) report message plus its metadata under
// data_dir/domains/<id>/reports/<kind>/ and returns the raw file path.
func SaveDomainReport(dataDir string, domainID uint32, kind, from, to string, raw []byte) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("directory: report store: data dir not set")
	}
	if kind == "" {
		return "", fmt.Errorf("directory: report store: missing kind")
	}
	if len(raw) == 0 {
		return "", fmt.Errorf("directory: report store: empty message")
	}
	now := time.Now().UTC()
	sum := sha256.Sum256(raw)
	// The kind prefix keeps basenames unique across kinds: the same raw message
	// delivered to dmarc-reports@ and tls-reports@ in the same second would
	// otherwise share one Meta.File (the report list key).
	name := kind + "-" + now.Format("20060102T150405Z") + "-" + hex.EncodeToString(sum[:4])
	meta := ReportMeta{
		Kind:        kind,
		From:        from,
		To:          to,
		ReceivedAt:  now.Format(time.RFC3339),
		ContentType: contentTypeOf(raw),
		Format:      presumedFormat(raw),
		File:        name + ".eml",
	}
	dir := filepath.Join(DomainDir(dataDir, domainID), "reports", kind)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("directory: report store: %w", err)
	}
	rawPath := filepath.Join(dir, meta.File)
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		return "", fmt.Errorf("directory: report store: %w", err)
	}
	wire, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("directory: report store: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), wire, 0o600); err != nil {
		return "", fmt.Errorf("directory: report store: %w", err)
	}
	_ = pruneReports(dir, maxReportsPerKind, maxReportBytesPerKind) // the report is saved: failing it now would make the sender resend it; the next save prunes again
	return rawPath, nil
}

// StoredReport is one report as kept in the store: ingest metadata plus the raw
// message. Problems lists store-level read issues (e.g. unreadable metadata).
type StoredReport struct {
	Meta     ReportMeta
	Path     string // raw message file; read by ParseStoredReport, not by the listing
	Problems []string
}

// parsedCacheVersion changes whenever ParseReport's output changes, so older caches are parsed again.
const parsedCacheVersion = 1

type parsedCache struct {
	Version int          `json:"version"`
	Report  ParsedReport `json:"report"`
}

// ParseStoredReport returns the parse of the raw report at rawPath, from the cache file beside it
// when present, else parsing it and writing the cache. A report is decompressed once, not on every
// listing: anyone can fill the store, and each listing used to expand every report again
// (RFC 9990 8.1). The raw message is never modified.
func ParseStoredReport(log *slog.Logger, kind, rawPath string) ParsedReport {
	cachePath := strings.TrimSuffix(rawPath, ".eml") + ".parsed.json"
	if b, err := os.ReadFile(cachePath); err == nil {
		var c parsedCache
		if json.Unmarshal(b, &c) == nil && c.Version == parsedCacheVersion {
			return c.Report
		}
	}
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		return ParsedReport{Kind: kind, Format: "unknown", Problems: []string{"raw message unreadable: " + err.Error()}}
	}
	res := ParseReport(log, kind, raw)
	if b, err := json.Marshal(parsedCache{parsedCacheVersion, res}); err == nil {
		_ = os.WriteFile(cachePath, b, 0o600) // without the cache the next listing parses again
	}
	return res
}

// ListDomainReports reads every stored report of the domain across kinds, newest
// first. A report whose metadata or raw file cannot be read is still returned: only
// the fields known from the file system are filled and a problem note explains the
// rest, so nothing is ever invented.
func ListDomainReports(dataDir string, domainID uint32) ([]StoredReport, error) {
	if dataDir == "" {
		return nil, fmt.Errorf("directory: report store: data dir not set")
	}
	root := filepath.Join(DomainDir(dataDir, domainID), "reports")
	kinds, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("directory: report store: %w", err)
	}
	var out []StoredReport
	for _, kd := range kinds {
		if !kd.IsDir() {
			continue
		}
		kind := kd.Name()
		files, err := os.ReadDir(filepath.Join(root, kind))
		if err != nil {
			return nil, fmt.Errorf("directory: report store: %w", err)
		}
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".eml") {
				continue
			}
			st := StoredReport{Meta: ReportMeta{Kind: kind, File: f.Name(), Format: "unknown"}}
			wire, err := os.ReadFile(filepath.Join(root, kind, strings.TrimSuffix(f.Name(), ".eml")+".json"))
			switch {
			case err != nil:
				st.Problems = append(st.Problems, "metadata unreadable: "+err.Error())
			case json.Unmarshal(wire, &st.Meta) != nil:
				st.Problems = append(st.Problems, "metadata unreadable: invalid json")
			}
			// Kind and file name always follow the file system, not the metadata.
			st.Meta.Kind, st.Meta.File = kind, f.Name()
			st.Path = filepath.Join(root, kind, f.Name())
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meta.ReceivedAt > out[j].Meta.ReceivedAt })
	return out, nil
}

// contentTypeOf returns the top-level media type of the raw message ("" when unreadable).
func contentTypeOf(raw []byte) string {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	ct, _, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return ""
	}
	return ct
}

// presumedFormat guesses the payload format from Content-Type lines anywhere in the
// raw message (MIME parts included).
// ponytail: naive line scan, can mis-sniff unusual bodies; the real MIME walk belongs
// to the task-2 parser. gzip wins over xml/json because reports are usually gzipped.
func presumedFormat(raw []byte) string {
	format := "unknown"
	for _, line := range bytes.Split(raw, []byte("\n")) {
		lower := bytes.ToLower(bytes.TrimSpace(line))
		if !bytes.HasPrefix(lower, []byte("content-type:")) {
			continue
		}
		switch {
		case bytes.Contains(lower, []byte("gzip")):
			return "gzip"
		case bytes.Contains(lower, []byte("xml")):
			if format == "unknown" {
				format = "xml"
			}
		case bytes.Contains(lower, []byte("json")):
			if format == "unknown" {
				format = "json"
			}
		}
	}
	return format
}
