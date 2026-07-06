// Scan report: header metadata, TSV output, and row filters.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const scanSnippetMax = 120

type messageMeta struct {
	From      string
	To        string
	Subject   string
	Date      string
	MessageID string
	Snippet   string
}

type scanReportOpts struct {
	OutputPath string
	Only       string
	MinScore   float64
	AsJSON     bool
}

func parseScanReportOpts(raw map[string]string) scanReportOpts {
	out := scanReportOpts{
		OutputPath: strings.TrimSpace(raw["output"]),
		Only:       strings.TrimSpace(strings.ToLower(raw["only"])),
		AsJSON:     truthy(raw["json"]),
	}
	if s := strings.TrimSpace(raw["min_score"]); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			out.MinScore = v
		}
	}
	return out
}

// includeScanRow applies -only and -min-score filters.
func includeScanRow(resp filterResp, opts scanReportOpts) bool {
	class := spamClass(resp)
	if opts.MinScore > 0 && resp.Score < opts.MinScore {
		return false
	}
	switch opts.Only {
	case "":
		return true
	case "spam":
		return class == "spam"
	case "reject":
		return resp.Action == "reject" || resp.Action == "discard" ||
			class == "reject" || class == "discard"
	case "non-ham":
		return class != "ham"
	default:
		return true
	}
}

func parseMessageMeta(path string) messageMeta {
	b, err := os.ReadFile(path)
	if err != nil {
		return messageMeta{}
	}
	header, body := splitHeadersBody(b)
	meta := messageMeta{}
	for _, line := range strings.Split(string(header), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "from:"):
			meta.From = parseAddr(strings.TrimSpace(line[5:]))
		case strings.HasPrefix(lower, "to:"):
			meta.To = parseAddr(strings.TrimSpace(line[3:]))
		case strings.HasPrefix(lower, "subject:"):
			meta.Subject = strings.TrimSpace(line[8:])
		case strings.HasPrefix(lower, "date:"):
			meta.Date = strings.TrimSpace(line[5:])
		case strings.HasPrefix(lower, "message-id:"):
			meta.MessageID = strings.Trim(strings.TrimSpace(line[11:]), "<>")
		}
	}
	meta.Snippet = firstSnippet(body, scanSnippetMax)
	return meta
}

func firstSnippet(body []byte, max int) string {
	if len(body) == 0 || max <= 0 {
		return ""
	}
	s := strings.TrimSpace(string(body))
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max]
	}
	return s
}

var scanReportHeader = []string{
	"mailbox", "uid", "message_id", "date", "from", "to", "subject",
	"score", "class", "action", "tags", "snippet",
}

type scanReporter struct {
	file       *os.File
	w          *csv.Writer
	toStdout   bool
	json       bool
	headerDone bool
}

func newScanReporter(opts scanReportOpts) (*scanReporter, error) {
	r := &scanReporter{toStdout: opts.OutputPath == "", json: opts.AsJSON}
	if opts.OutputPath == "" {
		return r, nil
	}
	f, err := os.Create(opts.OutputPath)
	if err != nil {
		return nil, err
	}
	r.file = f
	r.w = csv.NewWriter(f)
	r.w.Comma = '\t'
	if err := r.w.Write(scanReportHeader); err != nil {
		_ = f.Close()
		return nil, err
	}
	return r, nil
}

func (r *scanReporter) Close() error {
	if r == nil || r.file == nil {
		return nil
	}
	r.w.Flush()
	err := r.w.Error()
	if closeErr := r.file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (r *scanReporter) WriteRow(msg scanMessage, meta messageMeta, resp filterResp) error {
	if r.json && r.toStdout {
		row := map[string]any{
			"mailbox": msg.Mailbox, "uid": msg.UID, "message_id": meta.MessageID,
			"date": meta.Date, "from": meta.From, "to": meta.To, "subject": meta.Subject,
			"score": resp.Score, "class": spamClass(resp), "action": resp.Action,
			"tags": resp.Tags, "snippet": meta.Snippet,
		}
		b, err := json.Marshal(row)
		if err != nil {
			return err
		}
		emitReport(string(b))
		return nil
	}
	row := []string{
		msg.Mailbox,
		strconv.FormatUint(uint64(msg.UID), 10),
		meta.MessageID,
		meta.Date,
		meta.From,
		meta.To,
		meta.Subject,
		fmt.Sprintf("%.2f", resp.Score),
		spamClass(resp),
		resp.Action,
		strings.Join(resp.Tags, ","),
		meta.Snippet,
	}
	if r.w != nil {
		if err := r.w.Write(row); err != nil {
			return err
		}
		r.w.Flush()
		return r.w.Error()
	}
	if r.toStdout {
		if !r.headerDone {
			emitReport(strings.Join(scanReportHeader, "\t"))
			r.headerDone = true
		}
		emitReport(strings.Join(row, "\t"))
	}
	return nil
}

func writeScanReportPathHint(path string) {
	if path != "" {
		fmt.Fprintf(os.Stderr, "report: %s\n", path)
	}
}
