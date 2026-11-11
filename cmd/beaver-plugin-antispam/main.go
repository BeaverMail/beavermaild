// beaver-plugin-antispam: rspamd-style scoring filter for the BeaverMail SMTP daemon protocol,
// plus the `beaver filter reload|status|scan` admin commands.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BeaverMail/beavermaild/plugin"
)

var descriptor = plugin.Descriptor{
	Command: []string{"filter"},
	License: plugin.LicenseFree,
	CliFlags: []plugin.CliFlag{
		{Key: "client_ip", Flag: "client-ip", Description: "simulated SMTP client IP (scan)"},
		{Key: "ehlo_domain", Flag: "ehlo", Description: "simulated SMTP EHLO domain (scan)"},
		{Key: "mail_auth", Flag: "mail-auth", Bool: true, Description: "run DKIM/DMARC verify on each message (scan)"},
		{Key: "rbl", Flag: "rbl", Bool: true, Description: "run RBL at connect phase (scan)"},
		{Key: "json", Flag: "json", Bool: true, Description: "JSON lines on stderr instead of TSV (scan, no -o)"},
		{Key: "output", Flag: "o", Description: "write TSV report to path (scan)"},
		{Key: "only", Flag: "only", Description: "filter rows: spam, reject, non-ham (scan)"},
		{Key: "min_score", Flag: "min-score", Description: "minimum score to include in report (scan)"},
	},
	CliSubcommands: []plugin.CliSubcommand{
		{Name: "reload", Profile: plugin.CliProfileJob, Summary: "reload antispam rules"},
		{Name: "status", Profile: plugin.CliProfileJob, Summary: "show filter status"},
		{Name: "scan", Profile: plugin.CliProfileAccountScan, Summary: "simulate antispam on account messages"},
	},
	Capabilities: []string{plugin.CapCLI, plugin.CapSMTP},
	CliKind:      plugin.CliKindAdmin,
}

func main() {
	switch {
	case plugin.IsMetadataProcess():
		plugin.EmitDescriptor(descriptor)
	case plugin.IsDaemonProcess():
		if err := runDaemon(); err != nil {
			logf("daemon: %v", err)
			os.Exit(1)
		}
	default:
		plugin.RunCLI(runCLI)
	}
}

func logf(format string, args ...any) { fmt.Fprintf(os.Stderr, "antispam: "+format+"\n", args...) }

func dataDir() string {
	if d := os.Getenv(plugin.EnvDataDir); d != "" {
		return d
	}
	return "."
}

// state owns the live Filter and reloads it when reload.stamp changes (written by `filter reload`).
type state struct {
	mu        sync.Mutex
	dir       string
	f         *Filter
	stamp     time.Time
	lastCheck time.Time
}

func newState(dir string) *state {
	s := &state{dir: dir}
	s.stamp = s.stampTime()
	cfg, lists, err := loadConfig(dir)
	if err != nil {
		// Keep mail flowing: start on defaults and say so; `filter status` shows the error.
		logf("config error, running with defaults: %v", err)
		cfg, lists = defaultConfig(), Lists{}
	}
	s.f = newFilter(cfg, lists, nil)
	return s
}

func (s *state) stampTime() time.Time {
	st, err := os.Stat(filepath.Join(antispamDir(s.dir), reloadStampFile))
	if err != nil {
		return time.Time{}
	}
	return st.ModTime()
}

func (s *state) filter() *Filter {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.lastCheck) < time.Second {
		return s.f
	}
	s.lastCheck = time.Now()
	if t := s.stampTime(); !t.Equal(s.stamp) {
		s.stamp = t
		cfg, lists, err := loadConfig(s.dir)
		if err != nil {
			logf("reload failed, keeping previous config: %v", err)
			return s.f
		}
		s.f = newFilter(cfg, lists, s.f.grey)
		logf("config reloaded")
	}
	return s.f
}

func runDaemon() error {
	sock := os.Getenv("BEAVER_SMTP_SOCKET")
	if sock == "" {
		return fmt.Errorf("BEAVER_SMTP_SOCKET not set")
	}
	st := newState(dataDir())
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return err
	}
	defer conn.Close()
	enc := json.NewEncoder(conn)
	if err := enc.Encode(map[string]any{"status": "ready", "capabilities": []string{plugin.CapSMTP}, "max_connections": 1}); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(conn, 64<<10)
	for {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			return nil // host closed the socket: exit, it respawns us if needed
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			logf("bad request: %v", err)
			continue
		}
		if err := enc.Encode(handle(st.filter(), &req)); err != nil {
			return err
		}
	}
}

// handle answers one filter request; only eom carries content, earlier phases accept.
func handle(f *Filter, req *request) response {
	if req.Phase != "eom" {
		return response{ID: req.ID, Action: "accept"}
	}
	timeout := 10 * time.Second
	if req.TimeoutMs > 0 {
		timeout = time.Duration(req.TimeoutMs) * time.Millisecond
	}
	// Answer before the host gives up: network checks get 80% of its budget.
	ctx, cancel := context.WithTimeout(context.Background(), timeout*8/10)
	defer cancel()
	return f.filterEOM(ctx, req)
}

func emitReport(msg string) {
	b, _ := json.Marshal(plugin.CliEvent{Op: plugin.CliOpReport, Message: msg})
	fmt.Fprintf(os.Stdout, "%s\n", b)
}

func emitDone(msg string) {
	b, _ := json.Marshal(plugin.CliEvent{Op: plugin.CliOpDone, Message: msg})
	fmt.Fprintf(os.Stdout, "%s\n", b)
}

func runCLI(req plugin.CliRequest, emit *plugin.BatchEmitter) error {
	params := map[string]string{}
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return fmt.Errorf("params: %w", err)
		}
	}
	dir := dataDir()
	switch req.Op {
	case "filter/reload":
		if _, _, err := loadConfig(dir); err != nil {
			return fmt.Errorf("config not reloaded: %w", err)
		}
		stamp := filepath.Join(antispamDir(dir), reloadStampFile)
		if err := os.MkdirAll(antispamDir(dir), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(stamp, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
			return err
		}
		emitReport("antispam: config valid; running daemon reloads within a second (on its next message)")
	case "filter/status":
		for _, l := range statusLines(dir) {
			emitReport(l)
		}
	case "filter/scan":
		summary, err := runScan(params)
		if err != nil {
			return err
		}
		emitDone(summary)
		return nil
	default:
		return fmt.Errorf("unknown op %q (want filter/reload, filter/status, filter/scan)", req.Op)
	}
	return emit.EmitDone()
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func statusLines(dir string) []string {
	path := filepath.Join(antispamDir(dir), configFile)
	out := []string{"config: " + path}
	if _, err := os.Stat(path); err != nil {
		out = append(out, "config file: absent (defaults)")
	}
	cfg, lists, err := loadConfig(dir)
	if err != nil {
		return append(out, "config error: "+err.Error())
	}
	var acts []string
	for _, k := range []string{"reject", "rewrite_subject", "add_header", "greylist"} {
		if t, ok := cfg.threshold(k); ok {
			acts = append(acts, fmt.Sprintf("%s=%g", k, t))
		} else {
			acts = append(acts, k+"=off")
		}
	}
	dqs := "no"
	if cfg.RBL.DQSKey != "" {
		dqs = "yes"
	}
	resolver := cfg.RBL.Resolver
	if resolver == "" {
		resolver = "system"
	}
	out = append(out,
		"actions: "+strings.Join(acts, " "),
		fmt.Sprintf("score overrides: %d, gtube: %s", len(cfg.Scores), cfg.GTUBE),
		fmt.Sprintf("rbl: %s (dqs key: %s, resolver: %s, max lookups: %d)", onOff(cfg.RBL.Enabled), dqs, resolver, cfg.RBL.MaxLookups),
		fmt.Sprintf("url_redirector: %s, hfilter dns_checks: %s", onOff(cfg.URLRedirector.Enabled), onOff(cfg.HFilter.DNSChecks)),
		fmt.Sprintf("lists: spam traps %d, trusted domains %d, url redirectors %d", len(lists.SpamTraps), len(lists.Trusted), len(lists.Redirectors)),
	)
	if st, err := os.Stat(filepath.Join(antispamDir(dir), reloadStampFile)); err == nil {
		out = append(out, "last reload request: "+st.ModTime().UTC().Format(time.RFC3339))
	}
	return out
}
