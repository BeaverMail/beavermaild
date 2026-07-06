// beaver-plugin-antispam applies inbound SMTP antispam policy (RBL, lists, score).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/BeaverMail/beaver/plugin"
)

func main() {
	if plugin.IsMetadataProcess() {
		plugin.EmitDescriptor(plugin.Descriptor{
			Command:      []string{"filter"},
			Capabilities: []string{plugin.CapCLI, plugin.CapSMTP},
			CliKind:      plugin.CliKindAdmin,
			CliSubcommands: []plugin.CliSubcommand{
				{Name: "reload", Profile: plugin.CliProfileJob, Summary: "reload antispam rules"},
				{Name: "status", Profile: plugin.CliProfileJob, Summary: "show filter status"},
				{Name: "scan", Profile: plugin.CliProfileAccountScan, Summary: "simulate antispam on account messages"},
			},
			CliFlags: []plugin.CliFlag{
				{Key: "client_ip", Flag: "client-ip", Description: "simulated SMTP client IP (scan)"},
				{Key: "mail_auth", Flag: "mail-auth", Bool: true, Description: "run DKIM/DMARC verify on each message (scan)"},
				{Key: "rbl", Flag: "rbl", Bool: true, Description: "run RBL at connect phase (scan)"},
				{Key: "json", Flag: "json", Bool: true, Description: "JSON lines on stderr instead of TSV (scan, no -o)"},
				{Key: "output", Flag: "o", Description: "write TSV report to path (scan)"},
				{Key: "only", Flag: "only", Description: "filter rows: spam, reject, non-ham (scan)"},
				{Key: "min_score", Flag: "min-score", Description: "minimum score to include in report (scan)"},
			},
		})
		return
	}
	if plugin.IsDaemonProcess() {
		runDaemon()
		return
	}
	runCLI()
}

func runCLI() {
	req, err := plugin.ReadCliRequest(os.Stdin)
	if err != nil {
		emitError(err.Error())
		return
	}
	dataDir := strings.TrimSpace(os.Getenv(plugin.EnvDataDir))
	if dataDir == "" {
		emitError("BEAVER_DATA_DIR not set")
		return
	}
	switch req.Op {
	case "filter/reload":
		if err := touchReload(dataDir); err != nil {
			emitError(err.Error())
			return
		}
		emitDone("antispam rules reloaded")
	case "filter/status":
		st, err := loadStatus(dataDir)
		if err != nil {
			emitError(err.Error())
			return
		}
		emitDone(st)
	case "filter/scan":
		if err := runScan(dataDir, req); err != nil {
			emitError(err.Error())
			return
		}
	default:
		emitError("unknown op: " + req.Op)
	}
}

func touchReload(dataDir string) error {
	dir := antispamDir(dataDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepathJoin(dir, ".reload"), []byte(time.Now().Format(time.RFC3339)+"\n"), 0o644)
}

func loadStatus(dataDir string) (string, error) {
	cfg, err := loadConfig(dataDir)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("enabled=%v zones=%d thresholds.reject=%.1f last_reload=%s",
		cfg.Enabled, len(cfg.RBL.Zones), cfg.Thresholds.Reject, cfg.lastReload.Format(time.RFC3339)), nil
}

func emitDone(msg string) {
	b, _ := json.Marshal(plugin.CliEvent{Op: plugin.CliOpDone, Message: msg})
	fmt.Println(string(b))
}

func emitError(msg string) {
	b, _ := json.Marshal(plugin.CliEvent{Op: plugin.CliOpError, Message: msg})
	fmt.Println(string(b))
}

// emitReport sends one report line to the host (printed on beaver stdout).
func emitReport(line string) {
	b, _ := json.Marshal(plugin.CliEvent{Op: plugin.CliOpReport, Message: line})
	fmt.Println(string(b))
}

func runDaemon() {
	socket := os.Getenv("BEAVER_SMTP_SOCKET")
	dataDir := os.Getenv(plugin.EnvDataDir)
	if socket == "" || dataDir == "" {
		os.Exit(1)
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		os.Exit(1)
	}
	defer conn.Close()

	eng, err := newEngine(dataDir)
	if err != nil {
		os.Exit(1)
	}

	ready, _ := json.Marshal(map[string]any{
		"status":       "ready",
		"capabilities": []string{plugin.CapSMTP},
	})
	if _, err := conn.Write(append(ready, '\n')); err != nil {
		os.Exit(1)
	}

	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		eng.maybeReload()
		var req filterReq
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		resp := eng.handle(req)
		line, _ := json.Marshal(resp)
		if _, err := conn.Write(append(line, '\n')); err != nil {
			break
		}
	}
}

func filepathJoin(a, b string) string {
	return strings.TrimRight(a, "/") + "/" + b
}

func antispamDir(dataDir string) string {
	return filepathJoin(dataDir, "antispam")
}
