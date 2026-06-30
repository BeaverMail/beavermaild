// Daemon-capable plugin stub for registry/daemon integration tests.
package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"
	"strings"

	"github.com/BeaverMail/beaver/plugin"
)

func main() {
	if plugin.IsMetadataProcess() {
		plugin.EmitDescriptor(plugin.Descriptor{
			Command:      []string{"filter"},
			Capabilities: []string{plugin.CapSMTP},
		})
		return
	}
	if plugin.IsDaemonProcess() {
		runDaemon()
	}
}

func runDaemon() {
	socket := os.Getenv("BEAVER_SMTP_SOCKET")
	if socket == "" {
		os.Exit(1)
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		os.Exit(1)
	}
	defer conn.Close()

	action := strings.TrimSpace(os.Getenv("BEAVER_TEST_DAEMON_ACTION"))
	if action == "" {
		action = "accept"
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
		var req struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			continue
		}
		resp, _ := json.Marshal(map[string]string{"id": req.ID, "action": action})
		if _, err := conn.Write(append(resp, '\n')); err != nil {
			break
		}
	}
}
