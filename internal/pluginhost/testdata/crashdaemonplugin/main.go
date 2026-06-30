// SMTP daemon plugin that exits after one filter response (restart tests).
package main

import (
	"bufio"
	"encoding/json"
	"net"
	"os"

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

	ready, _ := json.Marshal(map[string]any{
		"status":       "ready",
		"capabilities": []string{plugin.CapSMTP},
	})
	if _, err := conn.Write(append(ready, '\n')); err != nil {
		os.Exit(1)
	}

	sc := bufio.NewScanner(conn)
	if sc.Scan() {
		var req struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(sc.Bytes(), &req)
		resp, _ := json.Marshal(map[string]string{"id": req.ID, "action": "accept"})
		_, _ = conn.Write(append(resp, '\n'))
	}
	os.Exit(1)
}
