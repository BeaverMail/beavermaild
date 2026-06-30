// JSON protocol types for SMTP daemon plugins.
package daemon

// ReadyLine is the first JSON line a daemon plugin sends after connecting.
type ReadyLine struct {
	Status         string   `json:"status"`
	Capabilities   []string `json:"capabilities,omitempty"`
	MaxConnections int      `json:"max_connections,omitempty"`
}

// FilterRequest is the host-to-plugin filter JSON line.
type FilterRequest struct {
	ID        string   `json:"id"`
	Phase     string   `json:"phase"`
	From      string   `json:"from,omitempty"`
	To        []string `json:"to,omitempty"`
	ClientIP  string   `json:"client_ip,omitempty"`
	BodyPath  string   `json:"body_path,omitempty"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
}

// FilterResponse is the plugin-to-host filter JSON line.
type FilterResponse struct {
	ID     string `json:"id"`
	Action string `json:"action"`
}
