// SQLite DSN helpers for modernc.org/sqlite connection pragmas.
package sqlite

import (
	"strings"
)

// dsn returns a modernc SQLite DSN with WAL and busy_timeout baked in.
func dsn(path string) string {
	if path == ":memory:" {
		return path
	}
	base := path
	if !strings.HasPrefix(path, "file:") {
		base = "file:" + path
	}
	// Commits never checkpoint (Store.checkpointLoop does, off the request path);
	// journal_size_limit truncates the WAL file when it restarts after a burst.
	pragma := "_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(30000)" +
		"&_pragma=wal_autocheckpoint(0)&_pragma=journal_size_limit(67108864)"
	if strings.Contains(base, "?") {
		return base + "&" + pragma
	}
	return base + "?" + pragma
}
