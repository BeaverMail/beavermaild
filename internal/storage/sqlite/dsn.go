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
	pragma := "_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(30000)"
	if strings.Contains(base, "?") {
		return base + "&" + pragma
	}
	return base + "?" + pragma
}
