// SQLite busy-lock detection and short retries for multi-process access.
package sqlite

import (
	"strings"
	"time"
)

const (
	busyRetryAttempts = 12
	busyRetryBase     = 5 * time.Millisecond
)

func isBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") || strings.Contains(msg, "SQLITE_BUSY")
}

func retryBusy(op func() error) error {
	var err error
	for attempt := 0; attempt < busyRetryAttempts; attempt++ {
		err = op()
		if err == nil || !isBusy(err) {
			return err
		}
		time.Sleep(busyRetryBase * time.Duration(attempt+1))
	}
	return err
}
