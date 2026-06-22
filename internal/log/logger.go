// Package log configures structured logging for BeaverMail.
package log

import (
	"log/slog"
	"os"
	"strings"
)

// New builds a stderr slog.Logger at the requested level (debug, info, warn, error).
func New(level string) *slog.Logger {
	var lv slog.LevelVar
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lv.Set(slog.LevelDebug)
	case "warn", "warning":
		lv.Set(slog.LevelWarn)
	case "error":
		lv.Set(slog.LevelError)
	default:
		lv.Set(slog.LevelInfo)
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &lv})
	return slog.New(handler)
}
