// Package log configures structured logging for BeaverMail.
package log

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// New builds a stderr slog.Logger at the requested level (debug, info, warn, error).
func New(level string) *slog.Logger {
	return slog.New(newTextHandler(level))
}

// WithFile tees to base and appends redacted JSON lines to file (nil file = base only).
func WithFile(base *slog.Logger, file *RotatingFile) *slog.Logger {
	if base == nil {
		base = slog.Default()
	}
	if file == nil {
		return base
	}
	return slog.New(&teeHandler{next: base.Handler(), file: file})
}

func newTextHandler(level string) slog.Handler {
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
	return slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &lv})
}

// Entry is one captured log line for the admin ops UI.
type Entry struct {
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"msg"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

// Query filters file history entries (newest first).
type Query struct {
	MinLevel slog.Level
	LevelSet bool
	Q        string
	Limit    int
	Before   time.Time // exclusive upper bound (pagination)
}

func entryMatch(e Entry, needle string) bool {
	if strings.Contains(strings.ToLower(e.Message), needle) {
		return true
	}
	for k, v := range e.Attrs {
		if strings.Contains(strings.ToLower(k), needle) {
			return true
		}
		if strings.Contains(strings.ToLower(fmt.Sprint(v)), needle) {
			return true
		}
	}
	return false
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// ParseLevelName maps API query values to slog levels.
func ParseLevelName(s string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

type teeHandler struct {
	next  slog.Handler
	file  *RotatingFile
	attrs []slog.Attr
	group string
}

func (h *teeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *teeHandler) Handle(ctx context.Context, rec slog.Record) error {
	e := Entry{
		Time:    rec.Time,
		Level:   rec.Level.String(),
		Message: rec.Message,
	}
	attrs := map[string]any{}
	for _, a := range h.attrs {
		putAttr(attrs, h.group, a)
	}
	rec.Attrs(func(a slog.Attr) bool {
		putAttr(attrs, h.group, a)
		return true
	})
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	_ = h.file.WriteEntry(e)
	return h.next.Handle(ctx, rec)
}

func (h *teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	cp := *h
	cp.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	cp.next = h.next.WithAttrs(attrs)
	return &cp
}

func (h *teeHandler) WithGroup(name string) slog.Handler {
	cp := *h
	if h.group != "" {
		cp.group = h.group + "." + name
	} else {
		cp.group = name
	}
	cp.next = h.next.WithGroup(name)
	return &cp
}

func putAttr(dst map[string]any, group string, a slog.Attr) {
	a.Value = a.Value.Resolve()
	key := a.Key
	if group != "" {
		key = group + "." + key
	}
	if redactKey(key) {
		dst[key] = "[redacted]"
		return
	}
	switch a.Value.Kind() {
	case slog.KindString:
		dst[key] = a.Value.String()
	case slog.KindInt64:
		dst[key] = a.Value.Int64()
	case slog.KindUint64:
		dst[key] = a.Value.Uint64()
	case slog.KindFloat64:
		dst[key] = a.Value.Float64()
	case slog.KindBool:
		dst[key] = a.Value.Bool()
	case slog.KindDuration:
		dst[key] = a.Value.Duration().String()
	case slog.KindTime:
		dst[key] = a.Value.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindGroup:
		for _, ga := range a.Value.Group() {
			putAttr(dst, key, ga)
		}
	default:
		if err, ok := a.Value.Any().(error); ok {
			dst[key] = err.Error()
			return
		}
		dst[key] = a.Value.String()
	}
}

func redactKey(key string) bool {
	k := strings.ToLower(key)
	if i := strings.LastIndex(k, "."); i >= 0 {
		k = k[i+1:]
	}
	switch k {
	case "password", "passwd", "secret", "token", "auth_key", "authorization", "cookie":
		return true
	default:
		return false
	}
}
