package log

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	defaultMaxBytes = 16 << 20 // 16 MiB
	defaultKeep     = 5
)

// RotatingFile appends JSON log lines and rotates by size.
type RotatingFile struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

// FileOptions configures rotation. Zero values use defaults.
type FileOptions struct {
	MaxBytes int64
	Keep     int
}

// OpenFile creates or appends path (mkdir parent). Caller must Close.
func OpenFile(path string, opts FileOptions) (*RotatingFile, error) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil, fmt.Errorf("log: empty file path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}
	keep := opts.Keep
	if keep <= 0 {
		keep = defaultKeep
	}
	rf := &RotatingFile{path: path, maxBytes: maxBytes, keep: keep}
	if err := rf.open(); err != nil {
		return nil, err
	}
	return rf, nil
}

// Path returns the active log file path.
func (r *RotatingFile) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

// WriteEntry marshals e as one JSON line (redacted attrs already applied by caller).
func (r *RotatingFile) WriteEntry(e Entry) error {
	if r == nil {
		return nil
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.writeLocked(b)
}

// Close flushes and closes the active file.
func (r *RotatingFile) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

func (r *RotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	r.f = f
	r.size = st.Size()
	return nil
}

func (r *RotatingFile) writeLocked(b []byte) error {
	if r.f == nil {
		if err := r.open(); err != nil {
			return err
		}
	}
	if r.size > 0 && r.size+int64(len(b)) > r.maxBytes {
		if err := r.rotateLocked(); err != nil {
			return err
		}
	}
	n, err := r.f.Write(b)
	r.size += int64(n)
	return err
}

func (r *RotatingFile) rotateLocked() error {
	if r.f != nil {
		_ = r.f.Close()
		r.f = nil
	}
	// Shift .N-1 -> .N, ..., current -> .1
	for i := r.keep - 1; i >= 1; i-- {
		src := r.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", r.path, i-1)
		}
		dst := fmt.Sprintf("%s.%d", r.path, i)
		_ = os.Remove(dst)
		_ = os.Rename(src, dst)
	}
	r.size = 0
	return r.open()
}
