package plugin

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/zeebo/blake3"
)

// WriteTempMessage stores raw RFC 5322 bytes in a temp file for raw_path batch transfer.
// The host removes the file after ingest when it lies under the system temp directory.
func WriteTempMessage(raw []byte) (string, error) {
	f, err := os.CreateTemp("", "beaver-plugin-msg-*.eml")
	if err != nil {
		return "", err
	}
	path := f.Name()
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// HashFile returns the Blake3 digest of a file as lowercase hex.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := blake3.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	return fmt.Sprintf("%x", sum), nil
}

// IsPluginTempPath reports whether the host should unlink path after ingest.
// Only files created by WriteTempMessage match (beaver-plugin-msg-*.eml under the OS temp dir).
func IsPluginTempPath(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	tmp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(tmp, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	base := filepath.Base(abs)
	return strings.HasPrefix(base, "beaver-plugin-msg-") && strings.HasSuffix(base, ".eml")
}
