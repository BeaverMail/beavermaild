// Owner-only permissions for the data dir and SQLite files (shared hosting servers).
package config

import (
	"errors"
	"io/fs"
	"os"
)

// privatePaths returns the paths that must not be readable by other local users: the data dir
// (the one barrier in front of the store, blobs, logs and keys) and the SQLite files.
func (c *Config) privatePaths() []string {
	return []string{c.DataDir, c.StorePath(), c.StorePath() + "-wal", c.StorePath() + "-shm"}
}

// SecureDataDir clears group and other permission bits on the data dir and the SQLite files
// and returns the paths it changed. Missing paths are skipped.
func (c *Config) SecureDataDir() ([]string, error) {
	var changed []string
	for _, p := range c.privatePaths() {
		st, err := os.Stat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return changed, err
		}
		if st.Mode().Perm()&0o077 == 0 {
			continue
		}
		if err := os.Chmod(p, st.Mode().Perm()&^0o077); err != nil {
			return changed, err
		}
		changed = append(changed, p)
	}
	return changed, nil
}

// ConfigFileShared reports whether the config file (secrets, relay and DSN passwords) is open
// to other users or writable by its group; group read is how packages let the service read it.
func (c *Config) ConfigFileShared() bool {
	st, err := os.Stat(c.ConfigPath())
	return err == nil && st.Mode().Perm()&0o027 != 0
}
