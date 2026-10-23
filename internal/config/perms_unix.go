//go:build unix

package config

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// AdoptDataDirOwner gives the files init created (store, blob dir) to the owner of the data dir
// when init runs as root in a dir prepared for the service user (package postinst). systemd's
// StateDirectory= only re-owns the tree when the dir itself has the wrong owner, so it would
// leave a root-owned store behind.
func (c *Config) AdoptDataDirOwner() error {
	if os.Geteuid() != 0 {
		return nil
	}
	st, err := os.Stat(c.DataDir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid == 0 {
		return nil
	}
	for _, p := range append(c.privatePaths()[1:], c.BlobDir()) {
		if err := os.Lchown(p, int(sys.Uid), int(sys.Gid)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
