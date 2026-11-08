//go:build !unix

package config

// AdoptDataDirOwner is a no-op where file ownership is not POSIX.
func (c *Config) AdoptDataDirOwner() error { return nil }
