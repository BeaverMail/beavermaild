//go:build unix

package main

import "syscall"

// privateUmask makes everything this process and its plugins create owner-only: the store,
// exports, logs and scan reports hold mail and credentials, and hosting servers are shared.
func privateUmask() { syscall.Umask(0o077) }
