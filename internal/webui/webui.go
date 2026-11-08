// Package webui serves the embedded admin static UI from dist/.
package webui

import "io/fs"

// Enabled reports whether the admin UI assets are linked into this binary.
func Enabled() bool { return assets != nil }

// Assets returns the embedded static file tree (index.html, _app/, ...).
func Assets() (fs.FS, bool) {
	if assets == nil {
		return nil, false
	}
	return assets, true
}
