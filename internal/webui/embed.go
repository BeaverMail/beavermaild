// Embeds admin UI static files from dist/ (populated by make web-build).
package webui

import (
	"embed"
	"io/fs"
)

// dist always embeds at least index.html (kept in git); full SPA after web-build.
//
//go:embed all:dist
var dist embed.FS

// assets is the public root (contents of dist/).
var assets fs.FS

// init exposes the dist subdirectory as the public asset root.
func init() {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("webui: embed dist: " + err.Error())
	}
	assets = sub
}
