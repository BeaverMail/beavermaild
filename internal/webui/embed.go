// Embeds admin UI static files from dist/ (populated by make web-build).
package webui

import (
	"embed"
	"io/fs"
)

// dist always holds .gitkeep (kept in git, so the embed compiles); the SPA appears after web-build.
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
	// Without a built SPA (fresh clone, make beaver-go) the UI stays disabled instead of serving a blank page.
	if _, err := fs.Stat(sub, "index.html"); err == nil {
		assets = sub
	}
}
