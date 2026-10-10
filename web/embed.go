package web

import (
	"embed"
	"io/fs"
)

//go:embed all:static
var staticFiles embed.FS

// GetStaticFS returns the sub-filesystem pointing to static files
func GetStaticFS() fs.FS {
	sub, err := fs.Sub(staticFiles, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
