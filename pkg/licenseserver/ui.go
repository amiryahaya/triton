package licenseserver

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

// `all:` prefix so Go's embed includes the .gitkeep placeholder that
// lives in ui/dist on a cold clone before `make web` runs. Matches the
// convention in pkg/server/ui.go. Without it, a clone without running
// `make web` first fails with "pattern ui/dist: contains no embeddable
// files" because Go's default embed globbing excludes dotfiles.
//
//go:embed all:ui/dist
var adminUIFS embed.FS

// adminUIHandler returns an http.Handler that serves the embedded admin web UI.
func adminUIHandler() http.Handler {
	sub, err := fs.Sub(adminUIFS, "ui/dist")
	if err != nil {
		log.Fatalf("embedded admin UI filesystem error: %v", err)
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	})
}
