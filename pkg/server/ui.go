package server

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed all:ui/dist
var uiFS embed.FS

// uiHandler returns an http.Handler that serves the embedded web UI.
func uiHandler() http.Handler {
	sub, err := fs.Sub(uiFS, "ui/dist")
	if err != nil {
		// Should never happen with valid embed directive
		log.Fatalf("embedded UI filesystem error: %v", err)
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Try to serve the file; if not found, serve index.html (SPA fallback)
		fileServer.ServeHTTP(w, r)
	})
}
