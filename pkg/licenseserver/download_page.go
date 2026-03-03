package licenseserver

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed download/dist/*
var downloadPageFS embed.FS

// downloadPageHandler returns an http.Handler that serves the embedded download page.
func downloadPageHandler() http.Handler {
	sub, err := fs.Sub(downloadPageFS, "download/dist")
	if err != nil {
		log.Fatalf("embedded download page filesystem error: %v", err)
	}

	fileServer := http.FileServer(http.FS(sub))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileServer.ServeHTTP(w, r)
	})
}
