package licenseserver

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed ui/dist
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
