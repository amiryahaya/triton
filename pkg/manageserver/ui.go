// Package manageserver — ui.go wires the embedded Vue SPA from the
// sibling ui/dist/ directory into the HTTP router. The directory is
// populated by `make web-build-manage` (which runs Vite from
// web/apps/manage-portal/). Only `.gitkeep` is tracked; the built
// assets are .gitignore'd and reproduced from source at CI/container
// build time.
package manageserver

import "embed"

//go:embed all:ui/dist
var uiFS embed.FS

// UIFS returns the embedded Vue portal filesystem root. The `ui/dist`
// subtree is populated by the Vite build in web/apps/manage-portal.
// Exported for tests only; production code paths use the package-
// scoped uiFS directly in server.go.
func UIFS() embed.FS { return uiFS }
