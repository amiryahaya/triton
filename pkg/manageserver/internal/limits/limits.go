// Package limits holds shared request-size constants used by the
// manageserver handler sub-packages (zones, hosts, scanjobs, agents).
// Defined in an internal package so the sub-handler packages can
// consume it without importing the main manageserver package (which
// would create an import cycle — manageserver already imports each
// sub-package).
//
// Defence-in-depth: admin CRUD endpoints are JWT-gated, but capping
// the body size prevents an authenticated-but-hostile client from
// wedging a handler's JSON decoder with a multi-gigabyte payload.
// 1 MiB is plenty for every admin-plane shape: zones / hosts / scan-
// jobs / agents JSON bodies are tiny (a 1000-host bulk import at ~200
// bytes per host still fits inside 200 KB).
package limits

// MaxRequestBody is the byte cap applied via http.MaxBytesReader on
// every admin CRUD handler that decodes a JSON body. Reads beyond
// this size return an error at the decoder surface (handlers translate
// that into a 400 Bad Request).
const MaxRequestBody int64 = 1 << 20 // 1 MiB
