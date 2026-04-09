package server

import (
	"compress/gzip"
	"net/http"
	"strings"
	"sync"
)

// GzipDecodeMiddleware transparently decompresses request bodies
// that arrive with `Content-Encoding: gzip`. Handlers further down
// the chain can read r.Body as if it were always plaintext.
//
// Motivated by the A10 agent change: the agent defaults to gzip
// compression on scan submissions because typical scan payloads
// are 1-5 MB of high-redundancy JSON that compresses 4-8x. Adding
// decode at the /api/v1 group lets every handler benefit without
// touching individual handler code.
//
// Backward compatible: requests without Content-Encoding (or with
// any encoding other than "gzip") pass through unchanged. This
// preserves the existing contract for agents that predate A10 and
// for operators who explicitly disable compression via
// Client.CompressSubmissions = false.
//
// Failure mode: a malformed gzip stream (header corruption,
// truncation, etc.) fails at gzip.NewReader and we return
// 400 Bad Request. This is the right status because the client
// sent us something we cannot parse — retrying won't help.
//
// Resource safety: the gzip.Reader is returned to a sync.Pool
// on body close so each request doesn't allocate a fresh ~30KB
// decoder state. The pool is bounded by GC pressure (unused
// readers are eventually collected) so we don't need an explicit
// cap.
func GzipDecodeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only act on gzipped requests. Empty header → pass through.
		if !strings.EqualFold(r.Header.Get("Content-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}

		gz, err := acquireGzipReader(r.Body)
		if err != nil {
			// Malformed gzip stream — can't proceed.
			http.Error(w, `{"error":"invalid gzip request body"}`, http.StatusBadRequest)
			return
		}

		// Wrap r.Body with a closer that returns the gzip reader
		// to the pool when the handler is done. This preserves
		// http.Request's Close() contract (the server calls it
		// after the handler returns).
		r.Body = &pooledGzipBody{
			Reader: gz,
			orig:   r.Body,
		}

		// Strip the Content-Encoding header so downstream handlers
		// don't see a mismatched (advertised: gzip; actual: plain)
		// body. Content-Length is also stale after decompression
		// so we clear it — handlers reading r.Body.Close don't
		// need it and any byte-counting decoder will read until
		// EOF naturally.
		r.Header.Del("Content-Encoding")
		r.Header.Del("Content-Length")
		r.ContentLength = -1

		next.ServeHTTP(w, r)
	})
}

// gzipReaderPool amortizes the ~30 KB allocation cost of a fresh
// gzip.Reader across requests. gzip.Reader.Reset() is the documented
// way to reuse an instance.
var gzipReaderPool = sync.Pool{
	New: func() interface{} {
		// Return nil so acquireGzipReader can detect the
		// first-use case and call gzip.NewReader with a fresh
		// source reader. Returning a zero-value gzip.Reader
		// without initialization would require calling Reset
		// immediately, which we do anyway — but this pattern
		// keeps the "allocate on first use" story simple.
		return nil
	},
}

// acquireGzipReader returns a gzip.Reader bound to r, pulling one
// from the pool if available. Must be paired with releaseGzipReader
// (called by pooledGzipBody.Close).
func acquireGzipReader(r interface{ Read(p []byte) (int, error) }) (*gzip.Reader, error) {
	if pooled := gzipReaderPool.Get(); pooled != nil {
		gz := pooled.(*gzip.Reader)
		// Reset rebinds the reader without reallocating internal
		// buffers. Returns an error only on header-parse failure,
		// which we surface to the caller as-is.
		if err := gz.Reset(readerAdapter{r}); err != nil {
			// Discard the pooled instance — Reset left it in an
			// indeterminate state.
			return nil, err
		}
		return gz, nil
	}
	return gzip.NewReader(readerAdapter{r})
}

// releaseGzipReader returns a gzip.Reader to the pool. Safe to call
// with nil. Does not close the underlying source reader — that's
// the caller's responsibility via pooledGzipBody.Close.
func releaseGzipReader(gz *gzip.Reader) {
	if gz == nil {
		return
	}
	gzipReaderPool.Put(gz)
}

// readerAdapter turns an `interface{ Read([]byte) (int, error) }`
// back into a concrete io.Reader. Used because http.Request.Body
// is io.ReadCloser but gzip.NewReader wants io.Reader specifically
// and Go's type system requires an explicit widening.
type readerAdapter struct {
	src interface{ Read(p []byte) (int, error) }
}

func (a readerAdapter) Read(p []byte) (int, error) {
	return a.src.Read(p)
}

// pooledGzipBody wraps a gzip.Reader with an io.ReadCloser so it
// can stand in for http.Request.Body. Close() closes the original
// body AND returns the gzip.Reader to the pool.
type pooledGzipBody struct {
	*gzip.Reader
	orig interface{ Close() error }
}

// Close closes both the gzip reader and the underlying body, then
// returns the gzip reader to the pool. Errors from the underlying
// body close are preserved; pool return is fire-and-forget (pool
// returns never error).
func (b *pooledGzipBody) Close() error {
	// Close the gzip reader first to flush any pending state.
	// Its error is informational — it means the request body was
	// truncated or corrupt, which we already surface via the
	// handler's own body parsing.
	_ = b.Reader.Close()
	releaseGzipReader(b.Reader)
	if b.orig != nil {
		return b.orig.Close()
	}
	return nil
}
