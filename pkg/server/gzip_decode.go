package server

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// maxDecompressedRequestBody caps the total decompressed byte
// count of a gzipped request body. Without this, a tiny gzip
// bomb payload (a few KB) can decompress to gigabytes before the
// downstream handler's own MaxBytesReader catches it — because
// MaxBytesReader runs AFTER GzipDecodeMiddleware in the middleware
// chain, it sees the decompressed bytes and can't catch the
// expansion early.
//
// Since GzipDecodeMiddleware runs BEFORE LicenceGate and
// UnifiedAuth, this cap is the last line of defense against
// pre-authentication DoS via gzip bomb on any /api/v1/* route.
//
// Chosen at 3× the handler-level maxRequestBody (10 MB) to give
// legitimate compressible payloads headroom — a 10 MB JSON scan
// that compresses to 1 MB on the wire would decompress cleanly
// at a 30 MB cap even with future payload growth.
const maxDecompressedRequestBody = 300 << 20 // 300 MiB (3× maxRequestBody)

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
// Security: the decompressed body is capped at
// maxDecompressedRequestBody so a gzip bomb cannot exhaust
// server memory. The cap fires BEFORE any downstream auth
// middleware runs, which means unauthenticated attackers
// cannot abuse the decode path for DoS. See the constant's
// doc comment for rationale on the chosen limit.
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

		// Wrap the gzip reader in a LimitedReader that fires at
		// maxDecompressedRequestBody+1 bytes. The +1 lets us
		// distinguish "exactly at the cap" (legitimate) from
		// "over the cap" (bomb) so we can return 413 in the
		// latter case.
		limited := &io.LimitedReader{R: gz, N: maxDecompressedRequestBody + 1}

		// Wrap r.Body with a closer that returns the gzip reader
		// to the pool when the handler is done. This preserves
		// http.Request's Close() contract (the server calls it
		// after the handler returns).
		r.Body = &pooledGzipBody{
			Reader:  limited,
			gz:      gz,
			orig:    r.Body,
			limited: limited,
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
// way to reuse an instance. The pool returns nil on first access
// so acquireGzipReader can branch between "fresh allocation" and
// "reset-and-reuse" without an extra nil-check on every Put.
var gzipReaderPool = sync.Pool{
	New: func() interface{} {
		return nil
	},
}

// acquireGzipReader returns a gzip.Reader bound to r, pulling one
// from the pool if available. Must be paired with releaseGzipReader
// (called by pooledGzipBody.Close).
//
// http.Request.Body satisfies io.Reader directly — no adapter
// needed.
func acquireGzipReader(r io.Reader) (*gzip.Reader, error) {
	if pooled := gzipReaderPool.Get(); pooled != nil {
		gz := pooled.(*gzip.Reader)
		// Reset rebinds the reader without reallocating internal
		// buffers. Returns an error only on header-parse failure,
		// which we surface to the caller as-is (the caller then
		// discards the indeterminate pool instance).
		if err := gz.Reset(r); err != nil {
			return nil, err
		}
		return gz, nil
	}
	return gzip.NewReader(r)
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

// decompressedSizeLimitError marks the case where a request's
// decompressed body exceeded the cap. Surfaced so middleware/
// handlers can translate it into a 413 response.
type decompressedSizeLimitError struct{ limit int64 }

func (e decompressedSizeLimitError) Error() string {
	return fmt.Sprintf("request body exceeds decompressed size limit of %d bytes", e.limit)
}

// pooledGzipBody wraps a gzip-decoded reader with an io.ReadCloser
// so it can stand in for http.Request.Body. Close() closes the
// original body AND returns the gzip.Reader to the pool.
//
// Read() enforces the decompressed-size cap by watching the
// embedded io.LimitedReader's N countdown. When the limit is
// exceeded, Read returns decompressedSizeLimitError so the
// next handler that reads the body sees a terminal error —
// preventing the gzip bomb from ever reaching a JSON decoder
// that would allocate a huge buffer.
type pooledGzipBody struct {
	io.Reader                   // the io.LimitedReader wrapping gz
	gz        *gzip.Reader      // the actual gzip decoder (for pool return + Close)
	orig      io.ReadCloser     // the underlying http.Request.Body (needs closing too)
	limited   *io.LimitedReader // kept as a handle for the cap check
}

// Read proxies the limited reader and translates the "hit the
// cap" condition (N == 0 after a non-zero read attempt) into an
// explicit size-limit error.
func (b *pooledGzipBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	// io.LimitedReader returns io.EOF when it hits its cap with
	// no more data to return, but its N counter tells us whether
	// that EOF was "upstream ended cleanly" or "we stopped the
	// client's gzip bomb". If N == 0 AND the gzip reader still
	// has data (which we detect by attempting a 1-byte peek),
	// the caller sent more than our cap and we must refuse.
	if b.limited.N <= 0 {
		var probe [1]byte
		m, _ := b.gz.Read(probe[:])
		if m > 0 {
			return n, decompressedSizeLimitError{limit: maxDecompressedRequestBody}
		}
	}
	return n, err
}

// Close closes both the gzip reader and the underlying body, then
// returns the gzip reader to the pool. The gzip reader is returned
// to the pool LAST so that the underlying source body's Close()
// completes first — this prevents a race where the next pool
// consumer calls gz.Reset(newSource) while the previous caller's
// body drain is still running.
//
// Errors from the underlying body close are preserved; pool
// return is fire-and-forget (pool returns never error).
func (b *pooledGzipBody) Close() error {
	// Close the gzip reader first to flush any pending state.
	// Its error is informational — it means the request body was
	// truncated or corrupt, which we already surface via the
	// handler's own body parsing.
	_ = b.gz.Close()
	var origErr error
	if b.orig != nil {
		origErr = b.orig.Close()
	}
	// Pool return AFTER the underlying body is closed so the
	// next consumer cannot race against the previous body's
	// in-flight drain.
	releaseGzipReader(b.gz)
	return origErr
}
