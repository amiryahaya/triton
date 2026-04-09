//go:build system

package system_test

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// pgxConnect is a thin wrapper around pgx.Connect so the rest of
// the system test suite doesn't import pgx directly. Keeping the
// import localized here makes it trivial to swap for an alternate
// driver if we ever need one.
func pgxConnect(ctx context.Context, url string) (*pgx.Conn, error) {
	return pgx.Connect(ctx, url)
}
