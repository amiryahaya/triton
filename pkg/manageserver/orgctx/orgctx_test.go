package orgctx_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/amiryahaya/triton/pkg/manageserver/orgctx"
)

func TestWithAndFrom_RoundTrip(t *testing.T) {
	id := uuid.Must(uuid.NewV7())
	ctx := orgctx.WithInstanceID(context.Background(), id)
	got, ok := orgctx.InstanceIDFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, id, got)
}

func TestFrom_MissingReturnsFalse(t *testing.T) {
	_, ok := orgctx.InstanceIDFromContext(context.Background())
	assert.False(t, ok)
}
