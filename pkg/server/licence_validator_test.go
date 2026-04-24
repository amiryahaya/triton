package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestComputeLicenceStatus_Active(t *testing.T) {
	require.Equal(t, "active", computeLicenceStatus(time.Now().Add(60*24*time.Hour)))
}

func TestComputeLicenceStatus_Grace(t *testing.T) {
	require.Equal(t, "grace", computeLicenceStatus(time.Now().Add(-5*24*time.Hour)))
}

func TestComputeLicenceStatus_Expired(t *testing.T) {
	require.Equal(t, "expired", computeLicenceStatus(time.Now().Add(-35*24*time.Hour)))
}
