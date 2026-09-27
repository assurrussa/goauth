package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProbeTestArgsAllowModuleFileUpdates(t *testing.T) {
	t.Helper()

	require.Equal(t, []string{"test", "-mod=mod", "./...", "-count=1"}, probeTestArgs())
}

func TestPostgresIntegrationRequiresDSN(t *testing.T) {
	t.Setenv("GOAUTH_TEST_POSTGRES_DSN", "")
	err := run(t.Context(), []string{"--local-path", t.TempDir(), "--postgres-integration"})
	require.EqualError(t, err, "GOAUTH_TEST_POSTGRES_DSN is required for the PostgreSQL external consumer probe")
}
