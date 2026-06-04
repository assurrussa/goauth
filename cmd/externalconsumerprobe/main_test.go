package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProbeTestArgsAllowModuleFileUpdates(t *testing.T) {
	t.Helper()

	require.Equal(t, []string{"test", "-mod=mod", "./...", "-count=1"}, probeTestArgs())
}
