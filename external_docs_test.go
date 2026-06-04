package goauth_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExternalConsumerDocsPresent(t *testing.T) {
	t.Helper()

	paths := []string{
		"README.md",
		"RELEASING.md",
		"reference/externalconsumer/doc.go",
		"reference/externalconsumer/imports.go",
	}

	for _, path := range paths {
		_, err := os.Stat(path)
		require.NoErrorf(t, err, "expected externalization artifact %s", path)
	}
}
