package goauth_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestModuleDoesNotDependOnGoadmin(t *testing.T) {
	t.Helper()

	content, err := os.ReadFile("go.mod")
	require.NoError(t, err)

	require.NotContains(t, string(content), "github.com/assurrussa/goadmin")
	require.NotContains(t, string(content), "github.com/assurrussa/blog")

	err = filepath.WalkDir(".", func(path string, d os.DirEntry, walkErr error) error {
		require.NoError(t, walkErr)
		if d.IsDir() || filepath.Ext(path) != ".go" {
			return nil
		}
		if path == "module_independence_test.go" {
			return nil
		}

		//nolint:gosec // this is a test script running over safe local paths
		source, err := os.ReadFile(path)
		require.NoError(t, err)
		require.NotContainsf(
			t,
			string(source),
			"github.com/assurrussa/goadmin",
			"unexpected goadmin import in %s",
			path,
		)
		require.NotContainsf(
			t,
			string(source),
			"github.com/assurrussa/blog",
			"unexpected backend/blog import in %s",
			path,
		)

		return nil
	})
	require.NoError(t, err)
}
