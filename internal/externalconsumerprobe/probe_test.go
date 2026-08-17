//nolint:testpackage // internal test
package externalconsumerprobe

import (
	"testing"

	"github.com/stretchr/testify/require"

	externalconsumer "github.com/assurrussa/goauth/reference/externalconsumer"
)

func TestConfigValidateRequiresVersionOrLocalPath(t *testing.T) {
	t.Helper()

	err := Config{
		ProbeModule: DefaultProbeModule,
		ModulePath:  DefaultModulePath,
	}.Validate()

	require.EqualError(t, err, "external consumer probe: version or local path is required")
}

func TestBuildGoModIncludesReplaceForLocalPath(t *testing.T) {
	t.Helper()

	content, err := Config{
		ProbeModule: DefaultProbeModule,
		ModulePath:  DefaultModulePath,
		LocalPath:   "/tmp/goauth",
	}.BuildGoMod()
	require.NoError(t, err)

	require.Contains(t, content, "module example.com/goauthprobe")
	require.Contains(t, content, "require github.com/assurrussa/goauth v0.0.0-local")
	require.Contains(t, content, "replace github.com/assurrussa/goauth => /tmp/goauth")
}

func TestBuildGoModUsesPublishedVersionWithoutReplace(t *testing.T) {
	t.Helper()

	content, err := Config{
		ProbeModule: DefaultProbeModule,
		ModulePath:  DefaultModulePath,
		Version:     "v0.1.0",
	}.BuildGoMod()
	require.NoError(t, err)

	require.Contains(t, content, "require github.com/assurrussa/goauth v0.1.0")
	require.NotContains(t, content, "replace github.com/assurrussa/goauth")
}

func TestBuildProbeTestImportsSupportedPackages(t *testing.T) {
	t.Helper()

	content, err := Config{
		ProbeModule: DefaultProbeModule,
		ModulePath:  DefaultModulePath,
		LocalPath:   "/tmp/goauth",
	}.BuildProbeTest()
	require.NoError(t, err)

	require.Contains(t, content, `package probe`)
	for _, pkg := range externalconsumer.SupportedPackages {
		require.Contains(t, content, `"`+pkg+`"`)
	}
	require.Contains(t, content, "func TestRuntimeFiberOIDCAndRBACWiring")
}
