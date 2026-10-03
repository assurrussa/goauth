//nolint:testpackage // internal test
package externalconsumerprobe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
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

func TestBuildPostgresProbeTestIsValidGo(t *testing.T) {
	content, err := Config{LocalPath: t.TempDir()}.BuildPostgresProbeTest()
	require.NoError(t, err)
	_, err = parser.ParseFile(token.NewFileSet(), "externalconsumer_postgres_test.go", content, parser.AllErrors)
	require.NoError(t, err)
	require.Contains(t, content, `github.com/assurrussa/goauth/postgres`)
	require.Contains(t, content, "func TestPostgresRuntimeExternalConsumer")
}

func TestOptionalModuleTemplatesRemainRunnableAndPublic(t *testing.T) {
	cfg := Config{ModulePath: "example.test/auth", LocalPath: t.TempDir()}
	for _, test := range []struct {
		name  string
		build func() (string, error)
		tests []string
	}{
		{"memory", cfg.BuildProbeTest, []string{
			"TestDisabledDeliveryRuntimeExternalConsumer", "TestCredentialAdmissionExternalConsumer",
			"TestTrustedLocalPasswordExternalConsumer",
		}},
		{"postgres", cfg.BuildPostgresProbeTest, []string{
			"TestManagedHostTransactionExternalConsumer", "TestCredentialProofExternalConsumer",
			"TestPasswordResetReceiptExternalConsumer", "TestDisabledDeliveryPostgresExternalConsumer",
			"TestTrustedLocalPasswordManagedExternalConsumer",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, err := test.build()
			require.NoError(t, err)
			require.NotContains(t, source, "GOAUTH_MODULE")
			file, err := parser.ParseFile(token.NewFileSet(), test.name+"_test.go", source, parser.AllErrors)
			require.NoError(t, err)
			functions := make(map[string]bool)
			for _, decl := range file.Decls {
				if function, ok := decl.(*ast.FuncDecl); ok {
					functions[function.Name.Name] = true
				}
			}
			for _, name := range test.tests {
				require.True(t, functions[name], "missing executable contract %s", name)
			}
			for _, importSpec := range file.Imports {
				path, err := strconv.Unquote(importSpec.Path.Value)
				require.NoError(t, err)
				if !strings.HasPrefix(path, cfg.ModulePath) {
					continue
				}
				supported := false
				for _, pkg := range externalconsumer.SupportedPackages {
					if path == strings.Replace(pkg, DefaultModulePath, cfg.ModulePath, 1) {
						supported = true
						break
					}
				}
				require.True(t, supported, "consumer imported unsupported package %s", path)
			}
		})
	}
}
