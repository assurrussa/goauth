//nolint:testpackage // internal test
package externalconsumer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSupportedPackagesMatchesBlankImports(t *testing.T) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "imports.go"), nil, parser.ImportsOnly)
	require.NoError(t, err)

	imported := make([]string, 0, len(file.Imports))
	for _, spec := range file.Imports {
		require.NotNil(t, spec)
		require.Equal(t, "_", spec.Name.Name)

		path, err := strconv.Unquote(spec.Path.Value)
		require.NoError(t, err)
		imported = append(imported, path)
	}

	slices.Sort(imported)

	supported := slices.Collect(slices.Values(SupportedPackages))
	slices.Sort(supported)

	require.Equal(t, supported, imported)
	require.Equal(t, len(SupportedPackages), SupportedPackageCount)
}

func TestImportsFileContainsOnlyBlankImports(t *testing.T) {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(".", "imports.go"), nil, 0)
	require.NoError(t, err)

	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.IMPORT {
			continue
		}

		for _, spec := range genDecl.Specs {
			importSpec, ok := spec.(*ast.ImportSpec)
			require.True(t, ok)
			require.NotNil(t, importSpec.Name)
			require.Equal(t, "_", importSpec.Name.Name)
		}
	}
}

func TestSupportedPackagesHaveReleaseSurfaceCategory(t *testing.T) {
	t.Helper()

	supported := slices.Collect(slices.Values(SupportedPackages))
	slices.Sort(supported)

	categorized := make([]string, 0, len(StablePublicPackages)+len(HostSupportPackages))
	categorized = append(categorized, StablePublicPackages[:]...)
	categorized = append(categorized, HostSupportPackages[:]...)
	slices.Sort(categorized)

	require.NotEmpty(t, StablePublicPackages)
	require.Empty(t, HostSupportPackages, "host support packages should be collapsed behind stable integration packages")
	require.Equal(t, supported, categorized)
}

func TestStablePublicRolesSurfaceGoesThroughIntegrationFacade(t *testing.T) {
	t.Helper()

	banned := map[string]struct{}{
		"github.com/assurrussa/goauth/domain/roles/model":         {},
		"github.com/assurrussa/goauth/domain/roles/repository":    {},
		"github.com/assurrussa/goauth/domain/roles/service/guard": {},
		"github.com/assurrussa/goauth/domain/roles/service/roles": {},
		"github.com/assurrussa/goauth/domain/roles/shared":        {},
	}

	var offenders []string
	for _, pkg := range StablePublicPackages {
		if _, ok := banned[pkg]; ok {
			offenders = append(offenders, pkg)
		}
	}

	slices.Sort(offenders)
	require.Empty(t, offenders, "role domain packages should stay behind goauth/integration/roles")
}

func TestHostSupportRolesSurfaceGoesThroughIntegrationFacade(t *testing.T) {
	t.Helper()

	banned := map[string]struct{}{
		"github.com/assurrussa/goauth/domain/roles/seeders/rolesseed": {},
	}

	var offenders []string
	for _, pkg := range HostSupportPackages {
		if _, ok := banned[pkg]; ok {
			offenders = append(offenders, pkg)
		}
	}

	slices.Sort(offenders)
	require.Empty(t, offenders, "role host-support packages should stay behind goauth/integration/roles")
}

func TestHostSupportFiberAuthSurfaceGoesThroughIntegrationFacades(t *testing.T) {
	t.Helper()

	banned := map[string]struct{}{
		"github.com/assurrussa/goauth/http/fiber/legacysession":     {},
		"github.com/assurrussa/goauth/http/fiber/oidcbearer":        {},
		"github.com/assurrussa/goauth/http/fiber/oidclinkedsubject": {},
	}

	var offenders []string
	for _, pkg := range HostSupportPackages {
		if _, ok := banned[pkg]; ok {
			offenders = append(offenders, pkg)
		}
	}

	slices.Sort(offenders)
	require.Empty(t, offenders, "fiber auth adapters should stay behind goauth integration facades")
}

func TestHostSupportStorageSurfaceGoesThroughIntegrationFacade(t *testing.T) {
	t.Helper()

	banned := map[string]struct{}{
		"github.com/assurrussa/goauth/storage/pgsql/confirmationcoderepo":   {},
		"github.com/assurrussa/goauth/storage/pgsql/confirmationrepo":       {},
		"github.com/assurrussa/goauth/storage/pgsql/emailchangerepo":        {},
		"github.com/assurrussa/goauth/storage/pgsql/identitylinkrepo":       {},
		"github.com/assurrussa/goauth/storage/pgsql/oidcrefreshtokenrepo":   {},
		"github.com/assurrussa/goauth/storage/pgsql/passwordresettokenrepo": {},
		"github.com/assurrussa/goauth/storage/pgsql/refreshtokenrepo":       {},
		"github.com/assurrussa/goauth/storage/pgsql/sessionrepo":            {},
		"github.com/assurrussa/goauth/storage/pgsql/subjectrepo":            {},
		"github.com/assurrussa/goauth/storage/redis/oidcstate":              {},
	}

	var offenders []string
	for _, pkg := range HostSupportPackages {
		if _, ok := banned[pkg]; ok {
			offenders = append(offenders, pkg)
		}
	}

	slices.Sort(offenders)
	require.Empty(t, offenders, "storage adapters should stay behind goauth integration facades")
}

func TestHostSupportPackagesAreUsedByRepoHosts(t *testing.T) {
	t.Helper()

	if len(HostSupportPackages) == 0 {
		return
	}

	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if !repoHostsAvailable(root) {
		t.Skip("repo host check requires backend and goadmin sibling directories")
	}

	hostImports := collectHostGoauthImports(t, root)

	var unused []string
	for _, pkg := range HostSupportPackages {
		if _, ok := hostImports[pkg]; !ok {
			unused = append(unused, pkg)
		}
	}

	slices.Sort(unused)
	require.Empty(t, unused, "host-support packages should be imported by backend or goadmin runtime sources")
}

func repoHostsAvailable(root string) bool {
	for _, host := range []string{"backend", "goadmin"} {
		info, err := os.Stat(filepath.Join(root, host))
		if err != nil || !info.IsDir() {
			return false
		}
	}

	return true
}

func collectHostGoauthImports(t *testing.T, root string) map[string]struct{} {
	t.Helper()

	imports := make(map[string]struct{})
	for _, host := range []string{"backend", "goadmin"} {
		walkRoot := filepath.Join(root, host)
		err := filepath.WalkDir(walkRoot, func(path string, d os.DirEntry, err error) error {
			require.NoError(t, err)
			if d.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			fset := token.NewFileSet()
			file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			require.NoError(t, parseErr)

			for _, spec := range file.Imports {
				importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
				require.NoError(t, unquoteErr)
				if strings.HasPrefix(importPath, "github.com/assurrussa/goauth/") {
					imports[importPath] = struct{}{}
				}
			}

			return nil
		})
		require.NoError(t, err)
	}

	return imports
}
