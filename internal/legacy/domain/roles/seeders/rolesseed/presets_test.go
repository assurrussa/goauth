//nolint:testpackage // Internal pure-policy helpers must be tested before DB writes.
package rolesseed

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/shared"
)

const (
	cmsEditorRoleSlug = "cms_editor"
	cmsEditorRoleName = "CMS editor"
)

func TestWithRolePresetsCopiesCallerPolicy(t *testing.T) {
	permission := shared.NewPermissionKey("cms.entry", "read")
	presets := []RolePreset{{
		Slug: cmsEditorRoleSlug, Permissions: []shared.PermissionKey{permission},
	}}
	seed := &Seed{}

	WithRolePresets(presets...)(seed)
	presets[0].Slug = "changed"
	presets[0].Permissions[0] = shared.NewPermissionKey("cms.entry", "delete")

	require.Equal(t, cmsEditorRoleSlug, seed.rolePresets[0].Slug)
	require.Equal(t, permission, seed.rolePresets[0].Permissions[0])
}

func TestBuildSeedRolesAppendsValidatedPresets(t *testing.T) {
	permission := shared.NewPermissionKey("cms.entry", "read")
	catalog := shared.NewPermissionCatalog([]shared.PermissionDefinition{
		{Key: permission, Description: "Read CMS entries"},
	})

	roles, err := buildSeedRoles(catalog, []RolePreset{{
		Slug: "  " + cmsEditorRoleSlug + "  ", Name: "  " + cmsEditorRoleName + "  ", IsSystem: true,
		Permissions: []shared.PermissionKey{permission},
	}})

	require.NoError(t, err)
	require.Len(t, roles, 3)
	require.Equal(t, cmsEditorRoleSlug, roles[2].Slug)
	require.Equal(t, cmsEditorRoleName, roles[2].Name)
	require.Equal(t, []shared.PermissionKey{permission}, roles[2].Permissions)
}

func TestBuiltInContentAdminDescriptionMatchesPermissions(t *testing.T) {
	t.Parallel()

	roles, err := buildSeedRoles(shared.NewPermissionCatalog(shared.DefaultPermissionDefinitions().Data), nil)
	require.NoError(t, err)
	require.Equal(t, contentAdminRoleSlug, roles[1].Slug)
	require.Equal(
		t,
		"Просмотр ролей и разрешений; доступ к CMS назначается отдельной CMS-ролью",
		roles[1].Description,
	)
}

func TestBuildSeedRolesRejectsInvalidPresets(t *testing.T) {
	permission := shared.NewPermissionKey("cms.entry", "read")
	catalog := shared.NewPermissionCatalog([]shared.PermissionDefinition{
		{Key: permission, Description: "Read CMS entries"},
	})

	tests := []struct {
		name    string
		presets []RolePreset
	}{
		{
			name: "reserved slug",
			presets: []RolePreset{{
				Slug: superAdminRoleSlug, Permissions: []shared.PermissionKey{permission},
			}},
		},
		{
			name: "duplicate slug",
			presets: []RolePreset{
				{Slug: cmsEditorRoleSlug, Name: cmsEditorRoleName, Permissions: []shared.PermissionKey{permission}},
				{Slug: " " + cmsEditorRoleSlug + " ", Name: "Duplicate", Permissions: []shared.PermissionKey{permission}},
			},
		},
		{
			name: "blank slug",
			presets: []RolePreset{{
				Slug: " ", Name: cmsEditorRoleName, Permissions: []shared.PermissionKey{permission},
			}},
		},
		{
			name: "blank name",
			presets: []RolePreset{{
				Slug: cmsEditorRoleSlug, Name: " ", Permissions: []shared.PermissionKey{permission},
			}},
		},
		{
			name: "unknown permission",
			presets: []RolePreset{{
				Slug: cmsEditorRoleSlug, Name: cmsEditorRoleName,
				Permissions: []shared.PermissionKey{
					shared.NewPermissionKey("cms.entry", "delete"),
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildSeedRoles(catalog, tt.presets)
			require.Error(t, err)
		})
	}
}
