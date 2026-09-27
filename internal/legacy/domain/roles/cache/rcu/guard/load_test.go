package rcucacheguard_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rcucacheguard "github.com/assurrussa/goauth/internal/legacy/domain/roles/cache/rcu/guard"
	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	listallroles "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_all_roles"
)

func TestLoadDataResponse(t *testing.T) {
	t.Parallel()

	useCase := &fakeRolesAllUseCase{
		err: errors.New("error"),
	}
	//nolint:nolintlint,ineffassign // it's valid
	data, err := rcucacheguard.LoadData(useCase)(context.Background())
	require.ErrorIs(t, err, useCase.err)
	require.Nil(t, data)

	useCase = &fakeRolesAllUseCase{
		resp: listallroles.Response{
			Roles: []model.Role{
				{ID: 1, UUID: "role-admin", Slug: "admin", Name: "Admin", IsSystem: true},
				{ID: 2, UUID: "role-editor", Slug: "editor", Name: "Editor"},
			},
			Permissions: []model.Permission{
				{ID: 10, UUID: "perm-roles-read", Domain: "roles", Action: "read"},
				{ID: 11, UUID: "perm-roles-write", Domain: "roles", Action: "write"},
			},
			RolePermissions: []model.RolePermission{
				{RoleID: 1, PermissionID: 10},
				{RoleID: 2, PermissionID: 11},
			},
			RoleHierarchy: []model.RoleHierarchy{
				{ParentRoleID: 1, ChildRoleID: 2},
			},
			SubjectRoles: []model.SubjectRole{
				{SubjectID: "123e4567-e89b-12d3-a456-426614174106", RoleID: 1},
			},
		},
	}

	//nolint:nolintlint,ineffassign // it's valid
	data, err = rcucacheguard.LoadData(useCase)(context.Background())
	require.NoError(t, err)

	enabled, ok := data["enabled"]
	require.True(t, ok)
	assert.True(t, enabled.Enabled)

	dataAll, ok := data["all"]
	require.True(t, ok)

	assert.True(t, dataAll.Enabled)
	require.Len(t, dataAll.Roles, 2)
	require.Len(t, dataAll.Permissions, 2)
	require.Len(t, dataAll.RolePermissions, 2)
	require.Len(t, dataAll.RoleHierarchy, 1)
	require.Len(t, dataAll.SubjectRole, 1)

	adminRole, ok := dataAll.Roles[1]
	require.True(t, ok)
	assert.Equal(t, "admin", adminRole.Slug)
	assert.True(t, adminRole.IsSystem)

	editorPerms := dataAll.RolePermissions[2]
	require.NotNil(t, editorPerms)
	if perm, ok := editorPerms[11]; assert.True(t, ok) {
		assert.Equal(t, int64(2), perm.RoleID)
		assert.Equal(t, int64(11), perm.PermissionID)
	}

	readPerm, ok := dataAll.Permissions[10]
	require.True(t, ok)
	assert.Equal(t, "roles", readPerm.Domain.String())
	assert.Equal(t, "read", readPerm.Action.String())

	hierarchy, ok := dataAll.RoleHierarchy[1]
	require.True(t, ok)
	child, ok := hierarchy[2]
	require.True(t, ok)
	assert.Equal(t, int64(1), child.ParentRoleID)
	assert.Equal(t, int64(2), child.ChildRoleID)

	adminAssignments, ok := dataAll.SubjectRole["123e4567-e89b-12d3-a456-426614174106"]
	require.True(t, ok)
	adminRoleData, ok := adminAssignments[1]
	require.True(t, ok)
	assert.Equal(t, int64(1), adminRoleData.RoleID)
}

type fakeRolesAllUseCase struct {
	resp listallroles.Response
	err  error
}

func (f *fakeRolesAllUseCase) Handle(context.Context, listallroles.Request) (listallroles.Response, error) {
	return f.resp, f.err
}
