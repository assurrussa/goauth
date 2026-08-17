package rbac_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

func TestManagementValidationAndMapping(t *testing.T) {
	t.Parallel()
	store := &storeStub{
		roles:       []rbac.Role{{ID: 1, Slug: testRoleSlug, Name: testRoleName}},
		permissions: []rbac.Permission{{ID: 2, Key: rbac.MustPermissionKey("content", "read")}},
		snapshot: rbac.Snapshot{
			RolePermissions: []rbac.RolePermission{{RoleID: 1, PermissionID: 2}},
		},
	}
	service, err := rbac.New(store, nil)
	require.NoError(t, err)
	ctx := context.Background()

	roles, err := service.Roles(ctx, rbac.RoleFilter{IncludeSystem: true, Search: testRoleSlug})
	require.NoError(t, err)
	require.Len(t, roles, 1)
	role, err := service.Role(ctx, 1)
	require.NoError(t, err)
	require.Equal(t, testRoleSlug, role.Slug)
	created, err := service.CreateRole(ctx, rbac.Role{Slug: "author", Name: " Author "}, nil)
	require.NoError(t, err)
	require.Equal(t, "Author", created.Name)
	keys := []rbac.PermissionKey{
		rbac.MustPermissionKey("content", "read"),
		rbac.MustPermissionKey("content", "read"),
	}
	_, err = service.UpdateRole(ctx, rbac.Role{ID: 1, Slug: testRoleSlug, Name: testRoleName}, &keys)
	require.NoError(t, err)
	require.NoError(t, service.ReplaceRolePermissions(ctx, 1, keys))
	require.Equal(t, []rbac.PermissionKey{keys[0]}, store.permissionKeys)
	require.NoError(t, service.ReplaceSubjectRoles(ctx, goauth.NewSubjectID(), []int64{1, 1}))
	permissions, err := service.Permissions(ctx, rbac.PermissionFilter{Domain: "content"})
	require.NoError(t, err)
	require.Len(t, permissions, 1)
	_, err = service.RolePermissions(ctx, 1)
	require.NoError(t, err)
	_, err = service.SubjectRoles(ctx, goauth.NewSubjectID())
	require.NoError(t, err)
	snapshot, err := service.Snapshot(ctx)
	require.NoError(t, err)
	require.Len(t, snapshot.RolePermissions, 1)
	require.NoError(t, service.DeleteRole(ctx, 1))
}

func TestManagementRejectsInvalidInputs(t *testing.T) {
	t.Parallel()
	service, err := rbac.New(&storeStub{}, nil)
	require.NoError(t, err)
	ctx := context.Background()

	_, err = service.Roles(ctx, rbac.RoleFilter{IDs: []int64{0}})
	require.ErrorIs(t, err, rbac.ErrInvalidRole)
	_, err = service.Role(ctx, 0)
	require.ErrorIs(t, err, rbac.ErrInvalidRole)
	_, err = service.CreateRole(ctx, rbac.Role{Slug: "Bad Role", Name: "Bad"}, nil)
	require.ErrorIs(t, err, rbac.ErrInvalidRole)
	_, err = service.UpdateRole(
		ctx,
		rbac.Role{ID: 1, Slug: "role", Name: "Role"},
		pointer([]rbac.PermissionKey{invalidValue}),
	)
	require.ErrorIs(t, err, rbac.ErrInvalidPermissionKey)
	require.ErrorIs(t, service.DeleteRole(ctx, 0), rbac.ErrInvalidRole)
	_, err = service.Permissions(ctx, rbac.PermissionFilter{Domain: "Bad Domain"})
	require.ErrorIs(t, err, rbac.ErrInvalidPermissionKey)
	_, err = service.RolePermissions(ctx, 0)
	require.ErrorIs(t, err, rbac.ErrInvalidRole)
	require.ErrorIs(t, service.ReplaceRolePermissions(ctx, 0, nil), rbac.ErrInvalidRole)
	require.ErrorIs(t, service.ReplaceSubjectRoles(ctx, goauth.NilSubjectID, nil), goauth.ErrInvalidSubjectID)
	require.ErrorIs(t, service.ReplaceSubjectRoles(ctx, goauth.NewSubjectID(), []int64{0}), rbac.ErrInvalidRole)
	_, err = service.SubjectRoles(ctx, goauth.NilSubjectID)
	require.ErrorIs(t, err, goauth.ErrInvalidSubjectID)
	require.True(t, rbac.IsNotFound(rbac.ErrRoleNotFound))
}

func pointer[T any](value T) *T { return &value }
