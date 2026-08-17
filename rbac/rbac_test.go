package rbac_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

const (
	testRoleName = "Editor"
	testRoleSlug = "editor"
	invalidValue = "bad"
)

func TestCachedAndUncachedChecksUseTheSamePermissionSemantics(t *testing.T) {
	t.Parallel()
	subjectID := goauth.NewSubjectID()
	key := rbac.MustPermissionKey("content", "publish")
	store := &storeStub{allowed: true}
	uncached, err := rbac.New(store, nil)
	require.NoError(t, err)
	cached, err := rbac.New(store, cacheStub{allowed: true, found: true})
	require.NoError(t, err)

	require.True(t, uncached.Can(context.Background(), subjectID, key))
	require.True(t, cached.Can(context.Background(), subjectID, key))
}

func TestCacheFailureIsFailClosed(t *testing.T) {
	t.Parallel()
	service, err := rbac.New(&storeStub{allowed: true}, cacheStub{err: context.Canceled})
	require.NoError(t, err)
	require.False(t, service.Can(
		context.Background(),
		goauth.NewSubjectID(),
		rbac.MustPermissionKey("content", "read"),
	))
}

func TestPermissionKeyValidation(t *testing.T) {
	t.Parallel()
	key, err := rbac.NewPermissionKey("content", "read")
	require.NoError(t, err)
	require.Equal(t, rbac.PermissionKey("content:read"), key)
	for _, value := range []rbac.PermissionKey{"", "content", ":read", "Content:read", "content:read:all"} {
		require.ErrorIs(t, value.Validate(), rbac.ErrInvalidPermissionKey)
	}
	require.Panics(t, func() { rbac.MustPermissionKey("invalid domain", "read") })
}

func TestServiceManagementAndFailClosedValidation(t *testing.T) {
	t.Parallel()
	store := &storeStub{allowed: true}
	service, err := rbac.New(store, cacheStub{found: false})
	require.NoError(t, err)
	subjectID := goauth.NewSubjectID()
	read := rbac.MustPermissionKey("content", "read")
	write := rbac.MustPermissionKey("content", "write")

	require.NoError(t, service.Require(context.Background(), subjectID, read))
	store.allowed = false
	require.ErrorIs(t, service.Require(context.Background(), subjectID, read), rbac.ErrPermissionDenied)
	require.False(t, service.Can(context.Background(), goauth.NilSubjectID, read))
	require.False(t, service.Can(context.Background(), subjectID, "invalid"))
	store.permissionErr = errors.New("storage unavailable")
	require.False(t, service.Can(context.Background(), subjectID, read))
	store.permissionErr = nil

	role, err := service.UpsertRole(context.Background(), rbac.Role{Slug: testRoleSlug, Name: testRoleName})
	require.NoError(t, err)
	require.Equal(t, testRoleSlug, role.Slug)
	_, err = service.UpsertRole(context.Background(), rbac.Role{Slug: "Bad Role", Name: testRoleName})
	require.Error(t, err)
	permission, err := service.UpsertPermission(context.Background(), rbac.Permission{Key: read})
	require.NoError(t, err)
	require.Equal(t, read, permission.Key)
	_, err = service.UpsertPermission(context.Background(), rbac.Permission{Key: invalidValue})
	require.ErrorIs(t, err, rbac.ErrInvalidPermissionKey)
	require.NoError(t, service.AssignRole(context.Background(), subjectID, testRoleSlug))
	require.Error(t, service.AssignRole(context.Background(), goauth.NilSubjectID, testRoleSlug))
	require.NoError(t, service.SetRolePermissions(context.Background(), testRoleSlug, []rbac.PermissionKey{read, write, read}))
	require.Equal(t, []rbac.PermissionKey{read, write}, store.permissionKeys)
	require.Error(t, service.SetRolePermissions(context.Background(), "Bad Role", []rbac.PermissionKey{read}))
	require.ErrorIs(
		t,
		service.SetRolePermissions(context.Background(), testRoleSlug, []rbac.PermissionKey{invalidValue}),
		rbac.ErrInvalidPermissionKey,
	)
}

func TestNewRequiresStore(t *testing.T) {
	t.Parallel()
	_, err := rbac.New(nil, nil)
	require.EqualError(t, err, "RBAC store is required")
}

func TestAuthorizationOnlyStoreDoesNotNeedManagementContract(t *testing.T) {
	t.Parallel()
	service, err := rbac.New(authorizationStore{}, nil)
	require.NoError(t, err)
	require.True(t, service.Can(
		context.Background(),
		goauth.NewSubjectID(),
		rbac.MustPermissionKey("content", "read"),
	))
	_, err = service.Roles(context.Background(), rbac.RoleFilter{})
	require.ErrorIs(t, err, rbac.ErrManagementUnavailable)
}

type authorizationStore struct{}

func (authorizationStore) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, error) {
	return true, nil
}

type storeStub struct {
	allowed        bool
	permissionErr  error
	permissionKeys []rbac.PermissionKey
	roles          []rbac.Role
	permissions    []rbac.Permission
	subjectRoles   []rbac.Role
	snapshot       rbac.Snapshot
}

func (s *storeStub) HasPermission(context.Context, goauth.SubjectID, rbac.PermissionKey) (bool, error) {
	return s.allowed, s.permissionErr
}

func (s *storeStub) UpsertRole(_ context.Context, role rbac.Role) (rbac.Role, error) {
	return role, nil
}

func (s *storeStub) UpsertPermission(
	_ context.Context,
	permission rbac.Permission,
) (rbac.Permission, error) {
	return permission, nil
}

func (s *storeStub) AssignRole(context.Context, goauth.SubjectID, string) error {
	return nil
}

func (s *storeStub) SetRolePermissions(_ context.Context, _ string, keys []rbac.PermissionKey) error {
	s.permissionKeys = append([]rbac.PermissionKey(nil), keys...)
	return nil
}

func (s *storeStub) ListRoles(context.Context, rbac.RoleFilter) ([]rbac.Role, error) {
	return s.roles, nil
}

func (s *storeStub) GetRole(context.Context, int64) (rbac.Role, error) {
	if len(s.roles) == 0 {
		return rbac.Role{}, rbac.ErrRoleNotFound
	}
	return s.roles[0], nil
}

func (s *storeStub) CreateRole(_ context.Context, role rbac.Role, _ []rbac.PermissionKey) (rbac.Role, error) {
	return role, nil
}

func (s *storeStub) UpdateRole(_ context.Context, role rbac.Role, _ *[]rbac.PermissionKey) (rbac.Role, error) {
	return role, nil
}

func (s *storeStub) DeleteRole(context.Context, int64) error { return nil }

func (s *storeStub) ListPermissions(context.Context, rbac.PermissionFilter) ([]rbac.Permission, error) {
	return s.permissions, nil
}

func (s *storeStub) ListRolePermissions(context.Context, int64) ([]rbac.Permission, error) {
	return s.permissions, nil
}

func (s *storeStub) ReplaceRolePermissions(_ context.Context, _ int64, keys []rbac.PermissionKey) error {
	s.permissionKeys = append([]rbac.PermissionKey(nil), keys...)
	return nil
}

func (s *storeStub) ReplaceSubjectRoles(context.Context, goauth.SubjectID, []int64) error {
	return nil
}

func (s *storeStub) ListSubjectRoles(context.Context, goauth.SubjectID) ([]rbac.Role, error) {
	return s.subjectRoles, nil
}

func (s *storeStub) Snapshot(context.Context) (rbac.Snapshot, error) { return s.snapshot, nil }

type cacheStub struct {
	allowed bool
	found   bool
	err     error
}

func (c cacheStub) HasPermission(
	context.Context,
	goauth.SubjectID,
	rbac.PermissionKey,
) (allowed bool, found bool, err error) {
	return c.allowed, c.found, c.err
}
