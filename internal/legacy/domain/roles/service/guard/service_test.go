package rolesguardservice_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/logger"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	rolesguardservice "github.com/assurrussa/goauth/internal/legacy/domain/roles/service/guard"
	rolesshared "github.com/assurrussa/goauth/internal/legacy/domain/roles/shared"
	listsubjectroles "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_subject_roles"
)

var (
	testDomain     = rolesshared.PermissionDomain("test")
	testActionRead = rolesshared.PermissionAction("read")
)

func TestSubjectGuardCheckBypassRole(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjectID := "123e4567-e89b-12d3-a456-426614174108"
	svc := rolesguardservice.Must(rolesguardservice.NewOptions(
		&rolesUseCaseStub{
			resp: listsubjectroles.Response{
				Roles: []model.Role{{ID: 1, Slug: rolesshared.SuperAdminRole}},
			},
		},
		&permissionUseCaseStub{},
		&cacheStub{},
		logger.Discard(),
	))

	ok := svc.SubjectGuardCheck(ctx, subjectID, rolesshared.NewPermissionKey(testDomain, testActionRead))
	require.True(t, ok)
}

func TestSubjectGuardCheckPermissionGranted(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjectID := "123e4567-e89b-12d3-a456-426614174109"
	key := rolesshared.NewPermissionKey(testDomain, testActionRead)
	permissions := &permissionUseCaseStub{allowed: true}
	svc := rolesguardservice.Must(rolesguardservice.NewOptions(
		&rolesUseCaseStub{
			resp: listsubjectroles.Response{
				Roles: []model.Role{{ID: 1, Slug: "manager"}},
			},
		},
		permissions,
		&cacheStub{},
		logger.Discard(),
	))

	ok := svc.SubjectGuardCheck(ctx, subjectID, key)
	require.True(t, ok)
	require.Equal(t, subjectID, permissions.lastSubjectID)
}

func TestSubjectGuardCheckReturnsFalseForMissingSubject(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	svc := rolesguardservice.Must(rolesguardservice.NewOptions(
		&rolesUseCaseStub{},
		&permissionUseCaseStub{},
		&cacheStub{},
		logger.Discard(),
	))

	ok := svc.SubjectGuardCheck(ctx, "", rolesshared.NewPermissionKey(testDomain, testActionRead))
	require.False(t, ok)
}

func TestGetRolesSubjectUsesCache(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjectID := "123e4567-e89b-12d3-a456-426614174110"
	expected := []model.Role{{ID: 7, Slug: "cached"}}
	svc := rolesguardservice.Must(rolesguardservice.NewOptions(
		&rolesUseCaseStub{err: errors.New("repository should not be called")},
		&permissionUseCaseStub{},
		&cacheStub{enabled: true, roles: map[string][]model.Role{subjectID: expected}},
		logger.Discard(),
	))

	got, err := svc.GetRolesSubject(ctx, subjectID)
	require.NoError(t, err)
	require.Equal(t, expected, got)
}

func TestCachedGuardChecksEveryRole(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subjectID := "123e4567-e89b-12d3-a456-426614174111"
	roles := []model.Role{{ID: 1, Slug: "first"}, {ID: 2, Slug: "second"}}
	key := rolesshared.NewPermissionKey(testDomain, testActionRead)
	svc := rolesguardservice.Must(rolesguardservice.NewOptions(
		&rolesUseCaseStub{},
		&permissionUseCaseStub{},
		&cacheStub{
			enabled: true,
			roles:   map[string][]model.Role{subjectID: roles},
			permissions: map[int64]map[int64]model.Permission{
				1: {10: {ID: 10, Domain: testDomain, Action: rolesshared.PermissionAction("write")}},
				2: {11: {ID: 11, Domain: testDomain, Action: testActionRead}},
			},
		},
		logger.Discard(),
	))

	require.True(t, svc.SubjectGuardCheck(ctx, subjectID, key))
}

type rolesUseCaseStub struct {
	resp listsubjectroles.Response
	err  error
}

func (s *rolesUseCaseStub) Handle(_ context.Context, _ listsubjectroles.Request) (listsubjectroles.Response, error) {
	return s.resp, s.err
}

type permissionUseCaseStub struct {
	allowed       bool
	err           error
	lastSubjectID string
}

func (s *permissionUseCaseStub) ListAllPermissionsByRoles(
	context.Context,
	[]int64,
) ([]model.PermissionWithRole, error) {
	return nil, nil
}

func (s *permissionUseCaseStub) HasPermission(
	_ context.Context,
	subjectID string,
	_ rolesshared.PermissionKey,
) (bool, error) {
	s.lastSubjectID = subjectID
	return s.allowed, s.err
}

type cacheStub struct {
	enabled     bool
	roles       map[string][]model.Role
	permissions map[int64]map[int64]model.Permission
}

func (s *cacheStub) Enabled(context.Context) bool {
	return s.enabled
}

func (s *cacheStub) SubjectRoles(subjectID string) []model.Role {
	return s.roles[subjectID]
}

func (s *cacheStub) AllRolePermissions([]model.Role) map[int64]map[int64]model.Permission {
	return s.permissions
}
