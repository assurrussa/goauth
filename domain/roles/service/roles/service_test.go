package rolesservice_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"github.com/assurrussa/goauth/domain/roles/model"
	"github.com/assurrussa/goauth/domain/roles/repository"
	repositorymocks "github.com/assurrussa/goauth/domain/roles/repository/mocks"
	rolesservice "github.com/assurrussa/goauth/domain/roles/service/roles"
	"github.com/assurrussa/goauth/domain/roles/shared"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

func mkPermissionKey(domain, action string) shared.PermissionKey {
	return shared.NewPermissionKey(shared.PermissionDomain(domain), shared.PermissionAction(action))
}

type testSuite struct {
	suite.Suite

	mockRoleRepository       *repositorymocks.MockRoleRepository
	mockPermissionRepository *repositorymocks.MockPermissionRepository
	mockAssignmentRepository *repositorymocks.MockAssignmentRepository
	mockHierarchyRepository  *repositorymocks.MockHierarchyRepository

	svc         *rolesservice.Service
	errExpected error
}

func newTestSuite(t *testing.T) (context.Context, context.CancelFunc, *testSuite) {
	t.Helper()

	return tests.NewSuite[*testSuite](t, func(t *testing.T, _ context.Context) *testSuite {
		t.Helper()

		ctrl := gomock.NewController(t)
		mockRoleRepository := repositorymocks.NewMockRoleRepository(ctrl)
		mockPermissionRepository := repositorymocks.NewMockPermissionRepository(ctrl)
		mockAssignmentRepository := repositorymocks.NewMockAssignmentRepository(ctrl)
		mockHierarchyRepository := repositorymocks.NewMockHierarchyRepository(ctrl)

		svc := rolesservice.Must(rolesservice.Dependencies{
			Roles:       mockRoleRepository,
			Permissions: mockPermissionRepository,
			Assignments: mockAssignmentRepository,
			Hierarchy:   mockHierarchyRepository,
		})

		return &testSuite{
			mockRoleRepository:       mockRoleRepository,
			mockPermissionRepository: mockPermissionRepository,
			mockAssignmentRepository: mockAssignmentRepository,
			mockHierarchyRepository:  mockHierarchyRepository,
			svc:                      svc,
			errExpected:              errors.New("expected error"),
		}
	})
}

func Test_MustInit(t *testing.T) {
	_, _, ts := newTestSuite(t)

	ts.Require().Panics(func() {
		rolesservice.Must(rolesservice.Dependencies{})
	})
}

func TestService_CreateRole_AssignsPermissions(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	key := mkPermissionKey("roles", "read")

	ts.mockRoleRepository.EXPECT().
		Create(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, input model.Role) (*model.Role, error) {
			ts.Equal("reader", input.Slug)
			ts.Equal("Reader", input.Name)
			input.ID = 42
			return &input, nil
		})

	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, repository.PermissionFilter{Keys: []shared.PermissionKey{key}}).
		Return([]model.Permission{{ID: 10, Domain: "roles", Action: "read"}}, nil)

	ts.mockAssignmentRepository.EXPECT().
		ReplacePermissions(ctx, int64(42), []int64{10}).
		Return(nil)

	role, err := ts.svc.CreateRole(ctx, rolesservice.CreateRoleInput{
		Slug:        " reader ",
		Name:        " Reader ",
		Description: nil,
		IsSystem:    false,
		Permissions: []shared.PermissionKey{
			key,
			key, // duplicate should be ignored
		},
	})

	ts.Require().NoError(err)
	ts.Equal(int64(42), role.ID)
	ts.Equal("reader", role.Slug)
	ts.Equal("Reader", role.Name)
}

func TestService_CreateRole_ValidationErrors(t *testing.T) {
	t.Helper()

	testCases := []struct {
		name  string
		input rolesservice.CreateRoleInput
		err   error
	}{
		{
			name: "empty slug",
			input: rolesservice.CreateRoleInput{
				Slug: "   ",
				Name: "Role",
			},
			err: shared.ErrInvalidRoleSlug,
		},
		{
			name: "empty name",
			input: rolesservice.CreateRoleInput{
				Slug: "role",
				Name: "   ",
			},
			err: rolesservice.ErrInvalidRoleName,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx, _, ts := newTestSuite(t)

			role, err := ts.svc.CreateRole(ctx, tc.input)
			ts.Require().ErrorIs(err, tc.err)
			ts.Nil(role)
		})
	}
}

func TestService_CreateRole_ReplacePermissionsError(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	key := mkPermissionKey("roles", "read")

	ts.mockRoleRepository.EXPECT().
		Create(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, input model.Role) (*model.Role, error) {
			input.ID = 100
			return &input, nil
		})

	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, repository.PermissionFilter{Keys: []shared.PermissionKey{key}}).
		Return([]model.Permission{{ID: 55, Domain: "roles", Action: "read"}}, nil)

	ts.mockAssignmentRepository.EXPECT().
		ReplacePermissions(ctx, int64(100), []int64{55}).
		Return(ts.errExpected)

	role, err := ts.svc.CreateRole(ctx, rolesservice.CreateRoleInput{
		Slug:        "reader",
		Name:        "Reader",
		Permissions: []shared.PermissionKey{key},
	})
	ts.Require().Error(err)
	ts.Nil(role)
	ts.Contains(err.Error(), "replace permissions")
}

func TestService_CreateRole_MissingPermissions(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	key := mkPermissionKey("roles", "write")

	ts.mockRoleRepository.EXPECT().
		Create(ctx, gomock.Any()).
		Return(&model.Role{ID: 20}, nil)

	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, repository.PermissionFilter{Keys: []shared.PermissionKey{key}}).
		Return([]model.Permission{}, nil)

	role, err := ts.svc.CreateRole(ctx, rolesservice.CreateRoleInput{
		Slug:        "writer",
		Name:        "Writer",
		Permissions: []shared.PermissionKey{key},
	})

	ts.Require().Error(err)
	ts.Nil(role)
	ts.Contains(err.Error(), rolesservice.ErrPermissionMissing.Error())
}

func TestService_UpdateRole_PreventsSystemDowngrade(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	ts.mockRoleRepository.EXPECT().
		GetByID(ctx, int64(1)).
		Return(&model.Role{ID: 1, UUID: "uuid", IsSystem: true}, nil)

	makeNonSystem := false
	role, err := ts.svc.UpdateRole(ctx, rolesservice.UpdateRoleInput{
		ID:       1,
		Slug:     "system",
		Name:     "System",
		IsSystem: &makeNonSystem,
	})
	ts.Require().ErrorIs(err, shared.ErrSystemRoleProtected)
	ts.Nil(role)
}

func TestService_UpdateRole_ReplacesPermissions(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	ts.mockRoleRepository.EXPECT().
		GetByID(ctx, int64(5)).
		Return(&model.Role{ID: 5, UUID: "u5", Slug: "old", Name: "Old"}, nil)

	ts.mockRoleRepository.EXPECT().
		Update(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, input model.Role) (*model.Role, error) {
			ts.Equal("updated", input.Slug)
			ts.Equal("Updated", input.Name)
			return &input, nil
		})

	key := mkPermissionKey("roles", "write")

	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, repository.PermissionFilter{Keys: []shared.PermissionKey{key}}).
		Return([]model.Permission{{ID: 77, Domain: "roles", Action: "write"}}, nil)

	ts.mockAssignmentRepository.EXPECT().
		ReplacePermissions(ctx, int64(5), []int64{77}).
		Return(nil)

	role, err := ts.svc.UpdateRole(ctx, rolesservice.UpdateRoleInput{
		ID:          5,
		Slug:        " updated ",
		Name:        " Updated ",
		Permissions: &[]shared.PermissionKey{key},
	})
	ts.Require().NoError(err)
	ts.Equal("updated", role.Slug)
}

func TestService_DeleteRole_ProtectsSystem(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	ts.mockRoleRepository.EXPECT().
		GetByID(ctx, int64(9)).
		Return(&model.Role{ID: 9, IsSystem: true}, nil)

	err := ts.svc.DeleteRole(ctx, 9)
	ts.Require().ErrorIs(err, shared.ErrSystemRoleProtected)
}

func TestService_DeleteRole_Success(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	ts.mockRoleRepository.EXPECT().
		GetByID(ctx, int64(9)).
		Return(&model.Role{ID: 9, IsSystem: false}, nil)

	ts.mockRoleRepository.EXPECT().
		Delete(ctx, int64(9)).
		Return(nil)

	ts.Require().NoError(ts.svc.DeleteRole(ctx, 9))
}

func TestService_SetRolePermissions_ValidatesAndReplaces(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	key := mkPermissionKey("posts", "publish")
	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, repository.PermissionFilter{Keys: []shared.PermissionKey{key}}).
		Return([]model.Permission{{ID: 500, Domain: "posts", Action: "publish"}}, nil)

	ts.mockAssignmentRepository.EXPECT().
		ReplacePermissions(ctx, int64(7), []int64{500}).
		Return(nil)

	ts.Require().NoError(ts.svc.SetRolePermissions(ctx, 7, []shared.PermissionKey{key}))

	err := ts.svc.SetRolePermissions(ctx, 0, nil)
	ts.Require().ErrorIs(err, shared.ErrInvalidRoleID)
}

func TestService_SetRoleParent_ValidationAndSuccess(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	t.Run("missing hierarchy repository", func(t *testing.T) {
		svc, err := rolesservice.New(rolesservice.Dependencies{
			Roles:       ts.mockRoleRepository,
			Permissions: ts.mockPermissionRepository,
			Assignments: ts.mockAssignmentRepository,
		})
		require.NoError(t, err)

		err = svc.SetRoleParent(ctx, 1, nil)
		require.ErrorIs(t, err, rolesservice.ErrHierarchyRepoMissing)
	})

	t.Run("invalid ids", func(_ *testing.T) {
		err := ts.svc.SetRoleParent(ctx, 0, nil)
		ts.Require().ErrorIs(err, shared.ErrInvalidRoleID)

		parent := int64(5)
		err = ts.svc.SetRoleParent(ctx, 5, &parent)
		ts.Require().Error(err)
		ts.Contains(err.Error(), "invalid parent role")
	})

	t.Run("success", func(_ *testing.T) {
		parent := int64(10)
		ts.mockHierarchyRepository.EXPECT().
			SetParent(ctx, int64(3), &parent).
			Return(nil)

		ts.Require().NoError(ts.svc.SetRoleParent(ctx, 3, &parent))
	})
}

func TestService_CreatePermissions_TrimsAndHandlesDuplicates(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	inputs := []rolesservice.CreatePermissionInput{
		{Key: mkPermissionKey(" roles ", " read "), Description: "  read  "},
	}

	ts.mockPermissionRepository.EXPECT().
		CreateBulk(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, perms []model.Permission) ([]model.Permission, error) {
			ts.Len(perms, 1)
			ts.Equal("roles", perms[0].Domain.String())
			ts.Equal("read", perms[0].Action.String())
			return perms, outbox.ErrRowAlreadyExists
		})

	created, err := ts.svc.CreatePermissions(ctx, inputs)
	ts.Require().NoError(err)
	ts.Len(created, 1)
}

func TestService_EnsurePermissions_CreatesMissing(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	inputs := []rolesservice.CreatePermissionInput{
		{Key: mkPermissionKey("roles", "read")},
		{Key: mkPermissionKey("posts", "write")},
	}

	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, repository.PermissionFilter{Keys: []shared.PermissionKey{
			inputs[0].Key,
			inputs[1].Key,
		}}).
		Return([]model.Permission{
			{Domain: "roles", Action: "read"},
		}, nil)

	ts.mockPermissionRepository.EXPECT().
		CreateBulk(ctx, gomock.Any()).
		DoAndReturn(func(_ context.Context, perms []model.Permission) ([]model.Permission, error) {
			ts.Len(perms, 1)
			ts.Equal("posts", perms[0].Domain.String())
			return perms, nil
		})

	ts.Require().NoError(ts.svc.EnsurePermissions(ctx, inputs))
}

func TestService_HasPermission(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	roleID := int64(11)
	subjectID := "123e4567-e89b-12d3-a456-426614174111"
	key := mkPermissionKey("roles", "update")

	ts.mockAssignmentRepository.EXPECT().
		ListSubjectRoles(ctx, subjectID).
		Return([]model.Role{{ID: roleID}}, nil)

	ts.mockAssignmentRepository.EXPECT().
		ListPermissions(ctx, roleID).
		Return([]model.Permission{{Domain: "roles", Action: "update"}}, nil)

	ok, err := ts.svc.HasPermission(ctx, subjectID, key)
	ts.Require().NoError(err)
	ts.True(ok)

	invalid, err := ts.svc.HasPermission(ctx, "", key)
	ts.Require().ErrorIs(err, shared.ErrInvalidSubjectID)
	ts.False(invalid)

	invalid, err = ts.svc.HasPermission(ctx, subjectID, shared.PermissionKey{})
	ts.Require().ErrorIs(err, shared.ErrInvalidPermission)
	ts.False(invalid)
}

func TestService_ListRoles_ForwardsFilter(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	filter := repository.RoleFilter{IncludeSys: true, Slugs: []string{"admin"}}
	expected := []model.Role{{ID: 1, Slug: "admin"}}

	ts.mockRoleRepository.EXPECT().
		List(ctx, filter).
		Return(expected, nil)

	res, err := ts.svc.ListRoles(ctx, filter)
	ts.Require().NoError(err)
	ts.Equal(expected, res)
}

func TestService_GetRole_Scenarios(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	_, err := ts.svc.GetRole(ctx, 0)
	ts.Require().ErrorIs(err, shared.ErrInvalidRoleID)

	ts.mockRoleRepository.EXPECT().
		GetByID(ctx, int64(2)).
		Return(nil, nil)
	_, err = ts.svc.GetRole(ctx, 2)
	ts.Require().ErrorIs(err, shared.ErrRoleNotFound)

	role := &model.Role{ID: 3}
	ts.mockRoleRepository.EXPECT().
		GetByID(ctx, int64(3)).
		Return(role, nil)
	got, err := ts.svc.GetRole(ctx, 3)
	ts.Require().NoError(err)
	ts.Equal(role, got)
}

func TestService_ListRolePermissions_Scenarios(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	_, err := ts.svc.ListRolePermissions(ctx, 0)
	ts.Require().ErrorIs(err, shared.ErrInvalidRoleID)

	expected := []model.Permission{{ID: 1}}
	ts.mockAssignmentRepository.EXPECT().
		ListPermissions(ctx, int64(5)).
		Return(expected, nil)
	res, err := ts.svc.ListRolePermissions(ctx, 5)
	ts.Require().NoError(err)
	ts.Equal(expected, res)

	ts.mockAssignmentRepository.EXPECT().
		ListPermissions(ctx, int64(6)).
		Return(nil, ts.errExpected)
	_, err = ts.svc.ListRolePermissions(ctx, 6)
	ts.Require().Error(err)
	ts.Contains(err.Error(), "list role permissions")
}

func TestService_AssignRolesToSubject_Scenarios(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	err := ts.svc.AssignRolesToSubject(ctx, "", nil)
	ts.Require().ErrorIs(err, shared.ErrInvalidSubjectID)

	roleIDs := []int64{1, 2}
	adminSubjectID := "123e4567-e89b-12d3-a456-426614174112"
	userSubjectID := "123e4567-e89b-12d3-a456-426614174113"

	ts.mockAssignmentRepository.EXPECT().
		AssignRoleToSubject(ctx, adminSubjectID, roleIDs).
		Return(nil)
	ts.Require().NoError(ts.svc.AssignRolesToSubject(ctx, adminSubjectID, roleIDs))

	ts.mockAssignmentRepository.EXPECT().
		AssignRoleToSubject(ctx, userSubjectID, roleIDs).
		Return(nil)
	ts.Require().NoError(ts.svc.AssignRolesToSubject(ctx, userSubjectID, roleIDs))
}

func TestService_ListSubjectRoles_Scenarios(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	_, err := ts.svc.ListSubjectRoles(ctx, "")
	ts.Require().ErrorIs(err, shared.ErrInvalidSubjectID)

	expected := []model.Role{{ID: 1}}
	subjectID := "123e4567-e89b-12d3-a456-426614174114"
	ts.mockAssignmentRepository.EXPECT().
		ListSubjectRoles(ctx, subjectID).
		Return(expected, nil)
	res, err := ts.svc.ListSubjectRoles(ctx, subjectID)
	ts.Require().NoError(err)
	ts.Equal(expected, res)

	missingSubjectID := "123e4567-e89b-12d3-a456-426614174115"
	ts.mockAssignmentRepository.EXPECT().
		ListSubjectRoles(ctx, missingSubjectID).
		Return(nil, ts.errExpected)
	_, err = ts.svc.ListSubjectRoles(ctx, missingSubjectID)
	ts.Require().Error(err)
	ts.Contains(err.Error(), "list subject roles")
}

func TestService_ListPermissions_ForwardsFilter(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	filter := repository.PermissionFilter{Domain: "roles"}
	expected := []model.Permission{{ID: 1}}

	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, filter).
		Return(expected, nil)

	res, err := ts.svc.ListPermissions(ctx, filter)
	ts.Require().NoError(err)
	ts.Equal(expected, res)
}

func TestService_EnsurePermissions_ListError(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	inputs := []rolesservice.CreatePermissionInput{
		{Key: mkPermissionKey("roles", "list")},
	}

	ts.mockPermissionRepository.EXPECT().
		ListByFilter(ctx, repository.PermissionFilter{Keys: []shared.PermissionKey{inputs[0].Key}}).
		Return(nil, ts.errExpected)

	err := ts.svc.EnsurePermissions(ctx, inputs)
	ts.Require().Error(err)
	ts.Contains(err.Error(), "list permissions")
}
