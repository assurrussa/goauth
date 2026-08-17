package listallroles_test

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goshared/pkg/tests"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	"github.com/assurrussa/goauth/internal/legacy/domain/roles/repository"
	listallroles "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_all_roles"
	listallrolesmocks "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_all_roles/mocks"
)

type testSuite struct {
	suite.Suite

	mockAssignmentRepository *listallrolesmocks.MockassignmentRepository
	mockService              *listallrolesmocks.Mockservice
	mockHierarchyRepository  *listallrolesmocks.MockhierarchyRepository
	mockPermissionRepository *listallrolesmocks.MockpermissionRepository
	mockRoleRepository       *listallrolesmocks.MockroleRepository

	svc         *listallroles.UseCase
	errExpected error
}

func newTestSuite(t *testing.T) (context.Context, context.CancelFunc, *testSuite) {
	t.Helper()

	return tests.NewSuite[*testSuite](t, func(t *testing.T, _ context.Context) *testSuite {
		t.Helper()
		ctrl := gomock.NewController(t)

		mockService := listallrolesmocks.NewMockservice(ctrl)
		mockAssignmentRepository := listallrolesmocks.NewMockassignmentRepository(ctrl)
		mockHierarchyRepository := listallrolesmocks.NewMockhierarchyRepository(ctrl)
		mockPermissionRepository := listallrolesmocks.NewMockpermissionRepository(ctrl)
		mockRoleRepository := listallrolesmocks.NewMockroleRepository(ctrl)

		svc := listallroles.Must(
			mockService,
			mockRoleRepository,
			mockPermissionRepository,
			mockAssignmentRepository,
			mockHierarchyRepository,
		)

		return &testSuite{
			mockAssignmentRepository: mockAssignmentRepository,
			mockHierarchyRepository:  mockHierarchyRepository,
			mockPermissionRepository: mockPermissionRepository,
			mockRoleRepository:       mockRoleRepository,
			mockService:              mockService,
			svc:                      svc,
			errExpected:              errors.New("expected error"),
		}
	})
}

func Test_MustInit(t *testing.T) {
	_, _, ts := newTestSuite(t)

	ts.Require().Panics(func() {
		listallroles.Must(nil, nil, nil, nil, nil)
	})
}

func Test_Handle_ReturnsAggregatedData(t *testing.T) {
	ctx, _, ts := newTestSuite(t)

	roles := []model.Role{
		{ID: 1, UUID: "role-admin", Slug: "admin", Name: "Admin", IsSystem: true},
		{ID: 2, UUID: "role-editor", Slug: "editor", Name: "Editor"},
	}
	permissions := []model.Permission{
		{ID: 10, UUID: "perm-read", Domain: "roles", Action: "read"},
		{ID: 11, UUID: "perm-write", Domain: "roles", Action: "write"},
	}
	subjectRoles := []model.SubjectRole{
		{SubjectID: "123e4567-e89b-12d3-a456-426614174107", RoleID: 1},
	}
	rolePermissions := []model.RolePermission{
		{RoleID: 1, PermissionID: 10},
		{RoleID: 2, PermissionID: 11},
	}
	roleHierarchy := []model.RoleHierarchy{
		{ParentRoleID: 1, ChildRoleID: 2},
	}

	gomock.InOrder(
		ts.mockService.EXPECT().
			ListRoles(ctx, repository.RoleFilter{IncludeSys: true}).
			Return(roles, nil).Times(1),
		ts.mockPermissionRepository.EXPECT().
			ListAllPermissions(ctx).
			Return(permissions, nil).Times(1),
		ts.mockRoleRepository.EXPECT().
			ListAllSubjectRoles(ctx).
			Return(subjectRoles, nil).Times(1),
		ts.mockRoleRepository.EXPECT().
			ListAllRolePermissions(ctx).
			Return(rolePermissions, nil).Times(1),
		ts.mockHierarchyRepository.EXPECT().
			ListAllRoleHierarchy(ctx).
			Return(roleHierarchy, nil).Times(1),
	)

	resp, err := ts.svc.Handle(ctx, listallroles.Request{})
	ts.Require().NoError(err)
	ts.Equal(listallroles.Response{
		Roles:           roles,
		Permissions:     permissions,
		SubjectRoles:    subjectRoles,
		RolePermissions: rolePermissions,
		RoleHierarchy:   roleHierarchy,
	}, resp)
}

func Test_Handle_PropagatesErrors(t *testing.T) {
	testCases := []struct {
		name    string
		setup   func(context.Context, *testSuite)
		wantErr string
	}{
		{
			name: "list roles error",
			setup: func(ctx context.Context, ts *testSuite) {
				ts.mockService.EXPECT().
					ListRoles(ctx, repository.RoleFilter{IncludeSys: true}).
					Return(nil, ts.errExpected)
			},
			wantErr: "list roles",
		},
		{
			name: "list permissions error",
			setup: func(ctx context.Context, ts *testSuite) {
				ts.mockService.EXPECT().
					ListRoles(ctx, repository.RoleFilter{IncludeSys: true}).
					Return([]model.Role{}, nil)
				ts.mockPermissionRepository.EXPECT().
					ListAllPermissions(ctx).
					Return(nil, ts.errExpected)
			},
			wantErr: "list roles",
		},
		{
			name: "list all subject roles error",
			setup: func(ctx context.Context, ts *testSuite) {
				ts.mockService.EXPECT().
					ListRoles(ctx, repository.RoleFilter{IncludeSys: true}).
					Return([]model.Role{}, nil)
				ts.mockPermissionRepository.EXPECT().
					ListAllPermissions(ctx).
					Return([]model.Permission{}, nil)
				ts.mockRoleRepository.EXPECT().
					ListAllSubjectRoles(ctx).
					Return(nil, ts.errExpected)
			},
			wantErr: "list all subject roles",
		},
		{
			name: "list all role permissions error",
			setup: func(ctx context.Context, ts *testSuite) {
				ts.mockService.EXPECT().
					ListRoles(ctx, repository.RoleFilter{IncludeSys: true}).
					Return([]model.Role{}, nil)
				ts.mockPermissionRepository.EXPECT().
					ListAllPermissions(ctx).
					Return([]model.Permission{}, nil)
				ts.mockRoleRepository.EXPECT().
					ListAllSubjectRoles(ctx).
					Return([]model.SubjectRole{}, nil)
				ts.mockRoleRepository.EXPECT().
					ListAllRolePermissions(ctx).
					Return(nil, ts.errExpected)
			},
			wantErr: "list all role permissions",
		},
		{
			name: "list all role hierarchy error",
			setup: func(ctx context.Context, ts *testSuite) {
				ts.mockService.EXPECT().
					ListRoles(ctx, repository.RoleFilter{IncludeSys: true}).
					Return([]model.Role{}, nil)
				ts.mockPermissionRepository.EXPECT().
					ListAllPermissions(ctx).
					Return([]model.Permission{}, nil)
				ts.mockRoleRepository.EXPECT().
					ListAllSubjectRoles(ctx).
					Return([]model.SubjectRole{}, nil)
				ts.mockRoleRepository.EXPECT().
					ListAllRolePermissions(ctx).
					Return([]model.RolePermission{}, nil)
				ts.mockHierarchyRepository.EXPECT().
					ListAllRoleHierarchy(ctx).
					Return(nil, ts.errExpected)
			},
			wantErr: "list all role permissions",
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx, _, ts := newTestSuite(t)

			tc.setup(ctx, ts)

			resp, err := ts.svc.Handle(ctx, listallroles.Request{})
			ts.Require().Error(err)
			ts.Contains(err.Error(), tc.wantErr)
			ts.Empty(resp.Roles)
			ts.Empty(resp.Permissions)
			ts.Empty(resp.SubjectRoles)
			ts.Empty(resp.RolePermissions)
			ts.Empty(resp.RoleHierarchy)
		})
	}
}
