package listallroles

import (
	"context"
	"errors"
	"fmt"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	"github.com/assurrussa/goauth/internal/legacy/domain/roles/repository"
)

//go:generate toolsmocks

var ErrNilService = errors.New("list all roles query: nil service")

type service interface {
	ListRoles(ctx context.Context, filter repository.RoleFilter) ([]model.Role, error)
	ListRolePermissions(ctx context.Context, roleID int64) ([]model.Permission, error)
}

type roleRepository interface {
	ListAllRolePermissions(ctx context.Context) ([]model.RolePermission, error)
	ListAllSubjectRoles(ctx context.Context) ([]model.SubjectRole, error)
}

type permissionRepository interface {
	ListAllPermissions(ctx context.Context) ([]model.Permission, error)
}

type assignmentRepository interface {
	ListSubjectRoles(ctx context.Context, subjectID string) ([]model.Role, error)
}

type hierarchyRepository interface {
	ListAllRoleHierarchy(ctx context.Context) ([]model.RoleHierarchy, error)
}

type UseCase struct {
	service              service
	roleRepository       roleRepository
	permissionRepository permissionRepository
	assignmentRepository assignmentRepository
	hierarchyRepository  hierarchyRepository
}

func Must(
	service service,
	roleRepository roleRepository,
	permissionRepository permissionRepository,
	assignmentRepository assignmentRepository,
	hierarchyRepository hierarchyRepository,
) *UseCase {
	uc, err := New(
		service,
		roleRepository,
		permissionRepository,
		assignmentRepository,
		hierarchyRepository,
	)
	if err != nil {
		panic(err)
	}
	return uc
}

func New(
	service service,
	roleRepository roleRepository,
	permissionRepository permissionRepository,
	assignmentRepository assignmentRepository,
	hierarchyRepository hierarchyRepository,
) (*UseCase, error) {
	if service == nil {
		return nil, ErrNilService
	}

	return &UseCase{
		service:              service,
		roleRepository:       roleRepository,
		permissionRepository: permissionRepository,
		assignmentRepository: assignmentRepository,
		hierarchyRepository:  hierarchyRepository,
	}, nil
}

func (u *UseCase) Handle(ctx context.Context, req Request) (Response, error) {
	if err := req.Validate(); err != nil {
		return Response{}, fmt.Errorf("validate: %w", err)
	}

	respRoles, err := u.service.ListRoles(ctx, repository.RoleFilter{IncludeSys: true})
	if err != nil {
		return Response{}, fmt.Errorf("list roles: %w", err)
	}

	respPermissions, err := u.permissionRepository.ListAllPermissions(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("list roles: %w", err)
	}

	subjectRoles, err := u.roleRepository.ListAllSubjectRoles(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("list all subject roles: %w", err)
	}

	allRolePermissions, err := u.roleRepository.ListAllRolePermissions(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("list all role permissions: %w", err)
	}

	roleHierarchy, err := u.hierarchyRepository.ListAllRoleHierarchy(ctx)
	if err != nil {
		return Response{}, fmt.Errorf("list all role permissions: %w", err)
	}

	return Response{
		Roles:           respRoles,
		Permissions:     respPermissions,
		SubjectRoles:    subjectRoles,
		RolePermissions: allRolePermissions,
		RoleHierarchy:   roleHierarchy,
	}, nil
}
