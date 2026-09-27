package rolesguardservice

import (
	"context"
	"errors"
	"fmt"
	"strings"

	logger "github.com/assurrussa/gologger"

	"github.com/assurrussa/goauth/internal/legacy/domain/roles/model"
	"github.com/assurrussa/goauth/internal/legacy/domain/roles/shared"
	listsubjectroles "github.com/assurrussa/goauth/internal/legacy/domain/roles/usecases/query/list_subject_roles"
)

var (
	ErrSubjectRoleIsCurrentRole   = errors.New("subject role is current role")
	ErrSubjectRoleIsSuperRole     = errors.New("subject role is super role")
	ErrSubjectRoleNotFound        = errors.New("subject role not found")
	ErrSubjectPermissionsNotFound = errors.New("subject permissions not found")
)

//go:generate toolsmocks

type rolesUseCase interface {
	Handle(ctx context.Context, req listsubjectroles.Request) (listsubjectroles.Response, error)
}

type permissionUseCase interface {
	ListAllPermissionsByRoles(ctx context.Context, roleIDs []int64) ([]model.PermissionWithRole, error)
	HasPermission(ctx context.Context, subjectID string, key shared.PermissionKey) (bool, error)
}

type cache interface {
	Enabled(ctx context.Context) bool
	SubjectRoles(subjectID string) []model.Role
	AllRolePermissions(roles []model.Role) map[int64]map[int64]model.Permission
}

//go:generate options-gen -out-filename=service_options.gen.go -from-struct=Options
type Options struct {
	rolesUseCase      rolesUseCase      `option:"mandatory" validate:"required"`
	permissionUseCase permissionUseCase `option:"mandatory" validate:"required"`
	cache             cache             `option:"mandatory" validate:"required"`
	logger            logger.Logger     `option:"mandatory" validate:"required"`
}

type Service struct {
	Options
}

func Must(opts Options) *Service {
	service, err := New(opts)
	if err != nil {
		panic(err)
	}
	return service
}

func New(opts Options) (*Service, error) {
	if err := opts.Validate(); err != nil {
		return nil, fmt.Errorf("validate options: %w", err)
	}

	return &Service{
		Options: opts,
	}, nil
}

func (s *Service) SubjectGuardCheck(
	ctx context.Context,
	subjectID string,
	key shared.PermissionKey,
	opts ...shared.PermissionGuardOption,
) bool {
	if key.IsZero() {
		s.logger.WarnContext(ctx, "permission guard: zero permission key")
		return false
	}

	bypassRoles := shared.CreateRoles(opts...)
	allowed, err := s.checkSubjectAccess(ctx, subjectID, key, bypassRoles)
	if err != nil {
		s.logger.WarnContext(ctx, "permission guard check failed", logger.Error(err))
		return false
	}

	return allowed
}

func (s *Service) IsSuperSubject(ctx context.Context, subjectID string) bool {
	roles, err := s.GetRolesSubject(ctx, subjectID)
	if err != nil {
		return false
	}
	if len(roles) == 0 {
		return false
	}

	for _, role := range roles {
		if role.Slug == shared.SuperAdminRole {
			return true
		}
	}

	return false
}

func (s *Service) SubjectCan(
	ctx context.Context,
	subjectID string,
	domain shared.PermissionDomain,
	action shared.PermissionAction,
) bool {
	return s.SubjectGuardCheck(ctx, subjectID, shared.NewPermissionKey(domain, action))
}

func (s *Service) GetRolesSubject(ctx context.Context, subjectID string) ([]model.Role, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, ErrSubjectRoleNotFound
	}

	if s.cache.Enabled(ctx) {
		roles := s.cache.SubjectRoles(subjectID)
		if len(roles) == 0 {
			return nil, ErrSubjectRoleNotFound
		}

		return roles, nil
	}

	rolesResp, err := s.rolesUseCase.Handle(ctx, listsubjectroles.Request{SubjectID: subjectID})
	if err != nil {
		s.logger.ErrorContext(ctx, "handle roles failed", logger.Error(err))
		return nil, ErrSubjectRoleNotFound
	}

	return rolesResp.Roles, nil
}

func (s *Service) checkSubjectAccess(
	ctx context.Context,
	subjectID string,
	key shared.PermissionKey,
	bypassRoles []string,
) (bool, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return false, ErrSubjectRoleNotFound
	}

	roles, err := s.GetRolesSubject(ctx, subjectID)
	if err != nil {
		return false, err
	}

	if hasBypassRole(roles, bypassRoles) {
		return true, nil
	}

	ok, err := s.hasPermission(ctx, roles, subjectID, key)
	if err != nil {
		return false, err
	}

	return ok, nil
}

func (s *Service) GetPermissions(
	ctx context.Context,
	roles []model.Role,
) (map[int64]map[int64]model.Permission, error) {
	if s.cache.Enabled(ctx) {
		allRolePerms := s.cache.AllRolePermissions(roles)
		permissions := make(map[int64]map[int64]model.Permission, len(roles))
		for _, role := range roles {
			perms, ok := allRolePerms[role.ID]
			if !ok {
				continue
			}

			permissions[role.ID] = perms
		}

		return permissions, nil
	}

	roleIDs := make([]int64, 0, len(roles))
	for _, role := range roles {
		roleIDs = append(roleIDs, role.ID)
	}

	permissionsByRoles, err := s.permissionUseCase.ListAllPermissionsByRoles(ctx, roleIDs)
	if err != nil {
		return nil, fmt.Errorf("list permissions by roles: %w", err)
	}

	permissions := make(map[int64]map[int64]model.Permission, len(permissionsByRoles))
	for _, permission := range permissionsByRoles {
		vals, ok := permissions[permission.RoleID]
		if !ok {
			vals = make(map[int64]model.Permission)
		}
		vals[permission.ID] = permission.Permission
		permissions[permission.RoleID] = vals
	}

	return permissions, nil
}

func (s *Service) hasPermission(
	ctx context.Context,
	roles []model.Role,
	subjectID string,
	key shared.PermissionKey,
) (bool, error) {
	if s.cache.Enabled(ctx) {
		allRolePerms := s.cache.AllRolePermissions(roles)
		for _, role := range roles {
			permissions, ok := allRolePerms[role.ID]
			if !ok {
				continue
			}

			for _, p := range permissions {
				if p.Domain == key.Domain && p.Action == key.Action {
					return true, nil
				}
			}
		}

		return false, nil
	}

	ok, err := s.permissionUseCase.HasPermission(ctx, subjectID, key)
	if err != nil {
		s.logger.ErrorContext(ctx, "handle permissions failed", logger.Error(err))
		return false, ErrSubjectPermissionsNotFound
	}
	if !ok {
		return false, nil
	}

	return true, nil
}

func hasBypassRole(roles []model.Role, bypassSlugs []string) bool {
	for _, role := range roles {
		for _, slug := range bypassSlugs {
			if strings.EqualFold(role.Slug, slug) {
				return true
			}
		}
	}

	return false
}
