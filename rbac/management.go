package rbac

import (
	"context"
	"errors"
	"strings"

	"github.com/assurrussa/goauth"
)

type RoleFilter struct {
	IDs           []int64
	Slugs         []string
	IncludeSystem bool
	Search        string
	Limit         uint64
	Offset        uint64
}

type PermissionFilter struct {
	IDs    []int64
	Keys   []PermissionKey
	Domain string
	Action string
}

type RolePermission struct {
	RoleID       int64
	PermissionID int64
}

type SubjectRole struct {
	SubjectID goauth.SubjectID
	RoleID    int64
}

// Snapshot is a consistent, hierarchy-free view for host-side permission
// editors and cache rebuilds.
type Snapshot struct {
	Roles           []Role
	Permissions     []Permission
	RolePermissions []RolePermission
	SubjectRoles    []SubjectRole
}

func (s *Service) Roles(ctx context.Context, filter RoleFilter) ([]Role, error) {
	if s.management == nil {
		return nil, ErrManagementUnavailable
	}
	if err := normalizeRoleFilter(&filter); err != nil {
		return nil, err
	}

	return s.management.ListRoles(ctx, filter)
}

func (s *Service) Role(ctx context.Context, roleID int64) (Role, error) {
	if s.management == nil {
		return Role{}, ErrManagementUnavailable
	}
	if roleID <= 0 {
		return Role{}, ErrInvalidRole
	}

	return s.management.GetRole(ctx, roleID)
}

func (s *Service) CreateRole(
	ctx context.Context,
	role Role,
	permissionKeys []PermissionKey,
) (Role, error) {
	if s.management == nil {
		return Role{}, ErrManagementUnavailable
	}
	if role.ID != 0 || strings.TrimSpace(role.PublicID) != "" {
		return Role{}, ErrInvalidRole
	}
	if err := normalizeRole(&role); err != nil {
		return Role{}, err
	}
	keys, err := normalizePermissionKeys(permissionKeys)
	if err != nil {
		return Role{}, err
	}

	return s.management.CreateRole(ctx, role, keys)
}

func (s *Service) UpdateRole(
	ctx context.Context,
	role Role,
	permissionKeys *[]PermissionKey,
) (Role, error) {
	if s.management == nil {
		return Role{}, ErrManagementUnavailable
	}
	if role.ID <= 0 {
		return Role{}, ErrInvalidRole
	}
	if err := normalizeRole(&role); err != nil {
		return Role{}, err
	}
	var normalized *[]PermissionKey
	if permissionKeys != nil {
		keys, err := normalizePermissionKeys(*permissionKeys)
		if err != nil {
			return Role{}, err
		}
		normalized = &keys
	}

	return s.management.UpdateRole(ctx, role, normalized)
}

func (s *Service) DeleteRole(ctx context.Context, roleID int64) error {
	if s.management == nil {
		return ErrManagementUnavailable
	}
	if roleID <= 0 {
		return ErrInvalidRole
	}

	return s.management.DeleteRole(ctx, roleID)
}

func (s *Service) Permissions(ctx context.Context, filter PermissionFilter) ([]Permission, error) {
	if s.management == nil {
		return nil, ErrManagementUnavailable
	}
	if err := normalizePermissionFilter(&filter); err != nil {
		return nil, err
	}

	return s.management.ListPermissions(ctx, filter)
}

func (s *Service) RolePermissions(ctx context.Context, roleID int64) ([]Permission, error) {
	if s.management == nil {
		return nil, ErrManagementUnavailable
	}
	if roleID <= 0 {
		return nil, ErrInvalidRole
	}

	return s.management.ListRolePermissions(ctx, roleID)
}

func (s *Service) ReplaceRolePermissions(
	ctx context.Context,
	roleID int64,
	permissionKeys []PermissionKey,
) error {
	if s.management == nil {
		return ErrManagementUnavailable
	}
	if roleID <= 0 {
		return ErrInvalidRole
	}
	keys, err := normalizePermissionKeys(permissionKeys)
	if err != nil {
		return err
	}

	return s.management.ReplaceRolePermissions(ctx, roleID, keys)
}

func (s *Service) ReplaceSubjectRoles(
	ctx context.Context,
	subjectID goauth.SubjectID,
	roleIDs []int64,
) error {
	if s.management == nil {
		return ErrManagementUnavailable
	}
	if subjectID.IsZero() {
		return goauth.ErrInvalidSubjectID
	}
	unique := make(map[int64]struct{}, len(roleIDs))
	result := make([]int64, 0, len(roleIDs))
	for _, roleID := range roleIDs {
		if roleID <= 0 {
			return ErrInvalidRole
		}
		if _, exists := unique[roleID]; exists {
			continue
		}
		unique[roleID] = struct{}{}
		result = append(result, roleID)
	}

	return s.management.ReplaceSubjectRoles(ctx, subjectID, result)
}

func (s *Service) SubjectRoles(ctx context.Context, subjectID goauth.SubjectID) ([]Role, error) {
	if s.management == nil {
		return nil, ErrManagementUnavailable
	}
	if subjectID.IsZero() {
		return nil, goauth.ErrInvalidSubjectID
	}

	return s.management.ListSubjectRoles(ctx, subjectID)
}

func (s *Service) Snapshot(ctx context.Context) (Snapshot, error) {
	if s.management == nil {
		return Snapshot{}, ErrManagementUnavailable
	}

	return s.management.Snapshot(ctx)
}

func normalizeRoleFilter(filter *RoleFilter) error {
	for _, id := range filter.IDs {
		if id <= 0 {
			return ErrInvalidRole
		}
	}
	for index := range filter.Slugs {
		filter.Slugs[index] = strings.TrimSpace(filter.Slugs[index])
		if !validSegment(filter.Slugs[index]) {
			return ErrInvalidRole
		}
	}
	filter.Search = strings.TrimSpace(filter.Search)
	if len(filter.Search) > 128 || filter.Limit > 1000 {
		return ErrInvalidRole
	}

	return nil
}

func normalizePermissionFilter(filter *PermissionFilter) error {
	for _, id := range filter.IDs {
		if id <= 0 {
			return ErrInvalidPermissionKey
		}
	}
	keys, err := normalizePermissionKeys(filter.Keys)
	if err != nil {
		return err
	}
	filter.Keys = keys
	filter.Domain = strings.TrimSpace(filter.Domain)
	filter.Action = strings.TrimSpace(filter.Action)
	if filter.Domain != "" && !validSegment(filter.Domain) {
		return ErrInvalidPermissionKey
	}
	if filter.Action != "" && !validSegment(filter.Action) {
		return ErrInvalidPermissionKey
	}

	return nil
}

func normalizePermissionKeys(keys []PermissionKey) ([]PermissionKey, error) {
	unique := make(map[PermissionKey]struct{}, len(keys))
	result := make([]PermissionKey, 0, len(keys))
	for _, key := range keys {
		if err := key.Validate(); err != nil {
			return nil, err
		}
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = struct{}{}
		result = append(result, key)
	}

	return result, nil
}

func IsNotFound(err error) bool {
	return errors.Is(err, ErrRoleNotFound) || errors.Is(err, ErrPermissionNotFound)
}
