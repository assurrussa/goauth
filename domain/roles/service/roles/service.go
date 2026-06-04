package rolesservice

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth/domain/roles/model"
	"github.com/assurrussa/goauth/domain/roles/repository"
	"github.com/assurrussa/goauth/domain/roles/shared"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

var (
	ErrServiceDependencyNil = errors.New("roles service: dependency is nil")
	ErrHierarchyRepoMissing = errors.New("roles service: hierarchy repository not configured")
	ErrPermissionMissing    = errors.New("roles service: permission not found")
	ErrInvalidRoleName      = errors.New("roles service: invalid role name")
)

type Service struct {
	roles       repository.RoleRepository
	permissions repository.PermissionRepository
	assignments repository.AssignmentRepository
	hierarchy   repository.HierarchyRepository
}

type Dependencies struct {
	Roles       repository.RoleRepository
	Permissions repository.PermissionRepository
	Assignments repository.AssignmentRepository
	Hierarchy   repository.HierarchyRepository
}

func New(deps Dependencies) (*Service, error) {
	if deps.Roles == nil {
		return nil, ErrServiceDependencyNil
	}
	if deps.Permissions == nil {
		return nil, ErrServiceDependencyNil
	}
	if deps.Assignments == nil {
		return nil, ErrServiceDependencyNil
	}

	return &Service{
		roles:       deps.Roles,
		permissions: deps.Permissions,
		assignments: deps.Assignments,
		hierarchy:   deps.Hierarchy,
	}, nil
}

func Must(deps Dependencies) *Service {
	svc, err := New(deps)
	if err != nil {
		panic(err)
	}

	return svc
}

func (s *Service) ListRoles(ctx context.Context, filter repository.RoleFilter) ([]model.Role, error) {
	return s.roles.List(ctx, filter)
}

func (s *Service) GetRole(ctx context.Context, id int64) (*model.Role, error) {
	if id == 0 {
		return nil, shared.ErrInvalidRoleID
	}

	role, err := s.roles.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if role == nil {
		return nil, shared.ErrRoleNotFound
	}

	return role, nil
}

type CreateRoleInput struct {
	Slug        string
	Name        string
	Description *string
	IsSystem    bool
	Permissions []shared.PermissionKey
}

func (s *Service) CreateRole(ctx context.Context, input CreateRoleInput) (*model.Role, error) {
	slug := strings.TrimSpace(input.Slug)
	if slug == "" {
		return nil, shared.ErrInvalidRoleSlug
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, ErrInvalidRoleName
	}

	roleModel := model.Role{
		UUID:        uuid.NewString(),
		Slug:        slug,
		Name:        name,
		Description: toNullString(input.Description),
		IsSystem:    input.IsSystem,
	}

	role, err := s.roles.Create(ctx, roleModel)
	if err != nil {
		return nil, fmt.Errorf("create role: %w", err)
	}

	if input.Permissions != nil {
		permissionIDs, err := s.resolvePermissionIDs(ctx, input.Permissions)
		if err != nil {
			return nil, err
		}

		if err := s.assignments.ReplacePermissions(ctx, role.ID, permissionIDs); err != nil {
			return nil, fmt.Errorf("replace permissions: %w", err)
		}
	}

	return role, nil
}

type CreatePermissionInput struct {
	Key         shared.PermissionKey
	Description string
}

func (s *Service) CreatePermissions(ctx context.Context, inputs []CreatePermissionInput) ([]model.Permission, error) {
	if len(inputs) == 0 {
		return nil, nil
	}

	for i := range inputs {
		if inputs[i].Key.Domain == "" || inputs[i].Key.Action == "" {
			return nil, shared.ErrInvalidPermission
		}
	}

	permModels := make([]model.Permission, 0, len(inputs))
	for _, input := range inputs {
		permModels = append(permModels, model.Permission{
			UUID:        uuid.NewString(),
			Domain:      shared.PermissionDomain(strings.TrimSpace(input.Key.Domain.String())),
			Action:      shared.PermissionAction(strings.TrimSpace(input.Key.Action.String())),
			Description: stringPtrOrNil(strings.TrimSpace(input.Description)),
		})
	}

	created, err := s.permissions.CreateBulk(ctx, permModels)
	if err != nil {
		if errors.Is(err, outbox.ErrRowAlreadyExists) {
			return created, nil
		}
		return nil, fmt.Errorf("create permissions: %w", err)
	}

	return created, nil
}

type UpdateRoleInput struct {
	ID          int64
	Slug        string
	Name        string
	Description *string
	IsSystem    *bool
	Permissions *[]shared.PermissionKey
}

func (s *Service) UpdateRole(ctx context.Context, input UpdateRoleInput) (*model.Role, error) {
	if input.ID <= 0 {
		return nil, shared.ErrInvalidRoleID
	}

	existing, err := s.roles.GetByID(ctx, input.ID)
	if err != nil {
		return nil, fmt.Errorf("get role: %w", err)
	}
	if existing == nil {
		return nil, shared.ErrRoleNotFound
	}
	if existing.IsSystem && input.IsSystem != nil && !*input.IsSystem {
		// Protect system roles from being downgraded silently.
		return nil, shared.ErrSystemRoleProtected
	}

	slug := strings.TrimSpace(input.Slug)
	if slug == "" {
		return nil, shared.ErrInvalidRoleSlug
	}

	name := strings.TrimSpace(input.Name)
	if name == "" {
		return nil, ErrInvalidRoleName
	}

	updated := model.Role{
		ID:          existing.ID,
		UUID:        existing.UUID,
		Slug:        slug,
		Name:        name,
		Description: toNullString(input.Description),
		IsSystem:    existing.IsSystem,
	}

	if input.IsSystem != nil {
		updated.IsSystem = *input.IsSystem
	}

	role, err := s.roles.Update(ctx, updated)
	if err != nil {
		return nil, fmt.Errorf("update role: %w", err)
	}

	if input.Permissions != nil {
		permissionIDs, err := s.resolvePermissionIDs(ctx, *input.Permissions)
		if err != nil {
			return nil, err
		}

		if err := s.assignments.ReplacePermissions(ctx, role.ID, permissionIDs); err != nil {
			return nil, fmt.Errorf("replace permissions: %w", err)
		}
	}

	return role, nil
}

func (s *Service) DeleteRole(ctx context.Context, id int64) error {
	if id <= 0 {
		return shared.ErrInvalidRoleID
	}

	role, err := s.roles.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get role: %w", err)
	}
	if role == nil {
		return shared.ErrRoleNotFound
	}
	if role.IsSystem {
		return shared.ErrSystemRoleProtected
	}

	if err := s.roles.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete role: %w", err)
	}

	return nil
}

func (s *Service) ListRolePermissions(ctx context.Context, roleID int64) ([]model.Permission, error) {
	if roleID <= 0 {
		return nil, shared.ErrInvalidRoleID
	}

	perms, err := s.assignments.ListPermissions(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("list role permissions: %w", err)
	}

	return perms, nil
}

func (s *Service) SetRolePermissions(ctx context.Context, roleID int64, keys []shared.PermissionKey) error {
	if roleID <= 0 {
		return shared.ErrInvalidRoleID
	}

	permissionIDs, err := s.resolvePermissionIDs(ctx, keys)
	if err != nil {
		return err
	}

	if err := s.assignments.ReplacePermissions(ctx, roleID, permissionIDs); err != nil {
		return fmt.Errorf("replace permissions: %w", err)
	}

	return nil
}

func (s *Service) SetRoleParent(ctx context.Context, childRoleID int64, parentRoleID *int64) error {
	if s.hierarchy == nil {
		return ErrHierarchyRepoMissing
	}
	if childRoleID <= 0 {
		return shared.ErrInvalidRoleID
	}
	if parentRoleID != nil && *parentRoleID == childRoleID {
		return fmt.Errorf("invalid parent role: %w", shared.ErrInvalidRoleID)
	}

	if err := s.hierarchy.SetParent(ctx, childRoleID, parentRoleID); err != nil {
		return fmt.Errorf("set parent: %w", err)
	}

	return nil
}

func (s *Service) AssignRolesToSubject(ctx context.Context, subjectID string, roleIDs []int64) error {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return shared.ErrInvalidSubjectID
	}

	if err := s.assignments.AssignRoleToSubject(ctx, subjectID, roleIDs); err != nil {
		return fmt.Errorf("assign roles to subject: %w", err)
	}

	return nil
}

func (s *Service) ListSubjectRoles(ctx context.Context, subjectID string) ([]model.Role, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, shared.ErrInvalidSubjectID
	}

	roles, err := s.assignments.ListSubjectRoles(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("list subject roles: %w", err)
	}

	return roles, nil
}

func (s *Service) ListPermissions(ctx context.Context, filter repository.PermissionFilter) ([]model.Permission, error) {
	return s.permissions.ListByFilter(ctx, filter)
}

func (s *Service) EnsurePermissions(ctx context.Context, inputs []CreatePermissionInput) error {
	return s.ensurePermissions(ctx, inputs)
}

func (s *Service) ensurePermissions(ctx context.Context, inputs []CreatePermissionInput) error {
	if len(inputs) == 0 {
		return nil
	}

	keys := make([]shared.PermissionKey, 0, len(inputs))
	for _, input := range inputs {
		keys = append(keys, input.Key)
	}

	filter := repository.PermissionFilter{Keys: keys}
	perms, err := s.permissions.ListByFilter(ctx, filter)
	if err != nil {
		return fmt.Errorf("list permissions: %w", err)
	}

	if len(perms) == len(inputs) {
		return nil
	}

	existing := make(map[string]struct{}, len(perms))
	for _, perm := range perms {
		existing[shared.NewPermissionKey(perm.Domain, perm.Action).String()] = struct{}{}
	}

	missing := make([]CreatePermissionInput, 0, len(inputs))
	for _, input := range inputs {
		if input.Key.IsZero() {
			continue
		}

		if _, ok := existing[input.Key.String()]; ok {
			continue
		}

		missing = append(missing, input)
	}

	if len(missing) == 0 {
		return nil
	}

	if _, err = s.CreatePermissions(ctx, missing); err != nil {
		return fmt.Errorf("create permissions: %w", err)
	}

	return nil
}

func (s *Service) ListAllPermissionsByRoles(ctx context.Context, roleIDs []int64) ([]model.PermissionWithRole, error) {
	return s.permissions.ListAllPermissionsByRoles(ctx, roleIDs)
}

func (s *Service) HasPermission(ctx context.Context, subjectID string, key shared.PermissionKey) (bool, error) {
	if key.IsZero() {
		return false, shared.ErrInvalidPermission
	}
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return false, shared.ErrInvalidSubjectID
	}

	roles, err := s.assignments.ListSubjectRoles(ctx, subjectID)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		perms, err := s.assignments.ListPermissions(ctx, role.ID)
		if err != nil {
			return false, err
		}

		for _, perm := range perms {
			if shared.NewPermissionKey(perm.Domain, perm.Action) == key {
				return true, nil
			}
		}
	}

	return false, nil
}

func stringPtrOrNil(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func (s *Service) resolvePermissionIDs(ctx context.Context, keys []shared.PermissionKey) ([]int64, error) {
	if len(keys) == 0 {
		return nil, nil
	}

	unique := dedupePermissionKeys(keys)
	perms, err := s.permissions.ListByFilter(ctx, repository.PermissionFilter{Keys: unique})
	if err != nil {
		return nil, fmt.Errorf("list permissions: %w", err)
	}

	if len(perms) != len(unique) {
		missing := findMissingPermissionKeys(unique, perms)
		if len(missing) > 0 {
			return nil, fmt.Errorf("%w: %s", ErrPermissionMissing, strings.Join(missing, ", "))
		}
		return nil, ErrPermissionMissing
	}

	ids := make([]int64, 0, len(unique))
	index := make(map[string]int64, len(perms))
	for _, perm := range perms {
		index[shared.NewPermissionKey(perm.Domain, perm.Action).String()] = perm.ID
	}

	for _, key := range unique {
		ids = append(ids, index[key.String()])
	}

	return ids, nil
}

func toNullString(value *string) sql.NullString {
	if value == nil {
		return sql.NullString{}
	}

	v := strings.TrimSpace(*value)
	if v == "" {
		return sql.NullString{}
	}

	return sql.NullString{
		String: v,
		Valid:  true,
	}
}

func dedupePermissionKeys(keys []shared.PermissionKey) []shared.PermissionKey {
	if len(keys) <= 1 {
		return keys
	}

	seen := make(map[string]struct{}, len(keys))
	result := make([]shared.PermissionKey, 0, len(keys))
	for _, key := range keys {
		if key.IsZero() {
			continue
		}
		k := key.String()
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		result = append(result, key)
	}

	return result
}

func findMissingPermissionKeys(expected []shared.PermissionKey, actual []model.Permission) []string {
	if len(expected) == 0 {
		return nil
	}

	actualSet := make(map[string]struct{}, len(actual))
	for _, perm := range actual {
		actualSet[shared.NewPermissionKey(perm.Domain, perm.Action).String()] = struct{}{}
	}

	var missing []string
	for _, key := range expected {
		if _, ok := actualSet[key.String()]; !ok {
			missing = append(missing, key.String())
		}
	}

	return missing
}
