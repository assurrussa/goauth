package rbac

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/assurrussa/goauth"
)

var (
	ErrInvalidPermissionKey  = errors.New("invalid permission key")
	ErrPermissionDenied      = errors.New("permission denied")
	ErrInvalidRole           = errors.New("invalid role")
	ErrRoleNotFound          = errors.New("role not found")
	ErrPermissionNotFound    = errors.New("permission not found")
	ErrSystemRoleProtected   = errors.New("system role is protected")
	ErrManagementUnavailable = errors.New("RBAC management store is unavailable")
	// ErrSnapshotTransactionUnsupported rejects snapshots inside a managed auth
	// transaction, whose isolation cannot guarantee a consistent cache rebuild.
	ErrSnapshotTransactionUnsupported = errors.New("RBAC snapshot requires a standalone repeatable-read transaction")
)

type PermissionKey string

func NewPermissionKey(domain, action string) (PermissionKey, error) {
	domain = strings.TrimSpace(domain)
	action = strings.TrimSpace(action)
	key := PermissionKey(domain + ":" + action)
	if err := key.Validate(); err != nil {
		return "", err
	}

	return key, nil
}

func MustPermissionKey(domain, action string) PermissionKey {
	key, err := NewPermissionKey(domain, action)
	if err != nil {
		panic(err)
	}

	return key
}

func (k PermissionKey) Validate() error {
	domain, action, ok := strings.Cut(string(k), ":")
	if !ok || strings.Contains(action, ":") || !validSegment(domain) || !validSegment(action) {
		return fmt.Errorf("%w: %q", ErrInvalidPermissionKey, k)
	}

	return nil
}

type Role struct {
	ID          int64
	PublicID    string
	Slug        string
	Name        string
	Description string
	System      bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Permission struct {
	ID          int64
	PublicID    string
	Key         PermissionKey
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type Store interface {
	HasPermission(ctx context.Context, subjectID goauth.SubjectID, key PermissionKey) (bool, error)
}

// ManagementStore is optional. Read-only authorization consumers only need
// Store; PostgreSQL Runtime implements both contracts.
type ManagementStore interface {
	UpsertRole(ctx context.Context, role Role) (Role, error)
	UpsertPermission(ctx context.Context, permission Permission) (Permission, error)
	AssignRole(ctx context.Context, subjectID goauth.SubjectID, roleSlug string) error
	SetRolePermissions(ctx context.Context, roleSlug string, keys []PermissionKey) error
	ListRoles(ctx context.Context, filter RoleFilter) ([]Role, error)
	GetRole(ctx context.Context, roleID int64) (Role, error)
	CreateRole(ctx context.Context, role Role, keys []PermissionKey) (Role, error)
	UpdateRole(ctx context.Context, role Role, keys *[]PermissionKey) (Role, error)
	DeleteRole(ctx context.Context, roleID int64) error
	ListPermissions(ctx context.Context, filter PermissionFilter) ([]Permission, error)
	ListRolePermissions(ctx context.Context, roleID int64) ([]Permission, error)
	ReplaceRolePermissions(ctx context.Context, roleID int64, keys []PermissionKey) error
	ReplaceSubjectRoles(ctx context.Context, subjectID goauth.SubjectID, roleIDs []int64) error
	ListSubjectRoles(ctx context.Context, subjectID goauth.SubjectID) ([]Role, error)
	Snapshot(ctx context.Context) (Snapshot, error)
}

type Cache interface {
	HasPermission(
		ctx context.Context,
		subjectID goauth.SubjectID,
		key PermissionKey,
	) (allowed bool, found bool, err error)
}

// CacheInvalidator clears cached authorization after committed management writes.
// PostgreSQL requires this capability when a cache is supplied.
// Implementations must honor context cancellation and deadlines, and return
// only after invalidation has completed; failures leave the cache bypassed.
type CacheInvalidator interface {
	Invalidate(ctx context.Context) error
}

type Service struct {
	store      Store
	management ManagementStore
	cache      Cache
}

func New(store Store, cache Cache) (*Service, error) {
	if store == nil {
		return nil, errors.New("RBAC store is required")
	}

	management, _ := store.(ManagementStore)

	return &Service{store: store, management: management, cache: cache}, nil
}

func (s *Service) Can(ctx context.Context, subjectID goauth.SubjectID, key PermissionKey) bool {
	if subjectID.IsZero() || key.Validate() != nil {
		return false
	}
	if s.cache != nil {
		allowed, found, err := s.cache.HasPermission(ctx, subjectID, key)
		if err != nil {
			return false
		}
		if found {
			return allowed
		}
	}
	allowed, err := s.store.HasPermission(ctx, subjectID, key)
	return err == nil && allowed
}

func (s *Service) Require(ctx context.Context, subjectID goauth.SubjectID, key PermissionKey) error {
	if !s.Can(ctx, subjectID, key) {
		return ErrPermissionDenied
	}

	return nil
}

func (s *Service) UpsertRole(ctx context.Context, role Role) (Role, error) {
	if s.management == nil {
		return Role{}, ErrManagementUnavailable
	}
	if err := normalizeRole(&role); err != nil {
		return Role{}, err
	}

	return s.management.UpsertRole(ctx, role)
}

func normalizeRole(role *Role) error {
	role.Slug = strings.TrimSpace(role.Slug)
	role.Name = strings.TrimSpace(role.Name)
	role.Description = strings.TrimSpace(role.Description)
	if !validSegment(role.Slug) || role.Name == "" || len(role.Name) > 128 || len(role.Description) > 1024 {
		return ErrInvalidRole
	}

	return nil
}

func (s *Service) UpsertPermission(ctx context.Context, permission Permission) (Permission, error) {
	if s.management == nil {
		return Permission{}, ErrManagementUnavailable
	}
	if err := permission.Key.Validate(); err != nil {
		return Permission{}, err
	}

	return s.management.UpsertPermission(ctx, permission)
}

func (s *Service) AssignRole(ctx context.Context, subjectID goauth.SubjectID, roleSlug string) error {
	if s.management == nil {
		return ErrManagementUnavailable
	}
	if subjectID.IsZero() || !validSegment(strings.TrimSpace(roleSlug)) {
		return errors.New("invalid role assignment")
	}

	return s.management.AssignRole(ctx, subjectID, strings.TrimSpace(roleSlug))
}

func (s *Service) SetRolePermissions(ctx context.Context, roleSlug string, keys []PermissionKey) error {
	if s.management == nil {
		return ErrManagementUnavailable
	}
	roleSlug = strings.TrimSpace(roleSlug)
	if !validSegment(roleSlug) {
		return errors.New("invalid role")
	}
	unique := make(map[PermissionKey]struct{}, len(keys))
	result := make([]PermissionKey, 0, len(keys))
	for _, key := range keys {
		if err := key.Validate(); err != nil {
			return err
		}
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = struct{}{}
		result = append(result, key)
	}

	return s.management.SetRolePermissions(ctx, roleSlug, result)
}

func validSegment(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(index > 0 && character >= '0' && character <= '9') ||
			(index > 0 && (character == '_' || character == '-')) {
			continue
		}
		return false
	}

	return true
}
