package repository

import (
	"context"

	"github.com/assurrussa/goauth/domain/roles/model"
	"github.com/assurrussa/goauth/domain/roles/shared"
)

//go:generate toolsmocks

type RoleFilter struct {
	IDs        []int64
	Slugs      []string
	IncludeSys bool
	Search     string
	Pagination Pagination
}

type PermissionFilter struct {
	IDs    []int64
	UUIDs  []string
	Keys   []shared.PermissionKey
	Domain string
	Action string
}

type Pagination struct {
	Limit  uint64
	Offset uint64
}

type RoleRepository interface {
	List(ctx context.Context, filter RoleFilter) ([]model.Role, error)
	GetByID(ctx context.Context, id int64) (*model.Role, error)
	GetBySlug(ctx context.Context, slug string) (*model.Role, error)
	Create(ctx context.Context, input model.Role) (*model.Role, error)
	Update(ctx context.Context, input model.Role) (*model.Role, error)
	Delete(ctx context.Context, id int64) error
	ListAllRolePermissions(ctx context.Context) ([]model.RolePermission, error)
	ListAllSubjectRoles(ctx context.Context) ([]model.SubjectRole, error)
}

type PermissionRepository interface {
	ListByFilter(ctx context.Context, filter PermissionFilter) ([]model.Permission, error)
	GetByKey(ctx context.Context, key shared.PermissionKey) (*model.Permission, error)
	GetByUUID(ctx context.Context, uuid string) (*model.Permission, error)
	CreateBulk(ctx context.Context, inputs []model.Permission) ([]model.Permission, error)
	ListAllPermissions(ctx context.Context) ([]model.Permission, error)
	ListAllPermissionsByRoles(ctx context.Context, roleIDs []int64) ([]model.PermissionWithRole, error)
}

type AssignmentRepository interface {
	ReplacePermissions(ctx context.Context, roleID int64, permissionIDs []int64) error
	ListPermissions(ctx context.Context, roleID int64) ([]model.Permission, error)
	AssignRoleToSubject(ctx context.Context, subjectID string, roleIDs []int64) error
	ListSubjectRoles(ctx context.Context, subjectID string) ([]model.Role, error)
}

type HierarchyRepository interface {
	SetParent(ctx context.Context, childRoleID int64, parentRoleID *int64) error
	ListChildren(ctx context.Context, parentRoleID int64) ([]model.RoleHierarchy, error)
	ListParents(ctx context.Context, childRoleID int64) ([]model.RoleHierarchy, error)
	ListAllRoleHierarchy(ctx context.Context) ([]model.RoleHierarchy, error)
}
