package roles

import (
	"context"

	"github.com/assurrussa/goshared/pkg/logger"

	rcucacheguard "github.com/assurrussa/goauth/domain/roles/cache/rcu/guard"
	"github.com/assurrussa/goauth/domain/roles/model"
	"github.com/assurrussa/goauth/domain/roles/repository"
	"github.com/assurrussa/goauth/domain/roles/repository/postgres"
	rolesseed "github.com/assurrussa/goauth/domain/roles/seeders/rolesseed"
	rolesguardservice "github.com/assurrussa/goauth/domain/roles/service/guard"
	rolesservice "github.com/assurrussa/goauth/domain/roles/service/roles"
	"github.com/assurrussa/goauth/domain/roles/shared"
	assignsubjectroles "github.com/assurrussa/goauth/domain/roles/usecases/command/assign_subject_roles"
	createrole "github.com/assurrussa/goauth/domain/roles/usecases/command/create_role"
	deleterole "github.com/assurrussa/goauth/domain/roles/usecases/command/delete_role"
	setrolepermissions "github.com/assurrussa/goauth/domain/roles/usecases/command/set_role_permissions"
	updaterole "github.com/assurrussa/goauth/domain/roles/usecases/command/update_role"
	getrole "github.com/assurrussa/goauth/domain/roles/usecases/query/get_role"
	listallroles "github.com/assurrussa/goauth/domain/roles/usecases/query/list_all_roles"
	listpermissions "github.com/assurrussa/goauth/domain/roles/usecases/query/list_permissions"
	listrolepermissions "github.com/assurrussa/goauth/domain/roles/usecases/query/list_role_permissions"
	listroles "github.com/assurrussa/goauth/domain/roles/usecases/query/list_roles"
	listsubjectroles "github.com/assurrussa/goauth/domain/roles/usecases/query/list_subject_roles"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

type (
	Repo        = postgres.Repo
	RepoOptions = postgres.Options
)

type (
	Seed       = rolesseed.Seed
	SeedOption = rolesseed.Option
)

type Service = rolesservice.Service

type (
	Role               = model.Role
	Permission         = model.Permission
	PermissionWithRole = model.PermissionWithRole
	RolePermission     = model.RolePermission
	SubjectRole        = model.SubjectRole
	RoleHierarchy      = model.RoleHierarchy
)

type (
	PermissionDomain      = shared.PermissionDomain
	PermissionAction      = shared.PermissionAction
	PermissionKey         = shared.PermissionKey
	PermissionCatalog     = shared.PermissionCatalog
	PermissionDefinition  = shared.PermissionDefinition
	PermissionGuardConfig = shared.PermissionGuardConfig
	PermissionGuardOption = shared.PermissionGuardOption
)

type (
	GuardCache       = rcucacheguard.CacheService
	GuardCacheOption = rcucacheguard.Option
)

type (
	GuardService        = rolesguardservice.Service
	GuardServiceOptions = rolesguardservice.Options
)

type (
	RoleFilter       = repository.RoleFilter
	PermissionFilter = repository.PermissionFilter
)

type (
	ListRolesUseCase  = listroles.UseCase
	ListRolesService  = listroles.Service
	ListRolesRequest  = listroles.Request
	ListRolesRole     = listroles.Role
	ListRolesResponse = listroles.Response
)

type (
	GetRoleUseCase    = getrole.UseCase
	GetRoleService    = getrole.Service
	GetRoleRequest    = getrole.Request
	GetRolePermission = getrole.Permission
	GetRoleResponse   = getrole.Response
)

type (
	CreateRoleUseCase  = createrole.UseCase
	CreateRoleService  = createrole.Service
	CreateRoleRequest  = createrole.Request
	CreateRoleResponse = createrole.Response
)

type (
	UpdateRoleUseCase  = updaterole.UseCase
	UpdateRoleService  = updaterole.Service
	UpdateRoleRequest  = updaterole.Request
	UpdateRoleResponse = updaterole.Response
)

type (
	DeleteRoleUseCase  = deleterole.UseCase
	DeleteRoleService  = deleterole.Service
	DeleteRoleRequest  = deleterole.Request
	DeleteRoleResponse = deleterole.Response
)

type (
	SetRolePermissionsUseCase  = setrolepermissions.UseCase
	SetRolePermissionsService  = setrolepermissions.Service
	SetRolePermissionsRequest  = setrolepermissions.Request
	SetRolePermissionsResponse = setrolepermissions.Response
)

type (
	AssignSubjectRolesUseCase  = assignsubjectroles.UseCase
	AssignSubjectRolesService  = assignsubjectroles.Service
	AssignSubjectRolesRequest  = assignsubjectroles.Request
	AssignSubjectRolesResponse = assignsubjectroles.Response
)

type (
	ListPermissionsUseCase    = listpermissions.UseCase
	ListPermissionsService    = listpermissions.Service
	ListPermissionsRequest    = listpermissions.Request
	ListPermissionsPermission = listpermissions.Permission
	ListPermissionsResponse   = listpermissions.Response
)

type (
	ListRolePermissionsUseCase    = listrolepermissions.UseCase
	ListRolePermissionsService    = listrolepermissions.Service
	ListRolePermissionsRequest    = listrolepermissions.Request
	ListRolePermissionsPermission = listrolepermissions.Permission
	ListRolePermissionsResponse   = listrolepermissions.Response
)

type (
	ListSubjectRolesUseCase  = listsubjectroles.UseCase
	ListSubjectRolesService  = listsubjectroles.Service
	ListSubjectRolesRequest  = listsubjectroles.Request
	ListSubjectRolesResponse = listsubjectroles.Response
)

type (
	ListAllRolesUseCase  = listallroles.UseCase
	ListAllRolesRequest  = listallroles.Request
	ListAllRolesResponse = listallroles.Response
)

type (
	CreatePermissionInput = rolesservice.CreatePermissionInput
	CreateRoleInput       = rolesservice.CreateRoleInput
	UpdateRoleInput       = rolesservice.UpdateRoleInput
)

type ListAllRolesService interface {
	ListRoles(ctx context.Context, filter repository.RoleFilter) ([]model.Role, error)
	ListRolePermissions(ctx context.Context, roleID int64) ([]model.Permission, error)
}

type ListAllRolesRepository interface {
	ListAllRolePermissions(ctx context.Context) ([]model.RolePermission, error)
	ListAllSubjectRoles(ctx context.Context) ([]model.SubjectRole, error)
	ListAllPermissions(ctx context.Context) ([]model.Permission, error)
	ListAllRoleHierarchy(ctx context.Context) ([]model.RoleHierarchy, error)
	ListSubjectRoles(ctx context.Context, subjectID string) ([]model.Role, error)
}

var (
	WithGuardCacheSyncInterval      = rcucacheguard.WithSyncInterval
	WithGuardCacheSyncCacheInterval = rcucacheguard.WithSyncCacheInterval
	NewGuardServiceOptions          = rolesguardservice.NewOptions
	ErrInvalidRoleName              = rolesservice.ErrInvalidRoleName
	NewSeed                         = rolesseed.NewSeed
	WithPermissionDefinitions       = rolesseed.WithPermissionDefinitions
	NewPermissionKey                = shared.NewPermissionKey
	ParsePermissionKey              = shared.ParsePermissionKey
	DefaultPermissionDefinitions    = shared.DefaultPermissionDefinitions
	NewPermissionCatalog            = shared.NewPermissionCatalog
	ClonePermissionDefinitions      = shared.ClonePermissionDefinitions
	MergePermissionDefinitions      = shared.MergePermissionDefinitions
	CreateRoles                     = shared.CreateRoles
	WithBypassRoles                 = shared.WithBypassRoles
	ErrRoleNotFound                 = shared.ErrRoleNotFound
	ErrPermissionNotFound           = shared.ErrPermissionNotFound
	ErrAssignmentNotFound           = shared.ErrAssignmentNotFound
	ErrInvalidPermission            = shared.ErrInvalidPermission
	ErrInvalidRoleID                = shared.ErrInvalidRoleID
	ErrInvalidRoleSlug              = shared.ErrInvalidRoleSlug
	ErrInvalidSubjectID             = shared.ErrInvalidSubjectID
	ErrSystemRoleProtected          = shared.ErrSystemRoleProtected
)

const (
	SuperAdminRole   = shared.SuperAdminRole
	SuperSubjectRole = shared.SuperSubjectRole
)

const (
	PermissionDomainRoles       = shared.PermissionDomainRoles
	PermissionDomainPermissions = shared.PermissionDomainPermissions
	PermissionDomainAdmins      = shared.PermissionDomainAdmins
	PermissionDomainDashboard   = shared.PermissionDomainDashboard
	PermissionDomainOperations  = shared.PermissionDomainOperations
	PermissionDomainUsers       = shared.PermissionDomainUsers
	PermissionDomainUploads     = shared.PermissionDomainUploads
	PermissionDomainQueues      = shared.PermissionDomainQueues
)

const (
	PermissionActionRead   = shared.PermissionActionRead
	PermissionActionCreate = shared.PermissionActionCreate
	PermissionActionUpdate = shared.PermissionActionUpdate
	PermissionActionDelete = shared.PermissionActionDelete
	PermissionActionAssign = shared.PermissionActionAssign
	PermissionActionSync   = shared.PermissionActionSync
)

func NewRepo(db outbox.StoragePgsqlClient, tx outbox.StoragePgsqlTxManager) (*Repo, error) {
	return postgres.New(postgres.Options{Pgsql: db, TxManager: tx})
}

func MustRepo(db outbox.StoragePgsqlClient, tx outbox.StoragePgsqlTxManager) *Repo {
	return postgres.Must(postgres.Options{Pgsql: db, TxManager: tx})
}

func MustService(repo *Repo) *Service {
	return rolesservice.Must(serviceDependencies(repo))
}

func NewService(repo *Repo) (*Service, error) {
	return rolesservice.New(serviceDependencies(repo))
}

func NewGuardCache(
	ctx context.Context,
	lg logger.Logger,
	listAll *ListAllRolesUseCase,
	opts ...GuardCacheOption,
) (*GuardCache, error) {
	if lg == nil {
		lg = logger.Discard()
	}

	return rcucacheguard.NewCache(ctx, lg, listAll, opts...)
}

func NewGuardService(
	listSubject *ListSubjectRolesUseCase,
	roles *Service,
	cache *GuardCache,
	lg logger.Logger,
) (*GuardService, error) {
	if lg == nil {
		lg = logger.Discard()
	}

	return rolesguardservice.New(rolesguardservice.NewOptions(listSubject, roles, cache, lg))
}

func NewGuardServiceWithOptions(opts GuardServiceOptions) (*GuardService, error) {
	return rolesguardservice.New(opts)
}

func MustListRolesUseCase(service ListRolesService) *ListRolesUseCase {
	return listroles.Must(service)
}

func MustGetRoleUseCase(service GetRoleService) *GetRoleUseCase {
	return getrole.Must(service)
}

func MustCreateRoleUseCase(service CreateRoleService) *CreateRoleUseCase {
	return createrole.Must(service)
}

func MustUpdateRoleUseCase(service UpdateRoleService) *UpdateRoleUseCase {
	return updaterole.Must(service)
}

func MustDeleteRoleUseCase(service DeleteRoleService) *DeleteRoleUseCase {
	return deleterole.Must(service)
}

func MustSetRolePermissionsUseCase(service SetRolePermissionsService) *SetRolePermissionsUseCase {
	return setrolepermissions.Must(service)
}

func MustAssignSubjectRolesUseCase(service AssignSubjectRolesService) *AssignSubjectRolesUseCase {
	return assignsubjectroles.Must(service)
}

func MustListPermissionsUseCase(service ListPermissionsService) *ListPermissionsUseCase {
	return listpermissions.Must(service)
}

func MustListRolePermissionsUseCase(service ListRolePermissionsService) *ListRolePermissionsUseCase {
	return listrolepermissions.Must(service)
}

func MustListSubjectRolesUseCase(service ListSubjectRolesService) *ListSubjectRolesUseCase {
	return listsubjectroles.Must(service)
}

func MustListAllRolesUseCase(service ListAllRolesService, repo ListAllRolesRepository) *ListAllRolesUseCase {
	return listallroles.Must(service, repo, repo, repo, repo)
}

func serviceDependencies(repo *Repo) rolesservice.Dependencies {
	return rolesservice.Dependencies{
		Roles:       repo,
		Permissions: repo,
		Assignments: repo,
		Hierarchy:   repo,
	}
}
