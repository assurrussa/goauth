package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/georgysavva/scany/v2/pgxscan"

	"github.com/assurrussa/goauth/domain/roles/model"
	"github.com/assurrussa/goauth/domain/roles/repository"
	"github.com/assurrussa/goauth/domain/roles/shared"
	outbox "github.com/assurrussa/goauth/infrastructure/outbox"
)

const (
	rolesTable           = "roles"
	permissionsTable     = "permissions"
	rolePermissionsTable = "role_permissions"
	subjectRolesTable    = "auth_subject_roles"
	roleHierarchyTable   = "role_hierarchy"
)

var (
	roleColumns = []string{
		"id",
		"uuid",
		"slug",
		"name",
		"description",
		"is_system",
		"created_at",
		"updated_at",
	}

	permissionColumns = []string{
		"id",
		"uuid",
		"domain",
		"action",
		"description",
		"created_at",
		"updated_at",
	}

	roleReturningColumns       = strings.Join(roleColumns, ", ")
	permissionReturningColumns = strings.Join(permissionColumns, ", ")
)

type Options struct {
	Pgsql     outbox.StoragePgsqlClient
	TxManager outbox.StoragePgsqlTxManager
}

func (o Options) Validate() error {
	if o.Pgsql == nil {
		return errors.New("roles repo: nil pgsql client")
	}
	if o.TxManager == nil {
		return errors.New("roles repo: nil tx manager")
	}

	return nil
}

type Repo struct {
	pg        outbox.StoragePgsqlClient
	txManager outbox.StoragePgsqlTxManager
}

func New(opts Options) (*Repo, error) {
	if err := opts.Validate(); err != nil {
		return nil, err
	}

	return &Repo{
		pg:        opts.Pgsql,
		txManager: opts.TxManager,
	}, nil
}

func Must(opts Options) *Repo {
	repo, err := New(opts)
	if err != nil {
		panic(fmt.Errorf("roles repo: %w", err))
	}

	return repo
}

func (r *Repo) List(ctx context.Context, filter repository.RoleFilter) ([]model.Role, error) {
	const op = "roles.repo.List"

	qb := outbox.BuilderDollar().
		Select(roleColumns...).
		From(rolesTable)

	if len(filter.IDs) > 0 {
		qb = qb.Where(squirrel.Eq{"id": filter.IDs})
	}

	if len(filter.Slugs) > 0 {
		qb = qb.Where(squirrel.Eq{"slug": filter.Slugs})
	}

	if !filter.IncludeSys {
		qb = qb.Where(squirrel.Eq{"is_system": false})
	}

	if filter.Search != "" {
		search := "%" + strings.ToLower(filter.Search) + "%"
		qb = qb.Where(squirrel.Or{
			squirrel.Expr("lower(name) LIKE ?", search),
			squirrel.Expr("lower(slug) LIKE ?", search),
		})
	}

	qb = qb.OrderBy("created_at DESC", "id DESC")

	if filter.Pagination.Limit > 0 {
		qb = qb.Limit(filter.Pagination.Limit)
	}

	if filter.Pagination.Offset > 0 {
		qb = qb.Offset(filter.Pagination.Offset)
	}

	var roles []model.Role
	if err := r.pg.DB().ScanAllx(ctx, op, &roles, qb); err != nil {
		return nil, fmt.Errorf("%s: list roles: %w", op, outbox.ErrorTransform(err))
	}

	return roles, nil
}

func (r *Repo) GetByID(ctx context.Context, id int64) (*model.Role, error) {
	const op = "roles.repo.GetByID"

	if id <= 0 {
		return nil, shared.ErrInvalidRoleID
	}

	qb := outbox.BuilderDollar().
		Select(roleColumns...).
		From(rolesTable).
		Where(squirrel.Eq{"id": id}).
		Limit(1)

	var role model.Role
	if err := r.pg.DB().ScanOnex(ctx, op, &role, qb); err != nil {
		if pgxscan.NotFound(err) {
			return nil, nil //nolint:nilnil // is need
		}

		return nil, fmt.Errorf("%s: get by id: %w", op, outbox.ErrorTransform(err))
	}

	return &role, nil
}

func (r *Repo) GetBySlug(ctx context.Context, slug string) (*model.Role, error) {
	const op = "roles.repo.GetBySlug"

	if slug == "" {
		return nil, shared.ErrInvalidRoleSlug
	}

	qb := outbox.BuilderDollar().
		Select(roleColumns...).
		From(rolesTable).
		Where(squirrel.Eq{"slug": slug}).
		Limit(1)

	var role model.Role
	if err := r.pg.DB().ScanOnex(ctx, op, &role, qb); err != nil {
		if pgxscan.NotFound(err) {
			return nil, nil //nolint:nilnil // is need
		}

		return nil, fmt.Errorf("%s: get by slug: %w", op, outbox.ErrorTransform(err))
	}

	return &role, nil
}

func (r *Repo) Create(ctx context.Context, input model.Role) (*model.Role, error) {
	const op = "roles.repo.Create"

	now := time.Now()
	qb := outbox.BuilderDollar().
		Insert(rolesTable).
		Columns("uuid", "slug", "name", "description", "is_system", "created_at", "updated_at").
		Values(input.UUID, input.Slug, input.Name, input.Description, input.IsSystem, now, now).
		Suffix("RETURNING " + roleReturningColumns)

	var role model.Role
	if err := r.pg.DB().ScanOnex(ctx, op, &role, qb); err != nil {
		return nil, fmt.Errorf("%s: create role: %w", op, outbox.ErrorTransform(err))
	}

	return &role, nil
}

func (r *Repo) Update(ctx context.Context, input model.Role) (*model.Role, error) {
	const op = "roles.repo.Update"

	if input.ID <= 0 {
		return nil, shared.ErrInvalidRoleID
	}

	qb := outbox.BuilderDollar().
		Update(rolesTable).
		Set("slug", input.Slug).
		Set("name", input.Name).
		Set("description", input.Description).
		Set("is_system", input.IsSystem).
		Set("updated_at", time.Now()).
		Where(squirrel.Eq{"id": input.ID}).
		Suffix("RETURNING " + roleReturningColumns)

	var role model.Role
	if err := r.pg.DB().ScanOnex(ctx, op, &role, qb); err != nil {
		return nil, fmt.Errorf("%s: update role: %w", op, outbox.ErrorTransform(err))
	}

	return &role, nil
}

func (r *Repo) Delete(ctx context.Context, id int64) error {
	const op = "roles.repo.Delete"

	if id <= 0 {
		return shared.ErrInvalidRoleID
	}

	qb := outbox.BuilderDollar().
		Delete(rolesTable).
		Where(squirrel.Eq{"id": id})

	if _, err := r.pg.DB().Execx(ctx, op, qb); err != nil {
		return fmt.Errorf("%s: delete role: %w", op, outbox.ErrorTransform(err))
	}

	return nil
}

func (r *Repo) ListByFilter(ctx context.Context, filter repository.PermissionFilter) ([]model.Permission, error) {
	const op = "roles.repo.ListPermissions"

	qb := outbox.BuilderDollar().
		Select(permissionColumns...).
		From(permissionsTable)

	if len(filter.IDs) > 0 {
		qb = qb.Where(squirrel.Eq{"id": filter.IDs})
	}

	if len(filter.UUIDs) > 0 {
		qb = qb.Where(squirrel.Eq{"uuid": filter.UUIDs})
	}

	if len(filter.Keys) > 0 {
		var orFilters []squirrel.Sqlizer
		for _, key := range filter.Keys {
			if key.IsZero() {
				continue
			}
			orFilters = append(orFilters, squirrel.And{
				squirrel.Eq{"domain": key.Domain},
				squirrel.Eq{"action": key.Action},
			})
		}
		if len(orFilters) > 0 {
			qb = qb.Where(squirrel.Or(orFilters))
		}
	}

	if filter.Domain != "" {
		qb = qb.Where(squirrel.Eq{"domain": filter.Domain})
	}

	if filter.Action != "" {
		qb = qb.Where(squirrel.Eq{"action": filter.Action})
	}

	qb = qb.OrderBy("domain ASC", "action ASC")

	var permissions []model.Permission
	if err := r.pg.DB().ScanAllx(ctx, op, &permissions, qb); err != nil {
		return nil, fmt.Errorf("%s: list permissions: %w", op, outbox.ErrorTransform(err))
	}

	return permissions, nil
}

func (r *Repo) GetByKey(ctx context.Context, key shared.PermissionKey) (*model.Permission, error) {
	const op = "roles.repo.GetPermissionByKey"

	if key.IsZero() {
		return nil, shared.ErrInvalidPermission
	}

	qb := outbox.BuilderDollar().
		Select(permissionColumns...).
		From(permissionsTable).
		Where(squirrel.Eq{"domain": key.Domain, "action": key.Action}).
		Limit(1)

	var perm model.Permission
	if err := r.pg.DB().ScanOnex(ctx, op, &perm, qb); err != nil {
		if pgxscan.NotFound(err) {
			return nil, nil //nolint:nilnil // is need
		}

		return nil, fmt.Errorf("%s: get permission by key: %w", op, outbox.ErrorTransform(err))
	}

	return &perm, nil
}

func (r *Repo) GetByUUID(ctx context.Context, uuid string) (*model.Permission, error) {
	const op = "roles.repo.GetPermissionByUUID"

	if uuid == "" {
		return nil, fmt.Errorf("%s: invalid uuid", op)
	}

	qb := outbox.BuilderDollar().
		Select(permissionColumns...).
		From(permissionsTable).
		Where(squirrel.Eq{"uuid": uuid}).
		Limit(1)

	var perm model.Permission
	if err := r.pg.DB().ScanOnex(ctx, op, &perm, qb); err != nil {
		if pgxscan.NotFound(err) {
			return nil, nil //nolint:nilnil // is need
		}

		return nil, fmt.Errorf("%s: get permission by uuid: %w", op, outbox.ErrorTransform(err))
	}

	return &perm, nil
}

func (r *Repo) CreateBulk(ctx context.Context, inputs []model.Permission) ([]model.Permission, error) {
	const op = "roles.repo.CreatePermissionsBulk"

	if len(inputs) == 0 {
		return nil, nil
	}

	qb := outbox.BuilderDollar().
		Insert(permissionsTable).
		Columns("uuid", "domain", "action", "description").
		Suffix("RETURNING " + permissionReturningColumns)

	for _, input := range inputs {
		qb = qb.Values(input.UUID, input.Domain, input.Action, input.Description)
	}

	var created []model.Permission
	if err := r.pg.DB().ScanAllx(ctx, op, &created, qb); err != nil {
		return nil, fmt.Errorf("%s: create bulk permissions: %w", op, outbox.ErrorTransform(err))
	}

	return created, nil
}

func (r *Repo) ReplacePermissions(ctx context.Context, roleID int64, permissionIDs []int64) error {
	const op = "roles.repo.ReplacePermissions"

	if roleID <= 0 {
		return shared.ErrInvalidRoleID
	}

	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		deleteQB := outbox.BuilderDollar().
			Delete(rolePermissionsTable).
			Where(squirrel.Eq{"role_id": roleID})

		if _, err := r.pg.DB().Execx(txCtx, op+".delete", deleteQB); err != nil {
			return fmt.Errorf("%s: delete old permissions: %w", op, outbox.ErrorTransform(err))
		}

		if len(permissionIDs) == 0 {
			return nil
		}

		insertQB := outbox.BuilderDollar().
			Insert(rolePermissionsTable).
			Columns("role_id", "permission_id", "created_at")

		now := time.Now()
		for _, permissionID := range permissionIDs {
			insertQB = insertQB.Values(roleID, permissionID, now)
		}

		if _, err := r.pg.DB().Execx(txCtx, op+".insert", insertQB); err != nil {
			return fmt.Errorf("%s: insert permissions: %w", op, outbox.ErrorTransform(err))
		}

		return nil
	})
}

func (r *Repo) ListPermissions(ctx context.Context, roleID int64) ([]model.Permission, error) {
	const op = "roles.repo.ListPermissionsByRole"

	if roleID <= 0 {
		return nil, shared.ErrInvalidRoleID
	}

	qb := outbox.BuilderDollar().
		Select("p.id", "p.uuid", "p.domain", "p.action", "p.description", "p.created_at", "p.updated_at").
		From(rolePermissionsTable + " rp").
		Join(permissionsTable + " p ON p.id = rp.permission_id").
		Where(squirrel.Eq{"rp.role_id": roleID})

	var permissions []model.Permission
	if err := r.pg.DB().ScanAllx(ctx, op, &permissions, qb); err != nil {
		return nil, fmt.Errorf("%s: list permissions by role: %w", op, outbox.ErrorTransform(err))
	}

	return permissions, nil
}

func (r *Repo) ListAllPermissionsByRoles(ctx context.Context, roleIDs []int64) ([]model.PermissionWithRole, error) {
	const op = "roles.repo.ListPermissionsByRole"

	if len(roleIDs) == 0 {
		return nil, shared.ErrInvalidRoleID
	}

	qb := outbox.BuilderDollar().
		Select("p.id", "rp.id as role_id", "p.uuid", "p.domain", "p.action", "p.description", "p.created_at", "p.updated_at").
		From(rolePermissionsTable + " rp").
		Join(permissionsTable + " p ON p.id = rp.permission_id").
		Where(squirrel.Eq{"rp.role_id": roleIDs})

	var permissions []model.PermissionWithRole
	if err := r.pg.DB().ScanAllx(ctx, op, &permissions, qb); err != nil {
		return nil, fmt.Errorf("%s: list permissions by role: %w", op, outbox.ErrorTransform(err))
	}

	return permissions, nil
}

func (r *Repo) ListAllPermissions(ctx context.Context) ([]model.Permission, error) {
	const op = "roles.repo.ListAllPermissions"

	qb := outbox.BuilderDollar().
		Select("p.id", "p.uuid", "p.domain", "p.action", "p.description", "p.created_at", "p.updated_at").
		From(permissionsTable + " p")

	var permissions []model.Permission
	if err := r.pg.DB().ScanAllx(ctx, op, &permissions, qb); err != nil {
		return nil, fmt.Errorf("%s: list all permissions: %w", op, outbox.ErrorTransform(err))
	}

	return permissions, nil
}

func (r *Repo) ListAllRolePermissions(ctx context.Context) ([]model.RolePermission, error) {
	const op = "roles.repo.ListAllRolePermissions"

	qb := outbox.BuilderDollar().
		Select("p.role_id", "p.permission_id", "p.created_at").
		From(rolePermissionsTable + " p")

	var data []model.RolePermission
	if err := r.pg.DB().ScanAllx(ctx, op, &data, qb); err != nil {
		return nil, fmt.Errorf("%s: list all role permissions: %w", op, outbox.ErrorTransform(err))
	}

	return data, nil
}

func (r *Repo) ListAllRoleHierarchy(ctx context.Context) ([]model.RoleHierarchy, error) {
	const op = "roles.repo.ListAllRoleHierarchy"

	qb := outbox.BuilderDollar().
		Select("p.parent_role_id", "p.child_role_id", "p.created_at").
		From(roleHierarchyTable + " p")

	var data []model.RoleHierarchy
	if err := r.pg.DB().ScanAllx(ctx, op, &data, qb); err != nil {
		return nil, fmt.Errorf("%s: list all role hierarchy: %w", op, outbox.ErrorTransform(err))
	}

	return data, nil
}

func (r *Repo) ListAllSubjectRoles(ctx context.Context) ([]model.SubjectRole, error) {
	const op = "roles.repo.ListAllSubjectRoles"

	qb := outbox.BuilderDollar().
		Select("p.subject_id", "p.role_id", "p.created_at").
		From(subjectRolesTable + " p")

	var data []model.SubjectRole
	if err := r.pg.DB().ScanAllx(ctx, op, &data, qb); err != nil {
		return nil, fmt.Errorf("%s: list all subject roles: %w", op, outbox.ErrorTransform(err))
	}

	return data, nil
}

func (r *Repo) AssignRoleToSubject(ctx context.Context, subjectID string, roleIDs []int64) error {
	const op = "roles.repo.AssignRoleToSubject"

	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return shared.ErrInvalidSubjectID
	}

	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		deleteQB := outbox.BuilderDollar().
			Delete(subjectRolesTable).
			Where(squirrel.Eq{"subject_id": subjectID})

		if _, err := r.pg.DB().Execx(txCtx, op+".delete", deleteQB); err != nil {
			return fmt.Errorf("%s: delete subject roles: %w", op, outbox.ErrorTransform(err))
		}

		if len(roleIDs) == 0 {
			return nil
		}

		insertQB := outbox.BuilderDollar().
			Insert(subjectRolesTable).
			Columns("subject_id", "role_id", "created_at")

		now := time.Now()
		for _, roleID := range roleIDs {
			insertQB = insertQB.Values(subjectID, roleID, now)
		}

		if _, err := r.pg.DB().Execx(txCtx, op+".insert", insertQB); err != nil {
			return fmt.Errorf("%s: insert subject roles: %w", op, outbox.ErrorTransform(err))
		}

		return nil
	})
}

func (r *Repo) ListSubjectRoles(ctx context.Context, subjectID string) ([]model.Role, error) {
	const op = "roles.repo.ListSubjectRoles"

	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return nil, shared.ErrInvalidSubjectID
	}

	selectColumns := make([]string, len(roleColumns))
	for i, column := range roleColumns {
		selectColumns[i] = "r." + column
	}

	qb := outbox.BuilderDollar().
		Select(selectColumns...).
		From(subjectRolesTable + " ar").
		Join(rolesTable + " r ON r.id = ar.role_id").
		Where(squirrel.Eq{"ar.subject_id": subjectID})

	var roles []model.Role
	if err := r.pg.DB().ScanAllx(ctx, op, &roles, qb); err != nil {
		return nil, fmt.Errorf("%s: list subject roles: %w", op, outbox.ErrorTransform(err))
	}

	return roles, nil
}

func (r *Repo) SetParent(ctx context.Context, childRoleID int64, parentRoleID *int64) error {
	const op = "roles.repo.SetParent"

	if childRoleID <= 0 {
		return shared.ErrInvalidRoleID
	}

	return r.txManager.RunInTx(ctx, func(txCtx context.Context) error {
		deleteQB := outbox.BuilderDollar().
			Delete(roleHierarchyTable).
			Where(squirrel.Eq{"child_role_id": childRoleID})

		if _, err := r.pg.DB().Execx(txCtx, op+".delete", deleteQB); err != nil {
			return fmt.Errorf("%s: delete hierarchy link: %w", op, outbox.ErrorTransform(err))
		}

		if parentRoleID == nil || *parentRoleID <= 0 {
			return nil
		}

		insertQB := outbox.BuilderDollar().
			Insert(roleHierarchyTable).
			Columns("parent_role_id", "child_role_id", "created_at").
			Values(*parentRoleID, childRoleID, time.Now())

		if _, err := r.pg.DB().Execx(txCtx, op+".insert", insertQB); err != nil {
			return fmt.Errorf("%s: insert hierarchy link: %w", op, outbox.ErrorTransform(err))
		}

		return nil
	})
}

func (r *Repo) ListChildren(ctx context.Context, parentRoleID int64) ([]model.RoleHierarchy, error) {
	const op = "roles.repo.ListChildren"

	if parentRoleID <= 0 {
		return nil, shared.ErrInvalidRoleID
	}

	qb := outbox.BuilderDollar().
		Select("parent_role_id", "child_role_id", "created_at").
		From(roleHierarchyTable).
		Where(squirrel.Eq{"parent_role_id": parentRoleID})

	var pairs []model.RoleHierarchy
	if err := r.pg.DB().ScanAllx(ctx, op, &pairs, qb); err != nil {
		return nil, fmt.Errorf("%s: list children: %w", op, outbox.ErrorTransform(err))
	}

	return pairs, nil
}

func (r *Repo) ListParents(ctx context.Context, childRoleID int64) ([]model.RoleHierarchy, error) {
	const op = "roles.repo.ListParents"

	if childRoleID <= 0 {
		return nil, shared.ErrInvalidRoleID
	}

	qb := outbox.BuilderDollar().
		Select("parent_role_id", "child_role_id", "created_at").
		From(roleHierarchyTable).
		Where(squirrel.Eq{"child_role_id": childRoleID})

	var pairs []model.RoleHierarchy
	if err := r.pg.DB().ScanAllx(ctx, op, &pairs, qb); err != nil {
		return nil, fmt.Errorf("%s: list parents: %w", op, outbox.ErrorTransform(err))
	}

	return pairs, nil
}

// Interface guards.
var (
	_ repository.RoleRepository       = (*Repo)(nil)
	_ repository.PermissionRepository = (*Repo)(nil)
	_ repository.AssignmentRepository = (*Repo)(nil)
	_ repository.HierarchyRepository  = (*Repo)(nil)
)
