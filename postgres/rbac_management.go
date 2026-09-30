package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

const (
	roleColumns             = `id, public_id::text, slug, name, description, is_system, created_at, updated_at`
	permissionColumns       = `id, public_id::text, permission_key, description, created_at, updated_at`
	rolePermissionListQuery = `
SELECT p.id, p.public_id::text, p.permission_key, p.description, p.created_at, p.updated_at
FROM auth_role_permissions rp
JOIN auth_permissions p ON p.id = rp.permission_id
WHERE rp.role_id = $1
ORDER BY p.permission_key, p.id`
	subjectRoleListQuery = `
SELECT r.id, r.public_id::text, r.slug, r.name, r.description, r.is_system, r.created_at, r.updated_at
FROM auth_subject_roles sr
JOIN auth_roles r ON r.id = sr.role_id
WHERE sr.subject_id = $1
ORDER BY r.is_system DESC, r.name, r.id`
)

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRole(row rowScanner) (rbac.Role, error) {
	var role rbac.Role
	err := row.Scan(
		&role.ID,
		&role.PublicID,
		&role.Slug,
		&role.Name,
		&role.Description,
		&role.System,
		&role.CreatedAt,
		&role.UpdatedAt,
	)

	return role, err
}

func scanPermission(row rowScanner) (rbac.Permission, error) {
	var permission rbac.Permission
	err := row.Scan(
		&permission.ID,
		&permission.PublicID,
		&permission.Key,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)

	return permission, err
}

func (s *rbacStore) ListRoles(ctx context.Context, filter rbac.RoleFilter) ([]rbac.Role, error) {
	query := `SELECT ` + roleColumns + ` FROM auth_roles`
	conditions := make([]string, 0, 4)
	args := make([]any, 0, len(filter.IDs)+len(filter.Slugs)+2)
	if !filter.IncludeSystem {
		conditions = append(conditions, `is_system = false`)
	}
	appendInt64Conditions(&conditions, &args, "id", filter.IDs)
	appendStringConditions(&conditions, &args, "slug", filter.Slugs)
	if filter.Search != "" {
		args = append(args, "%"+filter.Search+"%")
		conditions = append(conditions, fmt.Sprintf(
			`(slug ILIKE $%d OR name ILIKE $%d OR description ILIKE $%d)`,
			len(args), len(args), len(args),
		))
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY is_system DESC, name, id`
	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		query += fmt.Sprintf(` LIMIT $%d`, len(args))
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		query += fmt.Sprintf(` OFFSET $%d`, len(args))
	}

	rows, err := s.executor(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list RBAC roles: %w", err)
	}
	defer rows.Close()
	roles := make([]rbac.Role, 0)
	for rows.Next() {
		role, scanErr := scanRole(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan RBAC role: %w", scanErr)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate RBAC roles: %w", err)
	}

	return roles, nil
}

func (s *rbacStore) GetRole(ctx context.Context, roleID int64) (rbac.Role, error) {
	role, err := scanRole(s.executor(ctx).QueryRowContext(
		ctx,
		`SELECT `+roleColumns+` FROM auth_roles WHERE id = $1`,
		roleID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return rbac.Role{}, rbac.ErrRoleNotFound
	}
	if err != nil {
		return rbac.Role{}, fmt.Errorf("get RBAC role: %w", err)
	}

	return role, nil
}

func (s *rbacStore) CreateRole(
	ctx context.Context,
	role rbac.Role,
	keys []rbac.PermissionKey,
) (rbac.Role, error) {
	tx, owned, err := (&Store{db: s.db}).beginWrite(ctx)
	if err != nil {
		return rbac.Role{}, fmt.Errorf("begin create RBAC role: %w", err)
	}
	defer rollbackWrite(tx, owned)
	role.PublicID = uuid.NewString()
	role, err = scanRole(tx.QueryRowContext(ctx, `
INSERT INTO auth_roles (public_id, slug, name, description, is_system)
VALUES ($1, $2, $3, $4, $5)
RETURNING `+roleColumns,
		role.PublicID,
		role.Slug,
		role.Name,
		role.Description,
		role.System,
	))
	if err != nil {
		return rbac.Role{}, fmt.Errorf("create RBAC role: %w", err)
	}
	if err := replaceRolePermissionsTx(ctx, tx, role.ID, keys); err != nil {
		return rbac.Role{}, err
	}
	if err := s.finishWrite(tx, owned); err != nil {
		return rbac.Role{}, fmt.Errorf("commit create RBAC role: %w", err)
	}

	s.invalidateAfterCommit(ctx)
	return role, nil
}

func (s *rbacStore) UpdateRole(
	ctx context.Context,
	role rbac.Role,
	keys *[]rbac.PermissionKey,
) (rbac.Role, error) {
	tx, owned, err := (&Store{db: s.db}).beginWrite(ctx)
	if err != nil {
		return rbac.Role{}, fmt.Errorf("begin update RBAC role: %w", err)
	}
	defer rollbackWrite(tx, owned)
	current, err := scanRole(tx.QueryRowContext(
		ctx,
		`SELECT `+roleColumns+` FROM auth_roles WHERE id = $1 FOR UPDATE`,
		role.ID,
	))
	if errors.Is(err, sql.ErrNoRows) {
		return rbac.Role{}, rbac.ErrRoleNotFound
	}
	if err != nil {
		return rbac.Role{}, fmt.Errorf("lock RBAC role: %w", err)
	}
	if current.System && !role.System {
		return rbac.Role{}, rbac.ErrSystemRoleProtected
	}
	role, err = scanRole(tx.QueryRowContext(ctx, `
UPDATE auth_roles
SET slug = $2, name = $3, description = $4, is_system = $5, updated_at = now()
WHERE id = $1
RETURNING `+roleColumns,
		role.ID,
		role.Slug,
		role.Name,
		role.Description,
		role.System,
	))
	if err != nil {
		return rbac.Role{}, fmt.Errorf("update RBAC role: %w", err)
	}
	if keys != nil {
		if err := replaceRolePermissionsTx(ctx, tx, role.ID, *keys); err != nil {
			return rbac.Role{}, err
		}
	}
	if err := s.finishWrite(tx, owned); err != nil {
		return rbac.Role{}, fmt.Errorf("commit update RBAC role: %w", err)
	}

	s.invalidateAfterCommit(ctx)
	return role, nil
}

func (s *rbacStore) DeleteRole(ctx context.Context, roleID int64) error {
	tx, owned, err := (&Store{db: s.db}).beginWrite(ctx)
	if err != nil {
		return fmt.Errorf("begin delete RBAC role: %w", err)
	}
	defer rollbackWrite(tx, owned)
	var system bool
	if err := tx.QueryRowContext(
		ctx,
		`SELECT is_system FROM auth_roles WHERE id = $1 FOR UPDATE`,
		roleID,
	).Scan(&system); errors.Is(err, sql.ErrNoRows) {
		return rbac.ErrRoleNotFound
	} else if err != nil {
		return fmt.Errorf("lock RBAC role: %w", err)
	}
	if system {
		return rbac.ErrSystemRoleProtected
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_roles WHERE id = $1`, roleID); err != nil {
		return fmt.Errorf("delete RBAC role: %w", err)
	}
	if err := s.finishWrite(tx, owned); err != nil {
		return fmt.Errorf("commit delete RBAC role: %w", err)
	}

	s.invalidateAfterCommit(ctx)
	return nil
}

func (s *rbacStore) ListPermissions(
	ctx context.Context,
	filter rbac.PermissionFilter,
) ([]rbac.Permission, error) {
	query := `SELECT ` + permissionColumns + ` FROM auth_permissions`
	conditions := make([]string, 0, 4)
	args := make([]any, 0, len(filter.IDs)+len(filter.Keys)+2)
	appendInt64Conditions(&conditions, &args, "id", filter.IDs)
	if len(filter.Keys) > 0 {
		values := make([]string, len(filter.Keys))
		for index, key := range filter.Keys {
			values[index] = string(key)
		}
		appendStringConditions(&conditions, &args, "permission_key", values)
	}
	if filter.Domain != "" {
		args = append(args, filter.Domain)
		conditions = append(conditions, fmt.Sprintf(`split_part(permission_key, ':', 1) = $%d`, len(args)))
	}
	if filter.Action != "" {
		args = append(args, filter.Action)
		conditions = append(conditions, fmt.Sprintf(`split_part(permission_key, ':', 2) = $%d`, len(args)))
	}
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY permission_key, id`
	rows, err := s.executor(ctx).QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list RBAC permissions: %w", err)
	}
	defer rows.Close()
	permissions := make([]rbac.Permission, 0)
	for rows.Next() {
		permission, scanErr := scanPermission(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan RBAC permission: %w", scanErr)
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate RBAC permissions: %w", err)
	}

	return permissions, nil
}

func (s *rbacStore) ListRolePermissions(ctx context.Context, roleID int64) ([]rbac.Permission, error) {
	rows, err := s.executor(ctx).QueryContext(ctx, rolePermissionListQuery, roleID)
	if err != nil {
		return nil, fmt.Errorf("list role permissions: %w", err)
	}
	defer rows.Close()
	permissions := make([]rbac.Permission, 0)
	for rows.Next() {
		permission, scanErr := scanPermission(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan role permission: %w", scanErr)
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate role permissions: %w", err)
	}
	if len(permissions) == 0 {
		var exists bool
		if err := s.executor(ctx).QueryRowContext(
			ctx,
			`SELECT EXISTS (SELECT 1 FROM auth_roles WHERE id = $1)`,
			roleID,
		).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check RBAC role: %w", err)
		}
		if !exists {
			return nil, rbac.ErrRoleNotFound
		}
	}

	return permissions, nil
}

func (s *rbacStore) ReplaceRolePermissions(
	ctx context.Context,
	roleID int64,
	keys []rbac.PermissionKey,
) error {
	tx, owned, err := (&Store{db: s.db}).beginWrite(ctx)
	if err != nil {
		return fmt.Errorf("begin replace RBAC permissions: %w", err)
	}
	defer rollbackWrite(tx, owned)
	if err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM auth_roles WHERE id = $1 FOR UPDATE`,
		roleID,
	).Scan(&roleID); errors.Is(err, sql.ErrNoRows) {
		return rbac.ErrRoleNotFound
	} else if err != nil {
		return fmt.Errorf("lock RBAC role: %w", err)
	}
	if err := replaceRolePermissionsTx(ctx, tx, roleID, keys); err != nil {
		return err
	}
	if err := s.finishWrite(tx, owned); err != nil {
		return fmt.Errorf("commit replace RBAC permissions: %w", err)
	}

	s.invalidateAfterCommit(ctx)
	return nil
}

func replaceRolePermissionsTx(
	ctx context.Context,
	tx *sql.Tx,
	roleID int64,
	keys []rbac.PermissionKey,
) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_role_permissions WHERE role_id = $1`, roleID); err != nil {
		return fmt.Errorf("clear RBAC role permissions: %w", err)
	}
	for _, key := range keys {
		result, err := tx.ExecContext(ctx, `
INSERT INTO auth_role_permissions (role_id, permission_id)
SELECT $1, id FROM auth_permissions WHERE permission_key = $2`, roleID, key)
		if err != nil {
			return fmt.Errorf("assign RBAC permission: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read RBAC permission assignment: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("%w: %q", rbac.ErrPermissionNotFound, key)
		}
	}

	return nil
}

func (s *rbacStore) ReplaceSubjectRoles(
	ctx context.Context,
	subjectID goauth.SubjectID,
	roleIDs []int64,
) error {
	tx, owned, err := (&Store{db: s.db}).beginWrite(ctx)
	if err != nil {
		return fmt.Errorf("begin replace subject roles: %w", err)
	}
	defer rollbackWrite(tx, owned)
	var locked goauth.SubjectID
	if err := tx.QueryRowContext(
		ctx,
		`SELECT id FROM auth_subjects WHERE id = $1 FOR UPDATE`,
		subjectID,
	).Scan(&locked); errors.Is(err, sql.ErrNoRows) {
		return goauth.ErrAccountNotFound
	} else if err != nil {
		return fmt.Errorf("lock RBAC subject: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_subject_roles WHERE subject_id = $1`, subjectID); err != nil {
		return fmt.Errorf("clear subject roles: %w", err)
	}
	for _, roleID := range roleIDs {
		result, err := tx.ExecContext(ctx, `
INSERT INTO auth_subject_roles (subject_id, role_id)
SELECT $1, id FROM auth_roles WHERE id = $2`, subjectID, roleID)
		if err != nil {
			return fmt.Errorf("assign subject role: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("read subject role assignment: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("%w: %d", rbac.ErrRoleNotFound, roleID)
		}
	}
	if err := s.finishWrite(tx, owned); err != nil {
		return fmt.Errorf("commit replace subject roles: %w", err)
	}

	s.invalidateAfterCommit(ctx)
	return nil
}

func (s *rbacStore) ListSubjectRoles(
	ctx context.Context,
	subjectID goauth.SubjectID,
) ([]rbac.Role, error) {
	rows, err := s.executor(ctx).QueryContext(ctx, subjectRoleListQuery, subjectID)
	if err != nil {
		return nil, fmt.Errorf("list subject roles: %w", err)
	}
	defer rows.Close()
	roles := make([]rbac.Role, 0)
	for rows.Next() {
		role, scanErr := scanRole(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan subject role: %w", scanErr)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate subject roles: %w", err)
	}

	return roles, nil
}

func (s *rbacStore) Snapshot(ctx context.Context) (rbac.Snapshot, error) {
	tx, err := (&Store{db: s.db}).notificationTx(ctx)
	if err != nil {
		return rbac.Snapshot{}, fmt.Errorf("begin RBAC snapshot: %w", err)
	}
	if tx != nil {
		return rbac.Snapshot{}, rbac.ErrSnapshotTransactionUnsupported
	}
	tx, err = s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return rbac.Snapshot{}, fmt.Errorf("begin RBAC snapshot: %w", err)
	}
	defer rollbackWrite(tx, true)
	var snapshot rbac.Snapshot
	snapshot.Roles, err = snapshotRoles(ctx, tx)
	if err != nil {
		return rbac.Snapshot{}, err
	}
	snapshot.Permissions, err = snapshotPermissions(ctx, tx)
	if err != nil {
		return rbac.Snapshot{}, err
	}
	snapshot.RolePermissions, err = snapshotRolePermissions(ctx, tx)
	if err != nil {
		return rbac.Snapshot{}, err
	}
	snapshot.SubjectRoles, err = snapshotSubjectRoles(ctx, tx)
	if err != nil {
		return rbac.Snapshot{}, err
	}
	if err := s.finishWrite(tx, true); err != nil {
		return rbac.Snapshot{}, fmt.Errorf("commit RBAC snapshot: %w", err)
	}

	return snapshot, nil
}

func snapshotRoles(ctx context.Context, tx *sql.Tx) ([]rbac.Role, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, public_id::text, slug, name, description, is_system, created_at, updated_at
FROM auth_roles ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list snapshot roles: %w", err)
	}
	defer rows.Close()
	roles := make([]rbac.Role, 0)
	for rows.Next() {
		role, scanErr := scanRole(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan snapshot role: %w", scanErr)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshot roles: %w", err)
	}

	return roles, nil
}

func snapshotPermissions(ctx context.Context, tx *sql.Tx) ([]rbac.Permission, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT id, public_id::text, permission_key, description, created_at, updated_at
FROM auth_permissions ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list snapshot permissions: %w", err)
	}
	defer rows.Close()
	permissions := make([]rbac.Permission, 0)
	for rows.Next() {
		permission, scanErr := scanPermission(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan snapshot permission: %w", scanErr)
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshot permissions: %w", err)
	}

	return permissions, nil
}

func snapshotRolePermissions(ctx context.Context, tx *sql.Tx) ([]rbac.RolePermission, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT role_id, permission_id FROM auth_role_permissions ORDER BY role_id, permission_id`)
	if err != nil {
		return nil, fmt.Errorf("list snapshot role permissions: %w", err)
	}
	defer rows.Close()
	assignments := make([]rbac.RolePermission, 0)
	for rows.Next() {
		var assignment rbac.RolePermission
		if scanErr := rows.Scan(&assignment.RoleID, &assignment.PermissionID); scanErr != nil {
			return nil, fmt.Errorf("scan snapshot role permission: %w", scanErr)
		}
		assignments = append(assignments, assignment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshot role permissions: %w", err)
	}

	return assignments, nil
}

func snapshotSubjectRoles(ctx context.Context, tx *sql.Tx) ([]rbac.SubjectRole, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT subject_id, role_id FROM auth_subject_roles ORDER BY subject_id, role_id`)
	if err != nil {
		return nil, fmt.Errorf("list snapshot subject roles: %w", err)
	}
	defer rows.Close()
	assignments := make([]rbac.SubjectRole, 0)
	for rows.Next() {
		var assignment rbac.SubjectRole
		if scanErr := rows.Scan(&assignment.SubjectID, &assignment.RoleID); scanErr != nil {
			return nil, fmt.Errorf("scan snapshot subject role: %w", scanErr)
		}
		assignments = append(assignments, assignment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshot subject roles: %w", err)
	}

	return assignments, nil
}

func appendInt64Conditions(conditions *[]string, args *[]any, column string, values []int64) {
	if len(values) == 0 {
		return
	}
	placeholders := make([]string, len(values))
	for index, value := range values {
		*args = append(*args, value)
		placeholders[index] = fmt.Sprintf("$%d", len(*args))
	}
	*conditions = append(*conditions, column+` IN (`+strings.Join(placeholders, `, `)+`)`)
}

func appendStringConditions(conditions *[]string, args *[]any, column string, values []string) {
	if len(values) == 0 {
		return
	}
	placeholders := make([]string, len(values))
	for index, value := range values {
		*args = append(*args, value)
		placeholders[index] = fmt.Sprintf("$%d", len(*args))
	}
	*conditions = append(*conditions, column+` IN (`+strings.Join(placeholders, `, `)+`)`)
}
