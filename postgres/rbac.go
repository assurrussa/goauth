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

func NewRBAC(db *sql.DB, cache rbac.Cache) (*rbac.Service, error) {
	if db == nil {
		return nil, errors.New("PostgreSQL database is required")
	}

	return rbac.New(&rbacStore{db: db}, cache)
}

// RBAC assembles the optional hierarchy-free RBAC service on the Runtime's
// canonical PostgreSQL connection.
func (r *Runtime) RBAC(cache rbac.Cache) (*rbac.Service, error) {
	if r == nil || r.db == nil {
		return nil, errors.New("PostgreSQL Runtime is not initialized")
	}

	return NewRBAC(r.db, cache)
}

type rbacStore struct {
	db *sql.DB
}

func (s *rbacStore) HasPermission(
	ctx context.Context,
	subjectID goauth.SubjectID,
	key rbac.PermissionKey,
) (bool, error) {
	var allowed bool
	if err := s.db.QueryRowContext(ctx, `
SELECT EXISTS (
    SELECT 1
    FROM auth_subject_roles sr
    JOIN auth_role_permissions rp ON rp.role_id = sr.role_id
    JOIN auth_permissions p ON p.id = rp.permission_id
    WHERE sr.subject_id = $1 AND p.permission_key = $2
)`, subjectID, key).Scan(&allowed); err != nil {
		return false, fmt.Errorf("check RBAC permission: %w", err)
	}

	return allowed, nil
}

func (s *rbacStore) UpsertRole(ctx context.Context, role rbac.Role) (rbac.Role, error) {
	if role.PublicID == "" {
		role.PublicID = uuid.NewString()
	}
	err := s.db.QueryRowContext(ctx, `
INSERT INTO auth_roles (public_id, slug, name, description, is_system)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (slug) DO UPDATE
	SET name = EXCLUDED.name,
	    description = EXCLUDED.description,
	    is_system = auth_roles.is_system OR EXCLUDED.is_system,
	    updated_at = now()
RETURNING id, public_id::text, slug, name, description, is_system, created_at, updated_at`,
		role.PublicID,
		role.Slug,
		role.Name,
		role.Description,
		role.System,
	).Scan(
		&role.ID,
		&role.PublicID,
		&role.Slug,
		&role.Name,
		&role.Description,
		&role.System,
		&role.CreatedAt,
		&role.UpdatedAt,
	)
	if err != nil {
		return rbac.Role{}, fmt.Errorf("upsert RBAC role: %w", err)
	}

	return role, nil
}

func (s *rbacStore) UpsertPermission(
	ctx context.Context,
	permission rbac.Permission,
) (rbac.Permission, error) {
	if permission.PublicID == "" {
		permission.PublicID = uuid.NewString()
	}
	err := s.db.QueryRowContext(ctx, `
INSERT INTO auth_permissions (public_id, permission_key, description)
VALUES ($1, $2, $3)
ON CONFLICT (permission_key) DO UPDATE
SET description = EXCLUDED.description, updated_at = now()
RETURNING id, public_id::text, permission_key, description, created_at, updated_at`,
		permission.PublicID,
		permission.Key,
		permission.Description,
	).Scan(
		&permission.ID,
		&permission.PublicID,
		&permission.Key,
		&permission.Description,
		&permission.CreatedAt,
		&permission.UpdatedAt,
	)
	if err != nil {
		return rbac.Permission{}, fmt.Errorf("upsert RBAC permission: %w", err)
	}

	return permission, nil
}

func (s *rbacStore) AssignRole(ctx context.Context, subjectID goauth.SubjectID, roleSlug string) error {
	result, err := s.db.ExecContext(ctx, `
INSERT INTO auth_subject_roles (subject_id, role_id)
SELECT $1, id FROM auth_roles WHERE slug = $2
ON CONFLICT (subject_id, role_id) DO NOTHING`, subjectID, strings.TrimSpace(roleSlug))
	if err != nil {
		return fmt.Errorf("assign RBAC role: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read RBAC role assignment count: %w", err)
	}
	if rows == 0 {
		var exists bool
		if err := s.db.QueryRowContext(
			ctx,
			`SELECT EXISTS (SELECT 1 FROM auth_roles WHERE slug = $1)`,
			roleSlug,
		).Scan(&exists); err != nil {
			return fmt.Errorf("check RBAC role: %w", err)
		}
		if !exists {
			return errors.New("RBAC role not found")
		}
	}

	return nil
}

func (s *rbacStore) SetRolePermissions(
	ctx context.Context,
	roleSlug string,
	keys []rbac.PermissionKey,
) error {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return fmt.Errorf("begin RBAC permission transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var roleID int64
	if err := tx.QueryRowContext(ctx, `SELECT id FROM auth_roles WHERE slug = $1 FOR UPDATE`, roleSlug).Scan(&roleID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rbac.ErrRoleNotFound
		}
		return fmt.Errorf("lock RBAC role: %w", err)
	}
	if err := replaceRolePermissionsTx(ctx, tx, roleID, keys); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit RBAC permission transaction: %w", err)
	}

	return nil
}

var _ rbac.Store = (*rbacStore)(nil)
