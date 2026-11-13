//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
)

func TestHostScopedSnapshotSelectionAndConsistency(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	runtime := identityPostgresRuntime(t, db)
	admin, customer := goauth.NewSubjectID(), goauth.NewSubjectID()
	_, err := db.ExecContext(t.Context(), `INSERT INTO auth_subjects(id,status,created_at,updated_at)
 VALUES($1,'active',now(),now()),($2,'active',now(),now())`, admin.String(), customer.String())
	require.NoError(t, err)
	service, err := postgres.NewRBAC(db, nil)
	require.NoError(t, err)
	role, err := service.UpsertRole(t.Context(), rbac.Role{Slug: "scoped", Name: "Scoped"})
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `INSERT INTO auth_subject_roles(subject_id,role_id) VALUES($1,$3),($2,$3)`,
		admin.String(), customer.String(), role.ID)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `CREATE TABLE selected_admin (subject_id uuid PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `INSERT INTO selected_admin VALUES($1)`, admin.String())
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `DROP TABLE selected_admin`)
		require.NoError(t, err)
	})
	read := func(ctx context.Context, q postgres.SQLExecutor) ([]goauth.SubjectID, error) {
		var id goauth.SubjectID
		err := q.QueryRowContext(ctx, `SELECT subject_id FROM selected_admin`).Scan(&id)
		return []goauth.SubjectID{id}, err
	}
	snapshot, err := runtime.ScopedAuthorizationSnapshot(t.Context(), func(
		ctx context.Context, q postgres.SQLExecutor,
	) ([]goauth.SubjectID, error) {
		ids, err := read(ctx, q)
		if err != nil {
			return nil, err
		}
		// The selector establishes MVCC before another transaction changes membership and assignments.
		require.NoError(t, runtime.InOwnedAuthTransaction(ctx, func(write context.Context) error {
			exec, err := runtime.SQLExecutor(write)
			if err != nil {
				return err
			}
			if _, err = exec.ExecContext(write, `UPDATE selected_admin SET subject_id=$1`, customer.String()); err != nil {
				return err
			}
			_, err = exec.ExecContext(write, `DELETE FROM auth_subject_roles WHERE subject_id=$1`, admin.String())
			return err
		}))
		return ids, nil
	})
	require.NoError(t, err)
	require.Len(t, snapshot.SubjectRoles, 1)
	require.Equal(t, admin, snapshot.SubjectRoles[0].SubjectID)
	snapshot, err = runtime.ScopedAuthorizationSnapshot(t.Context(), read)
	require.NoError(t, err)
	require.Len(t, snapshot.SubjectRoles, 1)
	require.Equal(t, customer, snapshot.SubjectRoles[0].SubjectID)
	snapshot, err = runtime.ScopedAuthorizationSnapshot(t.Context(), func(
		context.Context, postgres.SQLExecutor,
	) ([]goauth.SubjectID, error) {
		return nil, nil
	})
	require.NoError(t, err)
	require.Empty(t, snapshot.SubjectRoles)
	require.Len(t, snapshot.Roles, 1)
	_, err = runtime.ScopedAuthorizationSnapshot(t.Context(), nil)
	require.Error(t, err)
	sentinel := errors.New("selector failed")
	snapshot, err = runtime.ScopedAuthorizationSnapshot(t.Context(), func(
		context.Context, postgres.SQLExecutor,
	) ([]goauth.SubjectID, error) {
		return nil, sentinel
	})
	require.ErrorIs(t, err, sentinel)
	require.Empty(t, snapshot)
}
