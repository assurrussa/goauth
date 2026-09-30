//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
)

func TestRBACSnapshotRejectsManagedAuthTransaction(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	service, err := postgres.NewRBAC(db, nil)
	require.NoError(t, err)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	require.NoError(t, store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		snapshot, err := service.Snapshot(ctx)
		require.ErrorIs(t, err, rbac.ErrSnapshotTransactionUnsupported)
		require.Empty(t, snapshot)
		_, err = service.UpsertRole(ctx, rbac.Role{Slug: "operator", Name: "Operator"})
		return err
	}))
	snapshot, err := service.Snapshot(t.Context())
	require.NoError(t, err)
	require.Len(t, snapshot.Roles, 1, "rejecting the snapshot must leave the outer write usable")
}

func TestRBACSnapshotKeepsRepeatableReadDuringConcurrentCommit(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	service, err := postgres.NewRBAC(db, nil)
	require.NoError(t, err)
	subject := goauth.NewSubjectID()
	_, err = db.ExecContext(t.Context(), `INSERT INTO auth_subjects (id, status, created_at, updated_at) VALUES ($1, 'active', now(), now())`, subject.String())
	require.NoError(t, err)
	writer, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback() }()
	// Pause query 2, after query 1 has established the snapshot's MVCC view.
	_, err = writer.ExecContext(t.Context(), `LOCK TABLE auth_permissions IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	type outcome struct {
		snapshot rbac.Snapshot
		err      error
	}
	result := make(chan outcome, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	go func() { snapshot, err := service.Snapshot(ctx); result <- outcome{snapshot, err} }()
	require.Eventually(t, func() bool {
		var blocked bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%FROM auth_permissions ORDER BY id%')`).Scan(&blocked)
		return err == nil && blocked
	}, 5*time.Second, 10*time.Millisecond)
	var roleID int64
	err = writer.QueryRowContext(ctx, `INSERT INTO auth_roles (public_id, slug, name) VALUES ($1, 'concurrent', 'Concurrent') RETURNING id`, goauth.NewSubjectID().String()).Scan(&roleID)
	require.NoError(t, err)
	_, err = writer.ExecContext(ctx, `INSERT INTO auth_subject_roles (subject_id, role_id) VALUES ($1, $2)`, subject.String(), roleID)
	require.NoError(t, err)
	require.NoError(t, writer.Commit())
	completed := <-result
	require.NoError(t, completed.err)
	require.Empty(t, completed.snapshot.Roles)
	require.Empty(t, completed.snapshot.SubjectRoles, "a later query must not see the newer committed role assignment")
	current, err := service.Snapshot(t.Context())
	require.NoError(t, err)
	require.Len(t, current.Roles, 1)
	require.Len(t, current.SubjectRoles, 1)
}
