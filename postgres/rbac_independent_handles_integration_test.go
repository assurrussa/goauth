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

func TestPostgresRBACIndependentHandlesUseAuthoritativePermissions(t *testing.T) {
	const roleName = "Operator"
	writerDB := integrationDB(t)
	readerDB := integrationDB(t)
	require.NotSame(t, writerDB, readerDB)
	resetSchema(t, writerDB)
	require.NoError(t, postgres.Migrate(t.Context(), writerDB))

	subject := goauth.NewSubjectID()
	_, err := writerDB.ExecContext(t.Context(), `
INSERT INTO auth_subjects (id, status, created_at, updated_at)
VALUES ($1, 'active', now(), now())`, subject.String())
	require.NoError(t, err)

	writer, err := postgres.NewRBAC(writerDB, nil)
	require.NoError(t, err)
	reader, err := postgres.NewRBAC(readerDB, nil)
	require.NoError(t, err)
	store, err := postgres.NewStore(writerDB)
	require.NoError(t, err)
	key := rbac.MustPermissionKey("users", "read")
	_, err = writer.UpsertPermission(t.Context(), rbac.Permission{Key: key})
	require.NoError(t, err)
	role, err := writer.CreateRole(t.Context(), rbac.Role{Slug: "operator", Name: roleName}, []rbac.PermissionKey{key})
	require.NoError(t, err)

	assertIndependentHandlePermission(t, t.Context(), reader, subject, key, false)
	require.NoError(t, writer.AssignRole(t.Context(), subject, role.Slug))
	assertIndependentHandlePermission(t, t.Context(), reader, subject, key, true)

	authorizationCtx := t.Context()
	rejected := errors.New("host rejected RBAC revocation")
	err = store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		if err := writer.ReplaceRolePermissions(ctx, role.ID, nil); err != nil {
			return err
		}
		assertIndependentHandlePermission(t, ctx, writer, subject, key, false)
		// The independent reader sees only the previously committed grant.
		assertIndependentHandlePermission(t, authorizationCtx, reader, subject, key, true)
		return rejected
	})
	require.ErrorIs(t, err, rejected)
	assertIndependentHandlePermission(t, t.Context(), reader, subject, key, true)

	require.NoError(t, writer.ReplaceRolePermissions(t.Context(), role.ID, nil))
	assertIndependentHandlePermission(t, t.Context(), reader, subject, key, false)
	require.NoError(t, writer.ReplaceRolePermissions(t.Context(), role.ID, []rbac.PermissionKey{key}))
	assertIndependentHandlePermission(t, t.Context(), reader, subject, key, true)

	// A closed reader handle must deny even while the committed grant remains.
	require.NoError(t, readerDB.Close())
	allowed, err := reader.Check(t.Context(), subject, key)
	require.Error(t, err)
	require.False(t, allowed)
	require.False(t, reader.Can(t.Context(), subject, key))
	require.ErrorIs(t, reader.Require(t.Context(), subject, key), rbac.ErrPermissionDenied)
	assertIndependentHandlePermission(t, t.Context(), writer, subject, key, true)
}

func assertIndependentHandlePermission(
	t *testing.T,
	ctx context.Context,
	service *rbac.Service,
	subject goauth.SubjectID,
	key rbac.PermissionKey,
	wantAllowed bool,
) {
	t.Helper()
	allowed, err := service.Check(ctx, subject, key)
	require.NoError(t, err)
	require.Equal(t, wantAllowed, allowed)
	require.Equal(t, wantAllowed, service.Can(ctx, subject, key))
	if wantAllowed {
		require.NoError(t, service.Require(ctx, subject, key))
	} else {
		require.ErrorIs(t, service.Require(ctx, subject, key), rbac.ErrPermissionDenied)
	}
}
