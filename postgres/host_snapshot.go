package postgres

import (
	"context"
	"errors"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/rbac"
)

// AuthorizationSnapshot reads RBAC and an optional host projection in one read-only
// repeatable-read transaction. project must use only the supplied executor, close
// all rows before returning, and not retain the executor. Its captured output is
// provisional and must be discarded on ANY error, including commit failure.
// Managed auth transactions are rejected; this cannot read uncommitted host writes.
// This method neither enables a cache nor changes authorization policy.
func (r *Runtime) AuthorizationSnapshot(
	ctx context.Context, project func(context.Context, SQLExecutor) error,
) (rbac.Snapshot, error) {
	if r == nil || r.store == nil {
		return rbac.Snapshot{}, errors.New("PostgreSQL Runtime is not initialized")
	}
	return (&rbacStore{db: r.db}).snapshotWithProjection(ctx, project)
}

// ScopedAuthorizationSnapshot reads the host's selected subject IDs and their
// subject assignments in one read-only repeatable-read transaction. selectSubjects
// must use the supplied executor to read host membership; nil callbacks are rejected.
// An empty selection returns no subject assignments, never all assignments.
// The full role/permission catalog is retained for role-management UI, including
// roles not assigned to selected subjects. The catalog is not a grant to a subject.
// All provisional-output and lifetime rules of AuthorizationSnapshot
// apply. Filtering happens in SQL, not after loading unrelated subject assignments.
func (r *Runtime) ScopedAuthorizationSnapshot(
	ctx context.Context, selectSubjects func(context.Context, SQLExecutor) ([]goauth.SubjectID, error),
) (rbac.Snapshot, error) {
	if r == nil || r.store == nil {
		return rbac.Snapshot{}, errors.New("PostgreSQL Runtime is not initialized")
	}
	if selectSubjects == nil {
		return rbac.Snapshot{}, errors.New("authorization subject selector is required")
	}
	return (&rbacStore{db: r.db}).snapshotWithSubjects(ctx, nil, selectSubjects)
}
