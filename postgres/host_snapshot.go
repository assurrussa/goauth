package postgres

import (
	"context"
	"errors"

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
