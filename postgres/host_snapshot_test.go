package postgres //nolint:testpackage // Reuse recording driver to verify transaction options.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestHostSnapshotProjection(t *testing.T) {
	for _, tc := range []struct {
		name            string
		project, commit error
	}{
		{name: "success"},
		{name: "projection failure", project: errors.New("projection")},
		{name: "commit failure", commit: io.ErrUnexpectedEOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var options driver.TxOptions
			queries := 0
			name := "host-snapshot-" + uuid.NewString()
			sql.Register(name, snapshotCommitDriver{err: tc.commit, options: &options, queries: &queries})
			db, err := sql.Open(name, "")
			require.NoError(t, err)
			defer db.Close()
			r := &Runtime{db: db, store: &Store{db: db}}
			called := false
			result, err := r.AuthorizationSnapshot(t.Context(), func(ctx context.Context, q SQLExecutor) error {
				called = true
				_, owns := q.(*sql.Tx)
				require.False(t, owns)
				rows, e := q.QueryContext(ctx, "SELECT host_memberships")
				require.NoError(t, e)
				defer rows.Close()
				require.NoError(t, rows.Err())
				return tc.project
			})
			require.True(t, called)
			require.Equal(t, 5, queries)
			require.True(t, options.ReadOnly)
			require.Equal(t, driver.IsolationLevel(sql.LevelRepeatableRead), options.Isolation)
			if tc.project != nil || tc.commit != nil {
				require.Error(t, err)
				require.Empty(t, result)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
