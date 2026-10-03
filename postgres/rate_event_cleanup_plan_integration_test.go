//go:build integration

//nolint:testpackage,tagliatelle // Execute the exact statement and decode PostgreSQL-defined JSON field names.
package postgres

import (
	"database/sql"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type cleanupPlan struct {
	NodeType    string        `json:"Node Type"`
	SubplanName string        `json:"Subplan Name"`
	IndexName   string        `json:"Index Name"`
	ActualRows  int           `json:"Actual Rows"`
	ActualLoops int           `json:"Actual Loops"`
	Plans       []cleanupPlan `json:"Plans"`
}

func walkCleanupPlan(plan cleanupPlan, visit func(cleanupPlan)) {
	visit(plan)
	for _, child := range plan.Plans {
		walkCleanupPlan(child, visit)
	}
}

func TestRateEventCleanupRepresentativeQueryPlan(t *testing.T) {
	dsn := os.Getenv("GOAUTH_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_TEST_POSTGRES_DSN is not configured")
	}
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()
	require.NoError(t, Down(t.Context(), db, ConfirmResetAuthState))
	require.NoError(t, Migrate(t.Context(), db))
	now := time.Now().UTC()
	_, err = db.ExecContext(t.Context(), `INSERT INTO auth_rate_limit_events (key_id,bucket_digest,action,occurred_at)
SELECT 'plan',decode(repeat('00',32),'hex'),'plan',$1::timestamptz - n*interval '1 minute' FROM generate_series(1,100000) n`, now)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(), `ANALYZE auth_rate_limit_events`)
	require.NoError(t, err)
	for _, limit := range []int{1, 1000} {
		tx, err := db.BeginTx(t.Context(), nil)
		require.NoError(t, err)
		var raw []byte
		err = tx.QueryRowContext(t.Context(), "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+rateEventCleanupSQL,
			now.Add(-25*time.Hour), limit).Scan(&raw)
		require.NoError(t, tx.Rollback())
		require.NoError(t, err)
		t.Logf("unforced PostgreSQL plan, backlog=100000, limit=%d: %s", limit, raw)
		var explain []struct {
			Plan cleanupPlan `json:"Plan"`
		}
		require.NoError(t, json.Unmarshal(raw, &explain))
		require.Len(t, explain, 1)
		candidates, lockRows, boundedDelete := false, false, false
		walkCleanupPlan(explain[0].Plan, func(node cleanupPlan) {
			require.NotEqual(t, "Seq Scan", node.NodeType, "representative cleanup must not enumerate the target relation")
			if node.SubplanName == "CTE candidates" {
				candidates = true
				require.Equal(t, "Limit", node.NodeType)
				require.Equal(t, limit, node.ActualRows)
				require.Len(t, node.Plans, 1)
				require.Equal(t, "auth_rate_limit_events_retention_idx", node.Plans[0].IndexName)
				require.Equal(t, limit, node.Plans[0].ActualRows)
			}
			if node.NodeType == "Tid Scan" {
				boundedDelete = true
				require.Equal(t, limit, node.ActualRows*node.ActualLoops)
			}
			if node.NodeType == "LockRows" {
				lockRows = true
				require.LessOrEqual(t, node.ActualRows*node.ActualLoops, limit)
				require.Len(t, node.Plans, 1)
				require.Equal(t, "auth_rate_limit_events_pkey", node.Plans[0].IndexName)
			}
		})
		require.True(t, candidates)
		require.True(t, lockRows)
		require.True(t, boundedDelete)
	}
}
