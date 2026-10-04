package postgres

import (
	"context"
	"database/sql"
	"time"
)

// SessionOIDCCleanupResult reports only confirmed committed row deletions.
// Each call deletes at most 1000 requests, 1000 codes, 1000 refresh tokens,
// and 32 empty refresh families. A remaining chain is continued on later calls.
type SessionOIDCCleanupResult struct {
	Requests        int64
	Codes           int64
	RefreshTokens   int64
	RefreshFamilies int64
}

// CleanupExpired removes expired strict-profile state in its own bounded
// transaction. It never touches legacy families, generic auth state or audit.
// Live-family code and refresh tombstones remain until the fixed family end.
// Ambient managed transactions are rejected; counters require confirmed commit.
func (s *SessionOIDCState) CleanupExpired(ctx context.Context) (SessionOIDCCleanupResult, error) {
	result := SessionOIDCCleanupResult{}
	err := s.InOwnedAuthTransaction(ctx, func(ctx context.Context) error {
		tx, err := s.transaction(ctx)
		if err != nil {
			return err
		}
		return cleanupSessionOIDC(ctx, tx, s.now(ctx), &result, true)
	})
	if err != nil {
		return SessionOIDCCleanupResult{}, err
	}
	return result, nil
}

const sessionOIDCCleanupBatch = 1000

// OIDC cleanup owns a separate bounded transaction. Like notification expiry,
// its confirmed work may precede an error from a later generic cleanup batch.
// No counters are returned on an uncertain commit or any batch error.
func cleanupSessionOIDCBatch(ctx context.Context, db *sql.DB, before time.Time) (SessionOIDCCleanupResult, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return SessionOIDCCleanupResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	result := SessionOIDCCleanupResult{}
	if err = cleanupSessionOIDC(ctx, tx, before, &result, false); err != nil {
		return SessionOIDCCleanupResult{}, err
	}
	if err = commitAuthTransaction(tx); err != nil {
		return SessionOIDCCleanupResult{}, err
	}
	return result, nil
}

// Cleanup follows the same code -> family -> token order as exchange and replay.
// Code rows are handled before any family locks. Families with surviving code
// tombstones are skipped, so deleting an empty family never cascades into a code
// row held by an exchange. A family lock precedes every token deletion. Actual
// deleted requests, codes and tokens are each bounded, not just their parents.
func cleanupSessionOIDC(
	ctx context.Context, tx *sql.Tx, before time.Time, result *SessionOIDCCleanupResult, boundOnly bool,
) error {
	for _, deletion := range []struct {
		statement string
		count     *int64
	}{
		{`DELETE FROM auth_oidc_authorization_requests WHERE selector IN (
 SELECT selector FROM auth_oidc_authorization_requests WHERE expires_at<=$1
 ORDER BY expires_at,selector LIMIT 1000 FOR UPDATE SKIP LOCKED)`, &result.Requests},
		{`DELETE FROM auth_oidc_authorization_codes WHERE selector IN (
 SELECT c.selector FROM auth_oidc_authorization_codes c LEFT JOIN auth_oidc_refresh_families f ON f.id=c.family_id
 WHERE c.expires_at<=$1 AND (c.family_id IS NULL OR f.expires_at<=$1)
 ORDER BY c.expires_at,c.selector LIMIT 1000 FOR UPDATE OF c SKIP LOCKED)`, &result.Codes},
	} {
		deleted, err := tx.ExecContext(ctx, deletion.statement, before)
		if err != nil {
			return err
		}
		count, err := deleted.RowsAffected()
		if err != nil {
			return err
		}
		*deletion.count = count
	}
	query := `SELECT f.id FROM auth_oidc_refresh_families f
 WHERE f.expires_at<=$1 AND NOT EXISTS(SELECT 1 FROM auth_oidc_authorization_codes c WHERE c.family_id=f.id)
 `
	if boundOnly {
		query += " AND f.session_id IS NOT NULL AND f.authorization_stamp IS NOT NULL AND f.absolute_expires_at IS NOT NULL"
	}
	query += " ORDER BY f.expires_at,f.id LIMIT 32 FOR UPDATE OF f SKIP LOCKED"
	rows, err := tx.QueryContext(ctx, query, before)
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()
	var families []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return err
		}
		families = append(families, id)
	}
	err = rows.Err()
	if closeErr := rows.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	remaining := sessionOIDCCleanupBatch
	for _, id := range families {
		if remaining == 0 {
			break
		}
		// Begin at an unreferenced predecessor, then take a bounded chain prefix.
		// Stop before a merge point, preserving self-FK safety even for legacy rows
		// produced by a custom writer. The family lock prevents supported rotations.
		deleted, err := tx.ExecContext(ctx, `WITH RECURSIVE chain(selector,next_selector,depth) AS (
 (SELECT t.selector,t.replaced_by_selector,1 FROM auth_oidc_refresh_tokens t
 WHERE t.family_id=$1 AND NOT EXISTS(SELECT 1 FROM auth_oidc_refresh_tokens p WHERE p.replaced_by_selector=t.selector)
 ORDER BY t.created_at,t.selector LIMIT 1)
 UNION ALL
 SELECT t.selector,t.replaced_by_selector,c.depth+1 FROM chain c JOIN auth_oidc_refresh_tokens t ON t.selector=c.next_selector
 WHERE t.family_id=$1 AND c.depth<$2
 AND NOT EXISTS(SELECT 1 FROM auth_oidc_refresh_tokens p WHERE p.replaced_by_selector=t.selector AND p.selector<>c.selector))
 DELETE FROM auth_oidc_refresh_tokens WHERE selector IN (SELECT selector FROM chain)`, id, remaining)
		if err != nil {
			return err
		}
		count, err := deleted.RowsAffected()
		if err != nil {
			return err
		}
		result.RefreshTokens += count
		remaining -= int(count)
		// No live dependent rows, hence zero cascade work. Rechecking both tables
		// also fences an unexpected external writer that attached a code meanwhile.
		deleted, err = tx.ExecContext(ctx, `DELETE FROM auth_oidc_refresh_families f WHERE f.id=$1
 AND NOT EXISTS(SELECT 1 FROM auth_oidc_refresh_tokens t WHERE t.family_id=f.id)
 AND NOT EXISTS(SELECT 1 FROM auth_oidc_authorization_codes c WHERE c.family_id=f.id)`, id)
		if err != nil {
			return err
		}
		count, err = deleted.RowsAffected()
		if err != nil {
			return err
		}
		result.RefreshFamilies += count
	}
	return nil
}
