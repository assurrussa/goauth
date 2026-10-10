package postgres

import (
	"context"
	"database/sql"
	"time"
)

// Keep canonical replay evidence until the same session/family termination plus
// retention used by Cleanup. A subject lock always precedes dependent locks.
// Actual token, family and session deletions are bounded independently; a large
// subject or family never turns a parent limit into uncounted cascade work.
func cleanupRefreshStateBatch(ctx context.Context, db *sql.DB, before time.Time, limit int) (CleanupResult, error) {
	result := CleanupResult{}
	err := cleanupBatchTransaction(ctx, db, func(tx *sql.Tx) error {
		subjects, err := cleanupBatchIDs(ctx, tx, `SELECT sub.id FROM auth_subjects sub
WHERE EXISTS (
 SELECT 1 FROM auth_sessions sess WHERE sess.subject_id=sub.id AND (
  sess.expires_at<$1 OR sess.revoked_at<$1 OR EXISTS (
   SELECT 1 FROM auth_refresh_families f WHERE f.session_id=sess.id AND f.revoked_at<$1)))
ORDER BY sub.id LIMIT $2 FOR UPDATE OF sub SKIP LOCKED`, before, min(limit, 32))
		if err != nil || len(subjects) == 0 {
			return err
		}
		families, err := cleanupBatchIDs(ctx, tx, `SELECT f.id FROM auth_refresh_families f
JOIN auth_sessions sess ON sess.id=f.session_id
WHERE f.subject_id=ANY($2::uuid[]) AND sess.subject_id=f.subject_id
AND (sess.expires_at<$1 OR sess.revoked_at<$1 OR f.revoked_at<$1)
ORDER BY f.created_at,f.id LIMIT $3 FOR UPDATE OF f SKIP LOCKED`, before, subjects, min(limit, 32))
		if err != nil {
			return err
		}
		remaining := limit
		for _, family := range families {
			if remaining > 0 {
				count, err := cleanupBatchRows(ctx, tx, canonicalRefreshPrefixCleanupSQL, family, remaining)
				if err != nil {
					return err
				}
				result.RefreshTokens += count
				remaining -= int(count)
			}
			// The prior family lock fences new FK children. This statement uses a
			// fresh READ COMMITTED snapshot, so an empty parent cannot cascade.
			count, err := cleanupBatchRows(ctx, tx, `DELETE FROM auth_refresh_families f
WHERE f.id=$1 AND NOT EXISTS(SELECT 1 FROM auth_refresh_tokens t WHERE t.family_id=f.id)`, family)
			if err != nil {
				return err
			}
			result.RefreshFamilies += count
		}
		// Lock empty sessions first, then recheck in a fresh statement. Besides
		// supported subject-serialized writers, this fences concurrent FK inserts.
		sessions, err := cleanupBatchIDs(ctx, tx, `SELECT sess.id FROM auth_sessions sess
WHERE sess.subject_id=ANY($2::uuid[]) AND (sess.expires_at<$1 OR sess.revoked_at<$1)
AND NOT EXISTS(SELECT 1 FROM auth_refresh_families f WHERE f.session_id=sess.id)
ORDER BY sess.expires_at,sess.id LIMIT $3 FOR UPDATE OF sess SKIP LOCKED`, before, subjects, limit)
		if err != nil || len(sessions) == 0 {
			return err
		}
		result.Sessions, err = cleanupBatchRows(ctx, tx, `DELETE FROM auth_sessions sess
WHERE sess.id=ANY($2::uuid[]) AND (sess.expires_at<$1 OR sess.revoked_at<$1)
AND NOT EXISTS(SELECT 1 FROM auth_refresh_families f WHERE f.session_id=sess.id)`, before, sessions)
		return err
	})
	if err != nil {
		return CleanupResult{}, err
	}
	return result, nil
}

func cleanupBatchIDs(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return ids, nil
}

// Begin at an unreferenced predecessor and delete only a bounded chain prefix.
// A merge point or cross-family successor is retained; cycles have no root and
// are retained. Never sever an FK or delete a still-referenced successor merely
// to make progress on malformed/custom history. Supported writers serialize on
// the subject; the family lock also prevents new token inserts through its FK.
const canonicalRefreshPrefixCleanupSQL = `WITH RECURSIVE chain(selector,next_selector,depth) AS (
 (SELECT t.selector,t.replaced_by_selector,1 FROM auth_refresh_tokens t
 WHERE t.family_id=$1 AND NOT EXISTS(SELECT 1 FROM auth_refresh_tokens p WHERE p.replaced_by_selector=t.selector)
 ORDER BY t.created_at,t.selector LIMIT 1)
 UNION ALL
 SELECT t.selector,t.replaced_by_selector,c.depth+1 FROM chain c JOIN auth_refresh_tokens t ON t.selector=c.next_selector
 WHERE t.family_id=$1 AND c.depth<$2
 AND NOT EXISTS(SELECT 1 FROM auth_refresh_tokens p WHERE p.replaced_by_selector=t.selector AND p.selector<>c.selector))
 DELETE FROM auth_refresh_tokens WHERE selector IN (SELECT selector FROM chain)`
