package postgres

import (
	"context"
	"database/sql"
	"time"
)

// Canonical refresh history is replay evidence, including consumed and expired
// tokens. Keep the complete chain until its family or session has ended, then
// apply retention. Session expiry is fixed, so custom/sliding token lifetimes
// cannot cause either premature deletion or indefinite history retention.
//
// This phase owns its transaction and locks subjects before dependent rows, as
// rotation and revocation do. Release these locks before generic cleanup, which
// also visits unrelated subjects' recovery records. Busy subjects are left for
// the next run. Like generic Cleanup, this is not a row-count-bounded batch.
func cleanupRefreshState(ctx context.Context, db *sql.DB, before time.Time) (CleanupResult, error) {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CleanupResult{}, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `SELECT sub.id FROM auth_subjects sub
WHERE EXISTS (
 SELECT 1 FROM auth_sessions sess WHERE sess.subject_id=sub.id AND (
  sess.expires_at<$1 OR sess.revoked_at<$1 OR EXISTS (
   SELECT 1 FROM auth_refresh_families f WHERE f.session_id=sess.id AND f.revoked_at<$1)))
ORDER BY sub.id FOR UPDATE OF sub SKIP LOCKED`, before)
	if err != nil {
		return CleanupResult{}, err
	}
	defer func() { _ = rows.Close() }()
	var subjects []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return CleanupResult{}, err
		}
		subjects = append(subjects, id)
	}
	if err := rows.Err(); err != nil {
		return CleanupResult{}, err
	}
	if err := rows.Close(); err != nil {
		return CleanupResult{}, err
	}
	result := CleanupResult{}
	if len(subjects) == 0 {
		return result, nil
	}
	for _, deletion := range []struct {
		query string
		count *int64
	}{
		{`DELETE FROM auth_refresh_tokens rt USING auth_refresh_families f, auth_sessions sess
WHERE rt.family_id=f.id AND f.session_id=sess.id AND f.subject_id=ANY($2::uuid[])
AND (sess.expires_at<$1 OR sess.revoked_at<$1 OR f.revoked_at<$1)`, &result.RefreshTokens},
		{`DELETE FROM auth_refresh_families f USING auth_sessions sess
WHERE f.session_id=sess.id AND f.subject_id=ANY($2::uuid[])
AND (sess.expires_at<$1 OR sess.revoked_at<$1 OR f.revoked_at<$1)`, &result.RefreshFamilies},
		{`DELETE FROM auth_sessions
WHERE subject_id=ANY($2::uuid[]) AND (expires_at<$1 OR revoked_at<$1)`, &result.Sessions},
	} {
		deleted, err := tx.ExecContext(ctx, deletion.query, before, subjects)
		if err != nil {
			return CleanupResult{}, err
		}
		*deletion.count, err = deleted.RowsAffected()
		if err != nil {
			return CleanupResult{}, err
		}
	}
	if err := commitAuthTransaction(tx); err != nil {
		return CleanupResult{}, err
	}
	return result, nil
}
