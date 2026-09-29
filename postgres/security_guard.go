package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
)

func lockActiveSubject(ctx context.Context, tx *sql.Tx, id goauth.SubjectID) error {
	var status string
	err := tx.QueryRowContext(ctx, `SELECT status FROM auth_subjects WHERE id=$1 FOR UPDATE`, id).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return goauth.ErrAccountNotFound
	}
	if err != nil {
		return fmt.Errorf("lock active subject: %w", err)
	}
	if goauth.SubjectStatus(status) != goauth.SubjectStatusActive {
		return goauth.ErrAccountUnavailable
	}
	return nil
}

func securityTime(ctx context.Context, origin, started time.Time) time.Time {
	return authclock.Now(ctx, origin, started)
}

// All callers hold the subject lock. Invalidating outstanding records on every
// security-version change binds them to that version without rewriting schema 3.
func invalidateEmailSecurityState(ctx context.Context, tx *sql.Tx, id goauth.SubjectID, now time.Time) error {
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_email_change_records SET consumed_at=$2
WHERE subject_id=$1 AND consumed_at IS NULL`, id, now); err != nil {
		return fmt.Errorf("invalidate pending email changes: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
UPDATE auth_email_challenges SET attempts=max_attempts
WHERE subject_id=$1 AND verified_at IS NULL AND attempts<max_attempts`, id); err != nil {
		return fmt.Errorf("invalidate pending email challenges: %w", err)
	}
	return nil
}
