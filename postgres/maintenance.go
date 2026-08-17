package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type CleanupPolicy struct {
	ExpiredRecordRetention time.Duration
	RateEventRetention     time.Duration
	AuditEventRetention    time.Duration
	Now                    func() time.Time
}

type CleanupResult struct {
	PasswordResets      int64
	EmailChallenges     int64
	EmailChanges        int64
	RefreshTokens       int64
	RefreshFamilies     int64
	OIDCRefreshTokens   int64
	OIDCRefreshFamilies int64
	Sessions            int64
	RateEvents          int64
	AuditEvents         int64
}

func DefaultCleanupPolicy() CleanupPolicy {
	return CleanupPolicy{
		ExpiredRecordRetention: 24 * time.Hour,
		RateEventRetention:     25 * time.Hour,
		AuditEventRetention:    90 * 24 * time.Hour,
		Now:                    time.Now,
	}
}

func (r *Runtime) Cleanup(ctx context.Context, policy CleanupPolicy) (CleanupResult, error) {
	if r == nil || r.db == nil {
		return CleanupResult{}, errors.New("PostgreSQL Runtime is not initialized")
	}
	defaults := DefaultCleanupPolicy()
	if policy.ExpiredRecordRetention == 0 {
		policy.ExpiredRecordRetention = defaults.ExpiredRecordRetention
	}
	if policy.RateEventRetention == 0 {
		policy.RateEventRetention = defaults.RateEventRetention
	}
	if policy.AuditEventRetention == 0 {
		policy.AuditEventRetention = defaults.AuditEventRetention
	}
	if policy.Now == nil {
		policy.Now = time.Now
	}
	if policy.ExpiredRecordRetention < 0 || policy.RateEventRetention < 24*time.Hour ||
		policy.AuditEventRetention < 24*time.Hour {
		return CleanupResult{}, errors.New("invalid goauth cleanup retention")
	}

	now := policy.Now().UTC()
	expiredBefore := now.Add(-policy.ExpiredRecordRetention)
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return CleanupResult{}, fmt.Errorf("begin goauth cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var result CleanupResult
	deletions := []struct {
		query string
		arg   time.Time
		count *int64
	}{
		{`DELETE FROM auth_password_reset_records WHERE expires_at < $1 OR consumed_at < $1`, expiredBefore, &result.PasswordResets},
		{`DELETE FROM auth_email_challenges WHERE expires_at < $1 OR verified_at < $1`, expiredBefore, &result.EmailChallenges},
		{`DELETE FROM auth_email_change_records WHERE expires_at < $1 OR consumed_at < $1`, expiredBefore, &result.EmailChanges},
		{`DELETE FROM auth_oidc_refresh_tokens WHERE expires_at < $1 OR consumed_at < $1`, expiredBefore, &result.OIDCRefreshTokens},
		{`DELETE FROM auth_oidc_refresh_families
WHERE expires_at < $1 OR revoked_at < $1 OR replayed_at < $1`, expiredBefore, &result.OIDCRefreshFamilies},
		{`DELETE FROM auth_refresh_tokens WHERE expires_at < $1 OR consumed_at < $1`, expiredBefore, &result.RefreshTokens},
		{`DELETE FROM auth_refresh_families WHERE revoked_at < $1`, expiredBefore, &result.RefreshFamilies},
		{`DELETE FROM auth_sessions WHERE expires_at < $1 OR revoked_at < $1`, expiredBefore, &result.Sessions},
		{`DELETE FROM auth_rate_limit_events WHERE occurred_at < $1`, now.Add(-policy.RateEventRetention), &result.RateEvents},
		{`DELETE FROM auth_security_audit_events WHERE occurred_at < $1`, now.Add(-policy.AuditEventRetention), &result.AuditEvents},
	}
	for _, deletion := range deletions {
		execResult, err := tx.ExecContext(ctx, deletion.query, deletion.arg)
		if err != nil {
			return CleanupResult{}, fmt.Errorf("clean goauth runtime state: %w", err)
		}
		rows, err := execResult.RowsAffected()
		if err != nil {
			return CleanupResult{}, fmt.Errorf("read goauth cleanup count: %w", err)
		}
		*deletion.count = rows
	}
	if err := tx.Commit(); err != nil {
		return CleanupResult{}, fmt.Errorf("commit goauth cleanup: %w", err)
	}

	return result, nil
}
