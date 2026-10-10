package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// CleanupBatchResult reports confirmed commits from one bounded maintenance pass.
// Each field is independently bounded by perCategoryLimit; OIDCRefreshFamilies
// and RefreshFamilies are additionally capped at 32. NotificationsExpired counts
// envelope updates, while NotificationReceipts counts physical row deletions.
type CleanupBatchResult struct {
	CleanupResult
	OIDCRequests int64
	OIDCCodes    int64
}

// CleanupBatch performs one opt-in, bounded broad maintenance pass. The limit
// must be 1..1000 and is per result field, NOT a total row budget. At most
// 12*perCategoryLimit + 2*min(perCategoryLimit, 32) row changes can commit.
// Policy defaults and retention predicates are the same as Cleanup; Cleanup's
// established behavior is unchanged. The policy clock is sampled exactly once.
//
// Notification, OIDC, canonical refresh/session and generic cleanup commit in
// separate phases, releasing each phase's locks before the next. Active managed
// transactions, including foreign scopes, are rejected before SQL. On error,
// the result contains only earlier confirmed phases, never the failed phase's
// provisional counts. An unknown commit preserves ErrOperationOutcomeUnknown;
// zero counts do not establish rollback or recover an earlier uncertain count.
//
// Call again with the same fixed policy clock to continue remaining eligible
// rows. There is no cursor, internal retry or exhaustion signal: locked rows,
// dependent rows and chain prefixes remain for later passes. Even a zero result
// does not prove the backlog is empty. Hosts own deadlines and spaced cadence;
// row-change bounds do not bound scan cost, lock latency or elapsed time.
func (r *Runtime) CleanupBatch(ctx context.Context, policy CleanupPolicy, perCategoryLimit int) (CleanupBatchResult, error) {
	if r == nil || r.db == nil || r.store == nil || r.store.db != r.db {
		return CleanupBatchResult{}, errors.New("PostgreSQL Runtime is not initialized")
	}
	if perCategoryLimit < 1 || perCategoryLimit > 1000 {
		return CleanupBatchResult{}, errors.New("cleanup per-category limit must be 1..1000")
	}
	policy, err := normalizeBatchCleanupPolicy(policy)
	if err != nil {
		return CleanupBatchResult{}, err
	}
	existing, err := r.store.notificationTx(ctx)
	if err != nil {
		return CleanupBatchResult{}, err
	}
	if existing != nil {
		return CleanupBatchResult{}, ErrAuthTransactionAlreadyActive
	}
	now := policy.Now().UTC()
	if now.IsZero() {
		return CleanupBatchResult{}, errors.New("cleanup clock must not be zero")
	}
	result := CleanupBatchResult{}
	var expired int64
	err = cleanupBatchTransaction(ctx, r.db, func(tx *sql.Tx) error {
		var phaseErr error
		expired, phaseErr = cleanupBatchRows(ctx, tx, notificationExpirySQL, now, perCategoryLimit)
		return phaseErr
	})
	if err != nil {
		return result, fmt.Errorf("expire cleanup notification batch: %w", err)
	}
	result.NotificationsExpired = expired
	expiredBefore := now.Add(-policy.ExpiredRecordRetention)
	var oidcResult SessionOIDCCleanupResult
	err = cleanupBatchTransaction(ctx, r.db, func(tx *sql.Tx) error {
		return cleanupSessionOIDCLimited(ctx, tx, expiredBefore, &oidcResult, false, perCategoryLimit)
	})
	if err != nil {
		return result, fmt.Errorf("clean session OIDC batch: %w", err)
	}
	result.OIDCRequests, result.OIDCCodes = oidcResult.Requests, oidcResult.Codes
	result.OIDCRefreshTokens, result.OIDCRefreshFamilies = oidcResult.RefreshTokens, oidcResult.RefreshFamilies
	canonical, err := cleanupRefreshStateBatch(ctx, r.db, expiredBefore, perCategoryLimit)
	if err != nil {
		return result, fmt.Errorf("clean canonical refresh batch: %w", err)
	}
	result.RefreshTokens = canonical.RefreshTokens
	result.RefreshFamilies = canonical.RefreshFamilies
	result.Sessions = canonical.Sessions
	generic, err := cleanupGenericBatch(ctx, r.db, policy, now, perCategoryLimit)
	if err != nil {
		return result, fmt.Errorf("clean generic auth batch: %w", err)
	}
	result.PasswordResets = generic.PasswordResets
	result.EmailChallenges = generic.EmailChallenges
	result.EmailChanges = generic.EmailChanges
	result.RateEvents = generic.RateEvents
	result.AuditEvents = generic.AuditEvents
	result.NotificationReceipts = generic.NotificationReceipts
	return result, nil
}

func normalizeBatchCleanupPolicy(policy CleanupPolicy) (CleanupPolicy, error) {
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
	if policy.NotificationReceiptRetention == 0 {
		policy.NotificationReceiptRetention = defaults.NotificationReceiptRetention
	}
	if policy.Now == nil {
		policy.Now = defaults.Now
	}
	if policy.ExpiredRecordRetention < 0 || policy.RateEventRetention < 24*time.Hour ||
		policy.AuditEventRetention < 24*time.Hour || policy.NotificationReceiptRetention < 24*time.Hour {
		return CleanupPolicy{}, errors.New("invalid goauth cleanup retention")
	}
	return policy, nil
}

func cleanupBatchTransaction(ctx context.Context, db *sql.DB, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return commitAuthTransaction(tx)
}

func cleanupBatchRows(ctx context.Context, tx *sql.Tx, query string, args ...any) (int64, error) {
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func cleanupGenericBatch(ctx context.Context, db *sql.DB, policy CleanupPolicy, now time.Time, limit int) (CleanupResult, error) {
	result := CleanupResult{}
	err := cleanupBatchTransaction(ctx, db, func(tx *sql.Tx) error {
		for _, deletion := range []struct {
			query  string
			before time.Time
			count  *int64
		}{
			{passwordResetCleanupBatchSQL, now.Add(-policy.ExpiredRecordRetention), &result.PasswordResets},
			{emailChallengeCleanupBatchSQL, now.Add(-policy.ExpiredRecordRetention), &result.EmailChallenges},
			{emailChangeCleanupBatchSQL, now.Add(-policy.ExpiredRecordRetention), &result.EmailChanges},
			{rateEventCleanupSQL, now.Add(-policy.RateEventRetention), &result.RateEvents},
			{auditCleanupBatchSQL, now.Add(-policy.AuditEventRetention), &result.AuditEvents},
			{receiptCleanupBatchSQL, now.Add(-policy.NotificationReceiptRetention), &result.NotificationReceipts},
		} {
			count, err := cleanupBatchRows(ctx, tx, deletion.query, deletion.before, limit)
			if err != nil {
				return err
			}
			*deletion.count = count
		}
		return nil
	})
	if err != nil {
		return CleanupResult{}, err
	}
	return result, nil
}

const passwordResetCleanupBatchSQL = `DELETE FROM auth_password_reset_records WHERE selector IN (
 SELECT selector FROM auth_password_reset_records WHERE expires_at < $1 OR consumed_at < $1
 ORDER BY LEAST(expires_at, consumed_at), selector LIMIT $2 FOR UPDATE SKIP LOCKED)`

const emailChallengeCleanupBatchSQL = `DELETE FROM auth_email_challenges WHERE id IN (
 SELECT id FROM auth_email_challenges WHERE expires_at < $1 OR verified_at < $1
 ORDER BY LEAST(expires_at, verified_at), id LIMIT $2 FOR UPDATE SKIP LOCKED)`

const emailChangeCleanupBatchSQL = `DELETE FROM auth_email_change_records WHERE id IN (
 SELECT id FROM auth_email_change_records WHERE expires_at < $1 OR consumed_at < $1
 ORDER BY LEAST(expires_at, consumed_at), id LIMIT $2 FOR UPDATE SKIP LOCKED)`

const auditCleanupBatchSQL = `DELETE FROM auth_security_audit_events WHERE id IN (
 SELECT id FROM auth_security_audit_events WHERE occurred_at < $1
 ORDER BY occurred_at, id LIMIT $2 FOR UPDATE SKIP LOCKED)`

const receiptCleanupBatchSQL = `DELETE FROM auth_notification_deliveries WHERE id IN (
 SELECT id FROM auth_notification_deliveries
 WHERE ciphertext IS NULL AND COALESCE(delivered_at, valid_until) < $1
 ORDER BY COALESCE(delivered_at, valid_until), id LIMIT $2 FOR UPDATE SKIP LOCKED)`
