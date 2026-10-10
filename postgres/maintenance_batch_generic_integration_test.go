//go:build integration

package postgres_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/postgres"
)

func TestCleanupBatchGenericBoundsCutoffsAndNotificationScrubbing(t *testing.T) {
	runtime, db, clock := refreshRetentionRuntime(t, 48*time.Hour, 48*time.Hour)
	registered := register(t, runtime, "bounded-generic@example.test")
	now := time.Unix(0, clock.Load()).UTC()
	subject := registered.Account.Subject.ID.String()
	for _, query := range []string{
		`INSERT INTO auth_password_reset_records
(selector,subject_id,key_id,secret_digest,created_at,expires_at)
SELECT 'batch-reset-'||g,$1,'fixture',decode(repeat('00',32),'hex'),$2::timestamptz-interval '4 days',
CASE WHEN g<=5 THEN $2::timestamptz-interval '24 hours 1 microsecond' ELSE $2::timestamptz-interval '24 hours' END
FROM generate_series(1,6) g`,
		`INSERT INTO auth_email_challenges
(id,subject_id,identifier_id,purpose,key_id,code_digest,created_at,expires_at)
SELECT md5('batch-challenge-'||g)::uuid,$1,
(SELECT id FROM auth_identifiers WHERE subject_id=$1 AND scheme='email' AND is_primary),
'verification','fixture',decode(repeat('00',32),'hex'),$2::timestamptz-interval '4 days',
CASE WHEN g<=5 THEN $2::timestamptz-interval '24 hours 1 microsecond' ELSE $2::timestamptz-interval '24 hours' END
FROM generate_series(1,6) g`,
		`INSERT INTO auth_email_change_records
(id,subject_id,new_display_value,new_normalized_value,key_id,code_digest,created_at,expires_at)
SELECT md5('batch-change-'||g)::uuid,$1,'batch-'||g||'@example.test','batch-'||g||'@example.test',
'fixture',decode(repeat('00',32),'hex'),$2::timestamptz-interval '4 days',
CASE WHEN g<=5 THEN $2::timestamptz-interval '24 hours 1 microsecond' ELSE $2::timestamptz-interval '24 hours' END
FROM generate_series(1,6) g`,
		`INSERT INTO auth_rate_limit_events(subject_id,key_id,bucket_digest,action,occurred_at)
SELECT $1,'fixture',decode(repeat('00',32),'hex'),'batch',
CASE WHEN g<=5 THEN $2::timestamptz-interval '25 hours 1 microsecond' ELSE $2::timestamptz-interval '25 hours' END
FROM generate_series(1,6) g`,
		`INSERT INTO auth_security_audit_events(id,subject_id,event_type,occurred_at)
SELECT md5('batch-audit-'||g)::uuid,$1,'batch',
CASE WHEN g<=5 THEN $2::timestamptz-interval '90 days 1 microsecond' ELSE $2::timestamptz-interval '90 days' END
FROM generate_series(1,6) g`,
		`INSERT INTO auth_notification_deliveries
(id,subject_id,event_type,valid_until,key_id,nonce,ciphertext,additional_data,created_at,
delete_after,state,next_attempt_at,lease_token,leased_until)
SELECT md5('batch-envelope-'||g)::uuid,$1,'batch',$2,'fixture',decode('01','hex'),decode('01','hex'),decode('01','hex'),
$2::timestamptz-interval '1 day',$2::timestamptz+interval '1 day','leased',
$2::timestamptz-interval '1 day',md5('batch-lease-'||g)::uuid,$2::timestamptz+interval '1 day'
FROM generate_series(1,5) g`,
		`INSERT INTO auth_notification_deliveries
(id,subject_id,event_type,valid_until,key_id,nonce,ciphertext,additional_data,created_at,delete_after,state,next_attempt_at)
SELECT md5('batch-receipt-'||g)::uuid,$1,'batch',
CASE WHEN g<=5 THEN $2::timestamptz-interval '7 days 1 microsecond' ELSE $2::timestamptz-interval '7 days' END,
'fixture','\x'::bytea,NULL,'\x'::bytea,$2::timestamptz-interval '8 days',$2,'expired',$2::timestamptz-interval '8 days'
FROM generate_series(1,6) g`,
	} {
		maintenanceExec(t, db, query, subject, now)
	}
	policy := postgres.CleanupPolicy{Now: func() time.Time { return now }}
	var totals postgres.CleanupBatchResult
	for _, want := range []int64{2, 2, 1, 0} {
		beforeReceipts := maintenanceCount(t, db, `SELECT count(*) FROM auth_notification_deliveries`)
		result, err := runtime.CleanupBatch(t.Context(), policy, 2)
		require.NoError(t, err)
		assertCleanupBatchBounds(t, result, 2)
		for _, count := range []int64{
			result.PasswordResets, result.EmailChallenges, result.EmailChanges, result.RateEvents,
			result.AuditEvents, result.NotificationsExpired, result.NotificationReceipts,
		} {
			require.Equal(t, want, count)
		}
		require.Equal(t, result.NotificationReceipts, beforeReceipts-maintenanceCount(t, db,
			`SELECT count(*) FROM auth_notification_deliveries`))
		totals.NotificationsExpired += result.NotificationsExpired
		totals.NotificationReceipts += result.NotificationReceipts
	}
	require.EqualValues(t, 5, totals.NotificationsExpired, "notification cutoff is inclusive")
	require.EqualValues(t, 5, totals.NotificationReceipts)
	require.EqualValues(t, 5, maintenanceCount(t, db, `SELECT count(*) FROM auth_notification_deliveries
WHERE event_type='batch' AND valid_until=$1 AND state='expired' AND ciphertext IS NULL
AND octet_length(nonce)=0 AND octet_length(additional_data)=0 AND lease_token IS NULL AND leased_until IS NULL`, now))
	for _, query := range []string{
		`SELECT count(*) FROM auth_password_reset_records WHERE selector LIKE 'batch-reset-%'`,
		`SELECT count(*) FROM auth_email_challenges WHERE key_id='fixture'`,
		`SELECT count(*) FROM auth_email_change_records WHERE key_id='fixture'`,
		`SELECT count(*) FROM auth_rate_limit_events WHERE action='batch'`,
		`SELECT count(*) FROM auth_security_audit_events WHERE event_type='batch'`,
		`SELECT count(*) FROM auth_notification_deliveries WHERE valid_until<$1 AND event_type='batch'`,
	} {
		// Only the receipt assertion needs the clock argument.
		if query == `SELECT count(*) FROM auth_notification_deliveries WHERE valid_until<$1 AND event_type='batch'` {
			require.EqualValues(t, 1, maintenanceCount(t, db, query, now))
		} else {
			require.EqualValues(t, 1, maintenanceCount(t, db, query))
		}
	}
	// Unrelated canonical identity, credentials and live session survive.
	require.EqualValues(t, 1, maintenanceCount(t, db, `SELECT count(*) FROM auth_subjects WHERE id=$1`, subject))
	require.EqualValues(t, 1, maintenanceCount(t, db, `SELECT count(*) FROM auth_local_credentials WHERE subject_id=$1`, subject))
	require.EqualValues(t, 1, maintenanceCount(t, db, `SELECT count(*) FROM auth_sessions WHERE subject_id=$1`, subject))
}

func TestCleanupBatchSkipsLockedGenericRowsThenContinues(t *testing.T) {
	runtime, db, clock := refreshRetentionRuntime(t, 48*time.Hour, 48*time.Hour)
	registered := register(t, runtime, "bounded-generic-lock@example.test")
	now := time.Unix(0, clock.Load()).UTC()
	maintenanceExec(t, db, `INSERT INTO auth_password_reset_records
(selector,subject_id,key_id,secret_digest,created_at,expires_at)
VALUES ('batch-locked',$1,'fixture',decode(repeat('00',32),'hex'),$2::timestamptz-interval '4 days',
$2::timestamptz-interval '25 hours')`,
		registered.Account.Subject.ID.String(), now)
	blocker, err := db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = blocker.Rollback() })
	_, err = blocker.ExecContext(t.Context(),
		`SELECT selector FROM auth_password_reset_records WHERE selector='batch-locked' FOR UPDATE`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	policy := postgres.CleanupPolicy{Now: func() time.Time { return now }}
	result, err := runtime.CleanupBatch(ctx, policy, 1)
	require.NoError(t, err)
	require.Zero(t, result.PasswordResets)
	require.EqualValues(t, 1, maintenanceCount(t, db,
		`SELECT count(*) FROM auth_password_reset_records WHERE selector='batch-locked'`))
	require.NoError(t, blocker.Commit())
	result, err = runtime.CleanupBatch(ctx, policy, 1)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.PasswordResets)
}
