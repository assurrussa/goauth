//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

const scopedEmailTestScope goauth.EmailChangeScope = "test-host-alias-v1"

type scopedEmailSQLTarget struct {
	runtime *postgres.Runtime
	fail    atomic.Bool
}

func (s *scopedEmailSQLTarget) SnapshotEmailChangeTarget(
	ctx context.Context, subject goauth.SubjectID,
) (goauth.EmailChangeTargetSnapshot, error) {
	ex, err := s.runtime.SQLExecutor(ctx)
	if err != nil {
		return goauth.EmailChangeTargetSnapshot{}, err
	}
	var snapshot goauth.EmailChangeTargetSnapshot
	err = ex.QueryRowContext(ctx, `SELECT address,version FROM goauth_test_email_alias WHERE subject_id=$1`, subject).
		Scan(&snapshot.NormalizedEmail, &snapshot.Version)
	return snapshot, err
}

func (s *scopedEmailSQLTarget) ApplyVerifiedEmailChange(ctx context.Context, subject goauth.SubjectID,
	expected goauth.EmailChangeTargetSnapshot, address string, _ time.Time,
) error {
	ex, err := s.runtime.SQLExecutor(ctx)
	if err != nil {
		return err
	}
	result, err := ex.ExecContext(ctx, `UPDATE goauth_test_email_alias SET address=$2,version=version+1
 WHERE subject_id=$1 AND address=$3 AND version=$4`, subject, address, expected.NormalizedEmail, expected.Version)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return goauth.ErrSecurityVersionMismatch
	}
	if s.fail.Load() {
		return errors.New("injected scoped email apply failure")
	}
	return nil
}

type scopedEmailFixture struct {
	db         *sql.DB
	runtime    *postgres.Runtime
	target     *scopedEmailSQLTarget
	account    goauth.Account
	clock      atomic.Int64
	deliveries atomic.Int64
}

func newScopedEmailFixture(t *testing.T) *scopedEmailFixture {
	t.Helper()
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(t.Context(), db))
	_, err := db.ExecContext(t.Context(), `DROP TABLE IF EXISTS goauth_test_email_alias;
 CREATE TABLE goauth_test_email_alias(subject_id uuid PRIMARY KEY REFERENCES auth_subjects(id),
 address text NOT NULL UNIQUE,version bigint NOT NULL)`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), `DROP TABLE IF EXISTS goauth_test_email_alias`)
		require.NoError(t, err)
	})
	f := &scopedEmailFixture{db: db, target: &scopedEmailSQLTarget{}}
	f.clock.Store(time.Now().UTC().Truncate(time.Microsecond).UnixMicro())
	cfg := runtimeConfig(t)
	cfg.Now = func() time.Time { return time.UnixMicro(f.clock.Load()).UTC() }
	cfg.EmailChangeTargets = map[goauth.EmailChangeScope]goauth.EmailChangeTarget{scopedEmailTestScope: f.target}
	f.runtime, err = postgres.NewRuntime(postgres.Config{
		DB: db, Runtime: cfg,
		NotificationSender: goauth.NotificationSenderFunc(func(_ context.Context, d goauth.NotificationDelivery) error {
			if d.Notification.Template == "email_change" {
				f.deliveries.Add(1)
			}
			return nil
		}),
		NotificationWorker: postgres.NotificationWorkerConfig{
			PollInterval: 10 * time.Millisecond, SendTimeout: time.Second,
			LeaseDuration: 2 * time.Second, RetryMin: 20 * time.Millisecond, RetryMax: 50 * time.Millisecond, MaxAttempts: 3,
		},
	})
	require.NoError(t, err)
	f.target.runtime = f.runtime
	f.account = register(t, f.runtime, "primary.scoped@example.test").Account
	f.account, err = f.runtime.GetAccount(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	_, err = db.ExecContext(t.Context(),
		`INSERT INTO goauth_test_email_alias VALUES($1,'old.alias@example.test',1)`, f.account.Subject.ID)
	require.NoError(t, err)
	return f
}

func (f *scopedEmailFixture) context(t *testing.T) context.Context {
	t.Helper()
	return goauth.WithEmailChangeScope(t.Context(), scopedEmailTestScope)
}

func (f *scopedEmailFixture) issue(t *testing.T, address string) (goauth.PendingEmailChange, string, string) {
	t.Helper()
	require.NoError(t, f.runtime.RequestEmailChange(f.context(t), f.account.Subject.ID, address))
	pending, err := f.runtime.PendingEmailChange(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	id, notice := queuedNotification(t, f.db, f.account.Subject.ID, "email_change")
	require.Equal(t, string(scopedEmailTestScope), notice.Data["email_change_scope"])
	require.Equal(t, address, notice.To)
	return pending, notice.Data["code"], id
}

func TestScopedEmailVerifiedTargetPreservesPrimaryAndConsumesOnce(t *testing.T) {
	f := newScopedEmailFixture(t)
	pending, code, _ := f.issue(t, "new.alias@example.test")
	_, err := f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, differentIntegrationCode(code))
	require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	current, err := f.runtime.PendingEmailChange(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, 1, current.Attempts)
	after, err := f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, code)
	require.NoError(t, err)
	require.Equal(t, f.account.Subject.ID, after.Subject.ID)
	require.Equal(t, f.account.PrimaryEmail, after.PrimaryEmail)
	require.Equal(t, f.account.Subject.SecurityVersion+1, after.Subject.SecurityVersion)
	snapshot, err := f.target.SnapshotEmailChangeTarget(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, "new.alias@example.test", snapshot.NormalizedEmail)
	require.EqualValues(t, 2, snapshot.Version)
	_, notice := queuedNotification(t, f.db, f.account.Subject.ID, "email_changed")
	require.Equal(t, "old.alias@example.test", notice.To)
	require.Equal(t, string(scopedEmailTestScope), notice.Data["email_change_scope"])
	require.Empty(t, notice.Data["code"])
	var consumed bool
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT consumed_at IS NOT NULL FROM auth_email_change_records WHERE id=$1`,
		pending.ID).Scan(&consumed))
	require.True(t, consumed)
	_, err = f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, code)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
}

func TestScopedEmailSharedSendQuotaAndSeparatePendingRecords(t *testing.T) {
	f := newScopedEmailFixture(t)
	first, _, _ := f.issue(t, "first.alias@example.test")
	err := f.runtime.RequestEmailChange(t.Context(), f.account.Subject.ID, "new.primary@example.test")
	require.ErrorIs(t, err, goauth.ErrConfirmationResendDelay)
	f.clock.Add(int64((time.Minute + time.Second) / time.Microsecond))
	require.NoError(t, f.runtime.RequestEmailChange(t.Context(), f.account.Subject.ID, "new.primary@example.test"))
	primary, err := f.runtime.PendingEmailChange(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Empty(t, primary.Scope)
	require.Zero(t, primary.ExpectedSecurityVersion)
	scoped, err := f.runtime.PendingEmailChange(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, first.ID, scoped.ID)
	f.clock.Add(int64((time.Minute + time.Second) / time.Microsecond))
	replacement, _, _ := f.issue(t, "second.alias@example.test")
	require.NotEqual(t, first.ID, replacement.ID)
	primaryAgain, err := f.runtime.PendingEmailChange(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, primary.ID, primaryAgain.ID)
	var oldConsumed bool
	require.NoError(t, f.db.QueryRowContext(t.Context(), `SELECT consumed_at IS NOT NULL FROM auth_email_change_records WHERE id=$1`,
		first.ID).Scan(&oldConsumed))
	require.True(t, oldConsumed)
	for _, address := range []string{"third.alias@example.test", "fourth.alias@example.test"} {
		f.clock.Add(int64((time.Minute + time.Second) / time.Microsecond))
		f.issue(t, address)
	}
	f.clock.Add(int64((time.Minute + time.Second) / time.Microsecond))
	err = f.runtime.RequestEmailChange(t.Context(), f.account.Subject.ID, "another.primary@example.test")
	require.ErrorIs(t, err, goauth.ErrConfirmationRateLimited)
}

func TestScopedEmailRejectsStaleTargetAndSecurity(t *testing.T) {
	for _, change := range []string{"target", "security"} {
		t.Run(change, func(t *testing.T) {
			f := newScopedEmailFixture(t)
			pending, code, _ := f.issue(t, "new.alias@example.test")
			query := `UPDATE goauth_test_email_alias SET address='temporary.alias@example.test',version=version+1 WHERE subject_id=$1`
			if change == "security" {
				query = `UPDATE auth_subjects SET security_version=security_version+1 WHERE id=$1`
			}
			_, err := f.db.ExecContext(t.Context(), query, f.account.Subject.ID)
			require.NoError(t, err)
			if change == "target" {
				_, err = f.db.ExecContext(t.Context(),
					`UPDATE goauth_test_email_alias SET address='old.alias@example.test',version=version+1 WHERE subject_id=$1`,
					f.account.Subject.ID)
				require.NoError(t, err)
			}
			_, err = f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, code)
			require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
			var consumed bool
			require.NoError(t, f.db.QueryRowContext(t.Context(),
				`SELECT consumed_at IS NOT NULL FROM auth_email_change_records WHERE id=$1`,
				pending.ID).Scan(&consumed))
			require.False(t, consumed)
		})
	}
}

func TestScopedEmailApplyFailureRollsBackProofAndVersion(t *testing.T) {
	f := newScopedEmailFixture(t)
	pending, code, _ := f.issue(t, "new.alias@example.test")
	f.target.fail.Store(true)
	_, err := f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, code)
	require.ErrorContains(t, err, "injected scoped email apply failure")
	account, err := f.runtime.GetAccount(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, f.account.Subject.SecurityVersion, account.Subject.SecurityVersion)
	snapshot, err := f.target.SnapshotEmailChangeTarget(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, "old.alias@example.test", snapshot.NormalizedEmail)
	require.EqualValues(t, 1, snapshot.Version)
	current, err := f.runtime.PendingEmailChange(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, pending.ID, current.ID)
	f.target.fail.Store(false)
	_, err = f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, code)
	require.NoError(t, err)
}

func TestScopedEmailQueuedNoticeRejectsChangedTarget(t *testing.T) {
	f := newScopedEmailFixture(t)
	_, _, id := f.issue(t, "new.alias@example.test")
	_, err := f.db.ExecContext(t.Context(), `UPDATE goauth_test_email_alias SET version=version+1 WHERE subject_id=$1`,
		f.account.Subject.ID)
	require.NoError(t, err)
	startManagedNotificationWorker(t, f.runtime)
	waitManagedNotificationState(t, f.db, id, "expired")
	require.Zero(t, f.deliveries.Load())
}

func TestScopedEmailCopiedPrimaryDigestCannotVerifyHostProjection(t *testing.T) {
	f := newScopedEmailFixture(t)
	require.NoError(t, f.runtime.RequestEmailChange(t.Context(), f.account.Subject.ID, "new.primary@example.test"))
	primary, err := f.runtime.PendingEmailChange(t.Context(), f.account.Subject.ID)
	require.NoError(t, err)
	_, notice := queuedNotification(t, f.db, f.account.Subject.ID, "email_change")
	f.clock.Add(int64((time.Minute + time.Second) / time.Microsecond))
	pending, _, _ := f.issue(t, "new.alias@example.test")
	_, err = f.db.ExecContext(t.Context(), `
 UPDATE auth_email_change_records target SET code_digest=source.code_digest,key_id=source.key_id
 FROM auth_email_change_records source WHERE target.id=$1 AND source.id=$2`, pending.ID, primary.ID)
	require.NoError(t, err)
	_, err = f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, notice.Data["code"])
	require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	snapshot, err := f.target.SnapshotEmailChangeTarget(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, "old.alias@example.test", snapshot.NormalizedEmail)
}

func TestScopedEmailQueuedEnvelopeCannotChangeScopeOrRecipient(t *testing.T) {
	for name, query := range map[string]string{
		"scope": `UPDATE auth_email_change_records SET scope='another-host' WHERE id=$1`,
		"legacy-downgrade": `UPDATE auth_email_change_records SET scope='',expected_security_version=NULL,
   target_version=NULL,old_normalized_value=NULL WHERE id=$1`,
		"recipient": `UPDATE auth_email_change_records SET new_normalized_value='changed.recipient@example.test' WHERE id=$1`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newScopedEmailFixture(t)
			pending, _, delivery := f.issue(t, "new.alias@example.test")
			_, err := f.db.ExecContext(t.Context(), query, pending.ID)
			require.NoError(t, err)
			startManagedNotificationWorker(t, f.runtime)
			waitManagedNotificationState(t, f.db, delivery, "expired")
			require.Zero(t, f.deliveries.Load())
		})
	}
}

func TestScopedEmailRecordAttemptsExpiryAndForeignSubject(t *testing.T) {
	f := newScopedEmailFixture(t)
	_, code, _ := f.issue(t, "new.alias@example.test")
	other := register(t, f.runtime, "another.subject@example.test").Account
	_, err := f.runtime.ConfirmEmailChange(f.context(t), other.Subject.ID, code)
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	for range 5 {
		_, err = f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, differentIntegrationCode(code))
		require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	}
	_, err = f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, code)
	require.ErrorIs(t, err, goauth.ErrConfirmationAttempts)
	pending, err := f.runtime.PendingEmailChange(f.context(t), f.account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, 5, pending.Attempts)
	f.clock.Add(int64((time.Minute + time.Second) / time.Microsecond))
	replacement, newCode, _ := f.issue(t, "replacement.alias@example.test")
	require.Zero(t, replacement.Attempts)
	f.clock.Add(int64((11 * time.Minute) / time.Microsecond))
	_, err = f.runtime.ConfirmEmailChange(f.context(t), f.account.Subject.ID, newCode)
	require.ErrorIs(t, err, goauth.ErrConfirmationExpired)
}
