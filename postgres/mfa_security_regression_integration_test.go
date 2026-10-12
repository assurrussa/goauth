//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/postgres"
)

const mfaConstraintCascade = "ON DELETE CASCADE"

func TestLocalMFAFinalLockWaitRechecksExpiry(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	binding := [32]byte{11}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	var clock atomic.Int64
	clock.Store(f.now.UnixNano())
	reached := make(chan struct{})
	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	config := f.config
	config.Now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(ctx context.Context, _ goauth.Realm, _ goauth.Account,
		_ map[string]any,
	) error {
		close(reached)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	runtime, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	type outcome struct {
		result goauth.LoginResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		r, e := runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
		done <- outcome{r, e}
	}()
	select {
	case <-reached:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	blocker, err := f.db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = blocker.Rollback() }()
	var id string
	require.NoError(t, blocker.QueryRowContext(ctx, "SELECT id FROM auth_subjects WHERE id=$1 FOR UPDATE",
		f.account.Subject.ID).Scan(&id))
	close(release)
	require.Eventually(t, func() bool {
		var waiting bool
		err := f.db.QueryRowContext(ctx,
			`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%auth_subjects%')`).Scan(&waiting)
		return err == nil && waiting
	}, 5*time.Second, 10*time.Millisecond)
	clock.Store(begin.Pending.ExpiresAt.UnixNano())
	require.NoError(t, blocker.Commit())
	select {
	case got := <-done:
		require.ErrorIs(t, got.err, goauth.ErrMFALoginDenied)
		require.Empty(t, got.result)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var count int
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL").Scan(&count))
	require.Zero(t, count)
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_mfa_pending WHERE id=$1", begin.Pending.ID).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, f.db.QueryRowContext(ctx, "SELECT count(*) FROM auth_mfa_recovery WHERE subject_id=$1",
		f.account.Subject.ID).Scan(&count))
	require.Equal(t, 10, count)
}

// Simulate a successfully committed write whose acknowledgment was lost.
// The public result must remain empty even though the database has committed.
type mfaLostAcknowledgment struct {
	*postgres.Store
	calls int
}

func (s *mfaLostAcknowledgment) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	s.calls++
	err := s.Store.InOwnedAuthTransaction(ctx, fn)
	if err == nil && s.calls == 2 {
		return errors.Join(goauth.ErrOperationOutcomeUnknown, errors.New("injected lost commit acknowledgment"))
	}
	return err
}

func TestLocalMFAUnknownCommitWithholdsResult(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	_, codes := f.enroll(t)
	ctx := context.Background()
	binding := [32]byte{12}
	begin, err := f.runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	store, err := postgres.NewStore(f.db)
	require.NoError(t, err)
	transaction := &mfaLostAcknowledgment{Store: store}
	config := f.config
	config.Store = store
	config.AuthTransaction = transaction
	config.AuditSink = store
	runtime, err := goauth.NewRuntime(config)
	require.NoError(t, err)
	result, err := runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Empty(t, result)
	require.Equal(t, 2, transaction.calls)
	var count int
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL").Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_mfa_pending WHERE id=$1",
		begin.Pending.ID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT count(*) FROM auth_mfa_recovery WHERE subject_id=$1",
		f.account.Subject.ID).Scan(&count))
	require.Equal(t, 9, count)
	result, err = runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, codes[0])
	require.ErrorIs(t, err, goauth.ErrMFALoginDenied)
	require.Empty(t, result)
}

func TestLocalMFARotatedKeysRetainExistingCiphertext(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	e, _ := f.enroll(t)
	ctx := context.Background()
	var original []byte
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT secret FROM auth_mfa_factors WHERE subject_id=$1",
		f.account.Subject.ID).Scan(&original))
	ring, err := goauth.NewKeyRing("mfa-2", goauth.Key{ID: "mfa-2", Material: bytes.Repeat([]byte{92}, 32)},
		goauth.Key{ID: "mfa-1", Material: bytes.Repeat([]byte{91}, 32)})
	require.NoError(t, err)
	config := f.config
	config.MFAKeys = &ring
	f.now = f.now.Add(30 * time.Second)
	runtime, err := postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	binding := [32]byte{13}
	begin, err := runtime.BeginLocalLogin(ctx, f.request, binding)
	require.NoError(t, err)
	code, err := totp.GenerateCode(e.Secret, f.now)
	require.NoError(t, err)
	_, err = runtime.CompleteLocalLogin(ctx, begin.Pending.ID, binding, code)
	require.NoError(t, err)
	var after []byte
	var keyID string
	require.NoError(t, f.db.QueryRowContext(t.Context(), "SELECT key_id,secret FROM auth_mfa_factors WHERE subject_id=$1",
		f.account.Subject.ID).Scan(&keyID, &after))
	require.Equal(t, "mfa-1", keyID)
	require.Equal(t, original, after)
	missingOld, err := goauth.NewKeyRing("mfa-2", goauth.Key{ID: "mfa-2", Material: bytes.Repeat([]byte{92}, 32)})
	require.NoError(t, err)
	config.MFAKeys = &missingOld
	runtime, err = postgres.NewRuntime(postgres.Config{DB: f.db, Runtime: config})
	require.NoError(t, err)
	result, err := runtime.BeginLocalLogin(ctx, f.request, binding)
	require.ErrorIs(t, err, goauth.ErrMFAUnavailable)
	require.Empty(t, result)
}

func TestLocalMFAMigrationCriticalConstraints(t *testing.T) {
	f := newMFAIntegrationFixture(t)
	required := map[string][]string{
		"auth_mfa_factors_pkey":                 {"PRIMARY KEY (subject_id)"},
		"auth_mfa_factors_subject_id_fkey":      {"FOREIGN KEY (subject_id)", "REFERENCES auth_subjects(id)", mfaConstraintCascade},
		"auth_mfa_recovery_pkey":                {"PRIMARY KEY (subject_id, digest)"},
		"auth_mfa_recovery_subject_id_fkey":     {"REFERENCES auth_mfa_factors(subject_id)", mfaConstraintCascade},
		"auth_mfa_pending_pkey":                 {"PRIMARY KEY (id)"},
		"auth_mfa_pending_subject_id_realm_key": {"UNIQUE (subject_id, realm)"},
		"auth_mfa_pending_subject_id_fkey":      {"REFERENCES auth_mfa_factors(subject_id)", mfaConstraintCascade},
		"auth_mfa_enrollments_pkey":             {"PRIMARY KEY (subject_id)"},
		"auth_mfa_enrollments_session_id_fkey":  {"REFERENCES auth_sessions(id)", mfaConstraintCascade},
	}
	for name, fragments := range required {
		var definition string
		require.NoError(t,
			f.db.QueryRowContext(t.Context(),
				`SELECT pg_get_constraintdef(oid) FROM pg_constraint
			WHERE connamespace='public'::regnamespace AND conname=$1`,
				name).Scan(&definition), name)
		for _, fragment := range fragments {
			require.Contains(t, definition, fragment, name)
		}
	}
	// Inspect CHECK definitions collectively without depending on auto-generated names.
	checks := map[string][]string{
		"auth_mfa_factors":  {"revision > 0", "last_step >= '-1'", "octet_length(secret) >= 28", "NOT enabled"},
		"auth_mfa_recovery": {"octet_length(digest) = 32"},
		"auth_mfa_budget":   {"attempts >= 1", "attempts <= 10"},
		"auth_mfa_pending": {
			"length(id) = 43", "security_version > 0", "factor_revision > 0",
			"octet_length(binding) = 32", "expires_at > authenticated_at", "00:03:00",
		},
		"auth_mfa_enrollments": {
			"length(id) = 43", "revision > 0", "security_version > 0",
			"octet_length(binding) = 32", "octet_length(secret) >= 28", "expires_at > created_at", "00:05:00",
		},
	}
	for table, fragments := range checks {
		var definition string
		require.NoError(t,
			f.db.QueryRowContext(t.Context(), `SELECT string_agg(pg_get_constraintdef(oid), ' ') FROM pg_constraint
			WHERE conrelid=to_regclass($1) AND contype='c'`,
				table).Scan(&definition), table)
		for _, fragment := range fragments {
			require.Contains(t, definition, fragment, table)
		}
	}
}
