//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/oidc/provider"
	"github.com/assurrussa/goauth/postgres"
	"github.com/assurrussa/goauth/rbac"
	"github.com/assurrussa/goauth/testkit"
)

func TestMigrationFreshSchemaDownUpAndLegacyRefusal(t *testing.T) {
	db := integrationDB(t)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))

	var version int
	require.NoError(t, db.QueryRow(`SELECT max(version) FROM goauth_schema_version`).Scan(&version))
	require.Equal(t, 5, version)
	var requiredTables int
	require.NoError(t, db.QueryRow(`
SELECT count(*)
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN (
      'auth_subjects', 'auth_identifiers', 'auth_basic_profiles', 'auth_local_credentials',
      'auth_sessions', 'auth_refresh_families', 'auth_refresh_tokens',
      'auth_oidc_refresh_families', 'auth_oidc_refresh_tokens',
      'auth_password_reset_records', 'auth_email_challenges', 'auth_email_change_records',
      'auth_identity_links', 'auth_roles', 'auth_permissions', 'auth_role_permissions',
      'auth_subject_roles', 'auth_rate_limit_events'
  )`).Scan(&requiredTables))
	require.Equal(t, 18, requiredTables)
	var hierarchyTable sql.NullString
	require.NoError(t, db.QueryRow(`SELECT to_regclass('public.auth_role_hierarchy')::text`).Scan(&hierarchyTable))
	require.False(t, hierarchyTable.Valid)
	var identifierForeignKeys int
	require.NoError(t, db.QueryRow(`
SELECT count(*)
FROM information_schema.table_constraints
WHERE table_schema = 'public'
  AND table_name = 'auth_identifiers'
  AND constraint_type = 'FOREIGN KEY'`).Scan(&identifierForeignKeys))
	require.Equal(t, 1, identifierForeignKeys)

	_, err := db.Exec(`CREATE TABLE host_auth_projection (
subject_id UUID PRIMARY KEY REFERENCES auth_subjects(id)
)`)
	require.NoError(t, err)
	require.Error(t, postgres.Down(context.Background(), db, postgres.ConfirmResetAuthState))
	var subjectsAfterRejectedReset sql.NullString
	require.NoError(t, db.QueryRow(`SELECT to_regclass('public.auth_subjects')::text`).Scan(&subjectsAfterRejectedReset))
	require.True(t, subjectsAfterRejectedReset.Valid, "failed reset must roll back canonical schema drops")
	_, err = db.Exec(`DROP TABLE host_auth_projection`)
	require.NoError(t, err)

	require.NoError(t, postgres.Down(context.Background(), db, postgres.ConfirmResetAuthState))
	require.NoError(t, postgres.Migrate(context.Background(), db))
	require.NoError(t, postgres.Down(context.Background(), db, postgres.ConfirmResetAuthState))
	_, err = db.Exec(`CREATE TABLE auth_subjects (id UUID PRIMARY KEY, email TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO auth_subjects (id, email) VALUES ('123e4567-e89b-12d3-a456-426614174000', 'legacy@example.test')`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.Migrate(context.Background(), db), postgres.ErrLegacySchemaRequiresReset)
	var legacyRows int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_subjects`).Scan(&legacyRows))
	require.Equal(t, 1, legacyRows, "legacy detection must not delete data")
	_, err = db.Exec(`
CREATE TABLE auth_confirmation_codes (id BIGSERIAL PRIMARY KEY);
CREATE TABLE auth_external_identities (id BIGSERIAL PRIMARY KEY);
CREATE TABLE IF NOT EXISTS role_hierarchy (id BIGSERIAL PRIMARY KEY);
CREATE TABLE goauth_goose_db_version (id BIGSERIAL PRIMARY KEY);`)
	require.NoError(t, err)
	require.NoError(t, postgres.Down(context.Background(), db, postgres.ConfirmResetAuthState))
	for _, table := range []string{
		"auth_subjects", "auth_confirmation_codes", "auth_external_identities",
		"goauth_goose_db_version",
	} {
		var relation sql.NullString
		require.NoError(t, db.QueryRow(`SELECT to_regclass($1)::text`, "public."+table).Scan(&relation))
		require.False(t, relation.Valid, table)
	}
	var hostTable sql.NullString
	require.NoError(t, db.QueryRow(`SELECT to_regclass('public.role_hierarchy')::text`).Scan(&hostTable))
	require.True(t, hostTable.Valid, "host RBAC table must survive auth reset")
	_, err = db.Exec(`DROP TABLE role_hierarchy`)
	require.NoError(t, err)

	require.NoError(t, postgres.Migrate(context.Background(), db))

	resetSchema(t, db)
	_, err = db.Exec(`CREATE TABLE auth_subjects (id UUID PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE goauth_schema_version (version SMALLINT NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO goauth_schema_version (version) VALUES (1)`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.Migrate(context.Background(), db), postgres.ErrLegacySchemaRequiresReset)

	resetSchema(t, db)
	_, err = db.Exec(`CREATE TABLE auth_subjects (id UUID PRIMARY KEY, status TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(`CREATE TABLE goauth_schema_version (version SMALLINT NOT NULL)`)
	require.NoError(t, err)
	_, err = db.Exec(`INSERT INTO goauth_schema_version (version) VALUES (2)`)
	require.NoError(t, err)
	require.ErrorIs(t, postgres.Migrate(context.Background(), db), postgres.ErrLegacySchemaRequiresReset)

	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
}

func TestPostgresRefreshRotationAllowsExactlyOneConcurrentIssuance(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "refresh.concurrent@example.test")

	const requests = 32
	var successes atomic.Int64
	var replays atomic.Int64
	var unexpected atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, err := runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, goauth.ErrRefreshReplay):
				replays.Add(1)
			default:
				unexpected.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, requests-1, replays.Load())
	require.Zero(t, unexpected.Load())
}

func TestPostgresConsumedRefreshSelectorRequiresValidSecretForReplay(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "refresh.selector@example.test")
	ctx := context.Background()

	rotated, err := runtime.Refresh(ctx, registered.Tokens.RefreshToken)
	require.NoError(t, err)

	parts := strings.Split(registered.Tokens.RefreshToken, ".")
	require.Len(t, parts, 3)
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	_, err = runtime.Refresh(ctx, strings.Join(parts, "."))
	require.ErrorIs(t, err, goauth.ErrInvalidToken)

	var revokedAt sql.NullTime
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT revoked_at FROM auth_sessions WHERE id = $1`, rotated.Session.ID,
	).Scan(&revokedAt))
	require.False(t, revokedAt.Valid, "wrong secret must not revoke the active session")
	var replayAudits int
	require.NoError(t, db.QueryRowContext(ctx, `
SELECT count(*) FROM auth_security_audit_events
WHERE subject_id = $1 AND event_type = 'refresh.replay'`,
		registered.Account.Subject.ID,
	).Scan(&replayAudits))
	require.Zero(t, replayAudits, "wrong secret must not report a replay")
	continued, err := runtime.Refresh(ctx, rotated.RefreshToken)
	require.NoError(t, err, "the active refresh family must remain usable")

	_, err = runtime.Refresh(ctx, registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrRefreshReplay)
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT revoked_at FROM auth_sessions WHERE id = $1`, rotated.Session.ID,
	).Scan(&revokedAt))
	require.True(t, revokedAt.Valid, "authenticated replay must revoke the session")
	require.NoError(t, db.QueryRowContext(ctx, `
SELECT count(*) FROM auth_security_audit_events
WHERE subject_id = $1 AND event_type = 'refresh.replay'`,
		registered.Account.Subject.ID,
	).Scan(&replayAudits))
	require.Equal(t, 1, replayAudits)
	_, err = runtime.Refresh(ctx, continued.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

func TestPostgresAccountLifecycleIsAtomicAndDigestOnly(t *testing.T) {
	db := integrationDB(t)
	runtime, events, envelopeKeys := integrationRuntime(t, db)
	registered := register(t, runtime, "lifecycle.before@example.test")

	require.NoError(t, runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	verificationCode := integrationNotificationCode(t, runtime, events, "email_challenge")
	_, err := runtime.VerifyEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		verificationCode,
	)
	require.NoError(t, err)
	profiled, err := runtime.UpdateBasicProfile(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.BasicProfile{Username: "lifecycle", DisplayName: "Lifecycle Account"},
	)
	require.NoError(t, err)
	require.Equal(t, "lifecycle", profiled.Profile.Username)

	logoutSession, err := runtime.Login(
		context.Background(),
		login("lifecycle.before@example.test", "Integration-Unique-Passphrase-1"),
	)
	require.NoError(t, err)
	require.NoError(t, runtime.Logout(
		context.Background(),
		registered.Account.Subject.ID,
		logoutSession.Tokens.Session.ID,
	))
	_, err = runtime.VerifyAccessToken(context.Background(), logoutSession.Tokens.AccessToken, true)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	logoutAllSession, err := runtime.Login(
		context.Background(),
		login("lifecycle.before@example.test", "Integration-Unique-Passphrase-1"),
	)
	require.NoError(t, err)
	revoked, err := runtime.LogoutAll(context.Background(), registered.Account.Subject.ID)
	require.NoError(t, err)
	require.Positive(t, revoked)
	_, err = runtime.VerifyAccessToken(context.Background(), logoutAllSession.Tokens.AccessToken, true)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)

	require.NoError(t, runtime.RequestEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		"Lifecycle.After@Example.Test",
	))
	changeCode := integrationNotificationCode(t, runtime, events, "email_change")
	var rawCodeOccurrences int
	require.NoError(t, db.QueryRow(`
SELECT count(*)
FROM auth_email_change_records
WHERE encode(code_digest, 'hex') = $1 OR new_display_value = $1 OR new_normalized_value = $1`, changeCode).Scan(&rawCodeOccurrences))
	require.Zero(t, rawCodeOccurrences)
	_, err = runtime.ConfirmEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		differentIntegrationCode(changeCode),
	)
	require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	pending, err := runtime.PendingEmailChange(context.Background(), registered.Account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, 1, pending.Attempts)
	changed, err := runtime.ConfirmEmailChange(
		context.Background(),
		registered.Account.Subject.ID,
		changeCode,
	)
	require.NoError(t, err)
	require.Equal(t, "lifecycle.after@example.test", changed.PrimaryEmail.NormalizedValue)
	require.True(t, changed.EmailVerified())

	const currentPassword = "Integration-Unique-Passphrase-1"
	passwords := []string{"Lifecycle-Password-A1", "Lifecycle-Password-B2"}
	errorsByPassword := make([]error, len(passwords))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, password := range passwords {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, errorsByPassword[index] = runtime.ChangePassword(context.Background(), goauth.ChangePasswordRequest{
				SubjectID:       registered.Account.Subject.ID,
				CurrentPassword: currentPassword,
				NewPassword:     password,
			})
		}()
	}
	close(start)
	wait.Wait()
	var successes int
	var winningPassword string
	for index, changeErr := range errorsByPassword {
		if changeErr == nil {
			successes++
			winningPassword = passwords[index]
			continue
		}
		require.True(t,
			errors.Is(changeErr, goauth.ErrPasswordChangeConflict) ||
				errors.Is(changeErr, goauth.ErrCurrentPasswordInvalid),
			"unexpected concurrent password change outcome: %v", changeErr,
		)
	}
	require.Equal(t, 1, successes)
	var storedPHC string
	require.NoError(t, db.QueryRow(`
SELECT password_phc FROM auth_local_credentials WHERE subject_id = $1`, registered.Account.Subject.ID).Scan(&storedPHC))
	require.NotEqual(t, winningPassword, storedPHC)
	require.NotContains(t, storedPHC, winningPassword)
	_, err = runtime.Login(context.Background(), login("lifecycle.after@example.test", winningPassword))
	require.NoError(t, err)

	for _, event := range events.Events() {
		notification, decryptErr := testkit.DecryptNotification(envelopeKeys, event.Envelope)
		require.NoError(t, decryptErr)
		if secret := notification.Data["code"]; secret != "" {
			require.NotContains(t, string(event.Envelope.Ciphertext), secret)
		}
	}
}

func TestPostgresEmailChangeRateAndAttemptOutcomes(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	account := register(t, runtime, "email.change.rate@example.test").Account
	other := register(t, runtime, "email.change.occupied@example.test").Account
	base := time.Now().UTC().Truncate(time.Second)
	digest := goauth.SecretDigest{KeyID: "email-change", Digest: bytes.Repeat([]byte{6}, 32)}
	rateDigest := goauth.SecretDigest{KeyID: "email-change-rate", Digest: bytes.Repeat([]byte{7}, 32)}
	limits := goauth.EmailChallengeLimits{MinResendInterval: time.Minute, PerHour: 5, PerDay: 10}
	record := func(index int, at time.Time) goauth.EmailChangeRecord {
		return goauth.EmailChangeRecord{
			ID:                 goauth.NewSubjectID().String(),
			SubjectID:          account.Subject.ID,
			NewDisplayValue:    fmt.Sprintf("Email.Change.%d@Example.Test", index),
			NewNormalizedValue: fmt.Sprintf("email.change.%d@example.test", index),
			Digest:             digest,
			RateDigest:         rateDigest,
			MaxAttempts:        5,
			CreatedAt:          at,
			ExpiresAt:          at.Add(10 * time.Minute),
		}
	}

	same := record(0, base)
	same.NewDisplayValue = account.PrimaryEmail.DisplayValue
	same.NewNormalizedValue = account.PrimaryEmail.NormalizedValue
	sameResult, err := store.IssueEmailChange(context.Background(), same, limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeSameValue, sameResult.Status)
	occupied := record(0, base)
	occupied.NewDisplayValue = other.PrimaryEmail.DisplayValue
	occupied.NewNormalizedValue = other.PrimaryEmail.NormalizedValue
	_, err = store.IssueEmailChange(context.Background(), occupied, limits)
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)

	issued, err := store.IssueEmailChange(context.Background(), record(1, base), limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeIssued, issued.Status)
	waiting, err := store.IssueEmailChange(context.Background(), record(2, base.Add(30*time.Second)), limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeWait, waiting.Status)
	for index := 2; index <= 5; index++ {
		at := base.Add(time.Duration(index-1) * (time.Minute + time.Second))
		issued, err = store.IssueEmailChange(context.Background(), record(index, at), limits)
		require.NoError(t, err)
		require.Equal(t, goauth.EmailChangeIssued, issued.Status)
	}
	hourly, err := store.IssueEmailChange(context.Background(), record(6, base.Add(6*time.Minute)), limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeHourlyLimit, hourly.Status)
	for index, hours := range []int{2, 4, 6, 8, 10} {
		issued, err = store.IssueEmailChange(
			context.Background(),
			record(10+index, base.Add(time.Duration(hours)*time.Hour)),
			limits,
		)
		require.NoError(t, err)
		require.Equal(t, goauth.EmailChangeIssued, issued.Status)
	}
	daily, err := store.IssueEmailChange(context.Background(), record(20, base.Add(12*time.Hour)), limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeDailyLimit, daily.Status)

	attemptAccount := register(t, runtime, "email.change.attempts@example.test").Account
	attemptRecord := record(30, base)
	attemptRecord.SubjectID = attemptAccount.Subject.ID
	attemptRecord.RateDigest = goauth.SecretDigest{KeyID: "attempt-rate", Digest: bytes.Repeat([]byte{8}, 32)}
	issued, err = store.IssueEmailChange(context.Background(), attemptRecord, limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeIssued, issued.Status)
	wrong := goauth.SecretDigest{KeyID: "wrong", Digest: bytes.Repeat([]byte{9}, 32)}
	for expectedAttempts := 1; expectedAttempts <= 5; expectedAttempts++ {
		result, verifyErr := store.VerifyEmailChange(context.Background(), goauth.EmailChangeVerifyRequest{
			SubjectID: attemptAccount.Subject.ID,
			Digests:   []goauth.SecretDigest{wrong},
			Now:       base.Add(time.Minute),
		})
		require.NoError(t, verifyErr)
		require.Equal(t, goauth.EmailChangeInvalid, result.Status)
		require.Equal(t, expectedAttempts, result.Attempts)
	}
	exhausted, err := store.VerifyEmailChange(context.Background(), goauth.EmailChangeVerifyRequest{
		SubjectID: attemptAccount.Subject.ID,
		Digests:   []goauth.SecretDigest{digest},
		Now:       base.Add(time.Minute),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeAttemptsUsed, exhausted.Status)

	expiredAccount := register(t, runtime, "email.change.expired@example.test").Account
	expiredRecord := record(40, base.Add(-20*time.Minute))
	expiredRecord.SubjectID = expiredAccount.Subject.ID
	expiredRecord.RateDigest = goauth.SecretDigest{KeyID: "expired-rate", Digest: bytes.Repeat([]byte{10}, 32)}
	issued, err = store.IssueEmailChange(context.Background(), expiredRecord, limits)
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeIssued, issued.Status)
	expired, err := store.VerifyEmailChange(context.Background(), goauth.EmailChangeVerifyRequest{
		SubjectID: expiredAccount.Subject.ID,
		Digests:   []goauth.SecretDigest{digest},
		Now:       base,
	})
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeExpired, expired.Status)
}

func TestPostgresOIDCRefreshTokensAreDigestOnlyAndReplayRevokesFamily(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "oidc.refresh@example.test")
	store, err := postgres.NewOIDCRefreshTokenStore(db, keyRing(t, "oidc-refresh", 9))
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	currentRaw := "oidc-current-raw-bearer-secret"
	current := oidc.RefreshToken{
		Token:           currentRaw,
		SubjectID:       registered.Account.Subject.ID.String(),
		ClientID:        "consumer-client",
		Scopes:          []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID},
		SecurityVersion: registered.Account.Subject.SecurityVersion,
		AuthenticatedAt: now,
		CreatedAt:       now,
		ExpiresAt:       now.Add(24 * time.Hour),
	}
	require.NoError(t, store.Save(context.Background(), current))

	var rawMatches int
	require.NoError(t, db.QueryRow(`
SELECT count(*)
FROM auth_oidc_refresh_tokens
WHERE row_to_json(auth_oidc_refresh_tokens)::text LIKE '%' || $1 || '%'`, currentRaw).Scan(&rawMatches))
	require.Zero(t, rawMatches, "OIDC refresh table contains the raw bearer token")
	loaded, err := store.Get(context.Background(), currentRaw)
	require.NoError(t, err)
	require.Equal(t, currentRaw, loaded.Token)
	require.Equal(t, current.SubjectID, loaded.SubjectID)

	next := current
	next.Token = "oidc-next-raw-bearer-secret"
	next.CreatedAt = now.Add(time.Minute)
	next.ExpiresAt = next.CreatedAt.Add(24 * time.Hour)
	const requests = 32
	var successes atomic.Int64
	var replays atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			err := store.Rotate(context.Background(), currentRaw, next, next.CreatedAt)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, oidc.ErrRefreshTokenReplay), errors.Is(err, oidc.ErrRefreshTokenNotFound):
				replays.Add(1)
			default:
				t.Errorf("unexpected OIDC refresh rotation result: %v", err)
			}
		}()
	}
	close(start)
	wait.Wait()
	require.EqualValues(t, 1, successes.Load())
	require.EqualValues(t, requests-1, replays.Load())

	loaded, err = store.Get(context.Background(), next.Token)
	require.NoError(t, err)
	require.NotNil(t, loaded.RevokedAt, "replay must revoke the whole OIDC refresh family")
	loaded, err = store.Get(context.Background(), currentRaw)
	require.NoError(t, err)
	require.NotNil(t, loaded.RevokedAt)
	var replayAudits int
	require.NoError(t, db.QueryRow(`
SELECT count(*) FROM auth_security_audit_events
WHERE subject_id = $1 AND event_type = 'oidc_refresh.replay'`, registered.Account.Subject.ID).Scan(&replayAudits))
	require.Equal(t, 1, replayAudits)

	revoked := current
	revoked.Token = "oidc-explicitly-revoked-bearer-secret"
	revoked.CreatedAt = now.Add(2 * time.Minute)
	revoked.ExpiresAt = revoked.CreatedAt.Add(24 * time.Hour)
	require.NoError(t, store.Save(context.Background(), revoked))
	require.NoError(t, store.Revoke(context.Background(), "", now))
	require.NoError(t, store.Revoke(context.Background(), "unknown-token", now))
	require.NoError(t, store.Revoke(context.Background(), revoked.Token, now.Add(3*time.Minute)))
	loaded, err = store.Get(context.Background(), revoked.Token)
	require.NoError(t, err)
	require.NotNil(t, loaded.RevokedAt)

	_, err = store.Get(context.Background(), "")
	require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
	_, err = store.Get(context.Background(), "different-unknown-token")
	require.ErrorIs(t, err, oidc.ErrRefreshTokenNotFound)
	require.Error(t, store.Save(context.Background(), oidc.RefreshToken{}))
	require.ErrorIs(
		t,
		store.Rotate(context.Background(), "different-unknown-token", next, now),
		oidc.ErrRefreshTokenNotFound,
	)
	require.Error(t, store.Rotate(context.Background(), next.Token, next, now))

	metadata := current
	metadata.Token = "oidc-metadata-current-secret"
	metadata.CreatedAt = now.Add(4 * time.Minute)
	metadata.ExpiresAt = metadata.CreatedAt.Add(24 * time.Hour)
	require.NoError(t, store.Save(context.Background(), metadata))
	metadataNext := metadata
	metadataNext.Token = "oidc-metadata-next-secret"
	metadataNext.ClientID = "different-client"
	metadataNext.CreatedAt = metadata.CreatedAt.Add(time.Minute)
	metadataNext.ExpiresAt = metadataNext.CreatedAt.Add(24 * time.Hour)
	require.Error(t, store.Rotate(context.Background(), metadata.Token, metadataNext, metadataNext.CreatedAt))

	expiredFamily := current
	expiredFamily.Token = "oidc-expired-current-secret"
	expiredFamily.CreatedAt = now.Add(-2 * time.Hour)
	expiredFamily.ExpiresAt = now.Add(-time.Hour)
	require.NoError(t, store.Save(context.Background(), expiredFamily))
	expiredNext := expiredFamily
	expiredNext.Token = "oidc-expired-next-secret"
	expiredNext.CreatedAt = now
	expiredNext.ExpiresAt = now.Add(24 * time.Hour)
	require.ErrorIs(
		t,
		store.Rotate(context.Background(), expiredFamily.Token, expiredNext, now),
		oidc.ErrRefreshTokenNotFound,
	)
}

func TestPostgresRuntimeAssemblesOptionalOIDCAndRBAC(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "optional.features@example.test")
	require.NotNil(t, runtime.OIDCRefreshTokens())

	resolved, err := runtime.Resolve(context.Background(), registered.Account.Subject.ID.String())
	require.NoError(t, err)
	require.Equal(t, registered.Account.Subject.ID, resolved.Subject.ID)
	_, err = runtime.Resolve(context.Background(), "not-a-subject-id")
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)

	permissionService, err := runtime.RBAC(nil)
	require.NoError(t, err)
	require.NotNil(t, permissionService)

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	providerService, err := runtime.OIDCProvider(provider.Options{
		Clients:  oidcClientStoreStub{},
		Requests: oidcRequestStoreStub{},
		Codes:    oidcCodeStoreStub{},
		Keys:     oidcKeyStoreStub{key: signingKey},
		Issuer:   "https://issuer.example.test",
	})
	require.NoError(t, err)
	require.True(t, providerService.Enabled())

	var nilRuntime *postgres.Runtime
	require.Nil(t, nilRuntime.OIDCRefreshTokens())
	_, err = nilRuntime.Resolve(context.Background(), registered.Account.Subject.ID.String())
	require.Error(t, err)
	_, err = nilRuntime.RBAC(nil)
	require.Error(t, err)
	_, err = nilRuntime.OIDCProvider(provider.Options{})
	require.Error(t, err)
	_, err = postgres.NewOIDCRefreshTokenStore(nil, keyRing(t, "nil-db", 4))
	require.Error(t, err)
	_, err = postgres.NewOIDCRefreshTokenStore(db, goauth.KeyRing{})
	require.Error(t, err)
}

func TestPostgresPasswordResetConsumesOnce(t *testing.T) {
	db := integrationDB(t)
	runtime, events, envelopeKeys := integrationRuntime(t, db)
	register(t, runtime, "reset.concurrent@example.test")
	require.NoError(t, runtime.RequestPasswordReset(context.Background(), "reset.concurrent@example.test"))
	eventList := events.Events()
	require.NotEmpty(t, eventList)
	notification, err := testkit.DecryptNotification(envelopeKeys, eventList[len(eventList)-1].Envelope)
	require.NoError(t, err)
	resetURL, err := url.Parse(notification.Data["reset_url"])
	require.NoError(t, err)
	token := resetURL.Query().Get("token")
	require.NotEmpty(t, token)

	passwords := []string{"Postgres-Replacement-A1", "Postgres-Replacement-B2"}
	results := make([]error, len(passwords))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, password := range passwords {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			results[index] = runtime.ResetPassword(context.Background(), token, password)
		}()
	}
	close(start)
	wait.Wait()
	var successes int
	var used int
	var winner string
	for index, err := range results {
		if err == nil {
			successes++
			winner = passwords[index]
		} else if errors.Is(err, goauth.ErrResetAlreadyUsed) {
			used++
		} else {
			t.Fatalf("unexpected password reset result: %v", err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, used)
	_, err = runtime.Login(context.Background(), login("reset.concurrent@example.test", winner))
	require.NoError(t, err)
}

func TestPostgresEmailChallengeAttemptsAndAtomicRateLimit(t *testing.T) {
	db := integrationDB(t)
	runtime, events, envelopeKeys := integrationRuntime(t, db)
	registered := register(t, runtime, "challenge@example.test")
	require.NoError(t, runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	eventList := events.Events()
	notification, err := testkit.DecryptNotification(envelopeKeys, eventList[len(eventList)-1].Envelope)
	require.NoError(t, err)
	code := notification.Data["code"]
	wrong := "000000"
	if code == wrong {
		wrong = "999999"
	}
	for range 5 {
		_, err := runtime.VerifyEmailChallenge(
			context.Background(),
			registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification,
			wrong,
		)
		require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
	}
	_, err = runtime.VerifyEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		wrong,
	)
	require.ErrorIs(t, err, goauth.ErrConfirmationAttempts)
	var attempts int
	require.NoError(t, db.QueryRow(`
SELECT attempts FROM auth_email_challenges
WHERE subject_id = $1
ORDER BY created_at DESC LIMIT 1`, registered.Account.Subject.ID).Scan(&attempts))
	require.Equal(t, 5, attempts)

	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	second := register(t, runtime, "rate.concurrent@example.test")
	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	limits := goauth.EmailChallengeLimits{PerHour: 5, PerDay: 10}
	var issued atomic.Int64
	var limited atomic.Int64
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := range 6 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			result, err := store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{
				ID:           fmt.Sprintf("123e4567-e89b-12d3-a456-%012d", index+1),
				SubjectID:    second.Account.Subject.ID,
				IdentifierID: second.Account.PrimaryEmail.ID,
				Purpose:      goauth.EmailChallengePurposeVerification,
				Digest:       goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{byte(index + 1)}, 32)},
				RateDigest:   goauth.SecretDigest{KeyID: "rate-test", Digest: bytes.Repeat([]byte{1}, 32)},
				MaxAttempts:  5,
				CreatedAt:    base,
				ExpiresAt:    base.Add(time.Hour),
			}, limits)
			require.NoError(t, err)
			if result.Status == goauth.EmailChallengeIssued {
				issued.Add(1)
			} else if result.Status == goauth.EmailChallengeHourlyLimit {
				limited.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	require.EqualValues(t, 5, issued.Load())
	require.EqualValues(t, 1, limited.Load())
}

func TestPostgresCaseInsensitiveRegistrationIsUnique(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	emails := []string{"Case.User@Example.Test", "case.user@example.test"}
	results := make([]error, len(emails))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, email := range emails {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, results[index] = runtime.Register(context.Background(), goauth.RegisterRequest{
				Email:    email,
				Password: "Case-Unique-Passphrase-1",
			})
		}()
	}
	close(start)
	wait.Wait()
	var successes, conflicts int
	for _, err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, goauth.ErrIdentifierAlreadyExists) {
			conflicts++
		} else {
			t.Fatalf("unexpected registration result: %v", err)
		}
	}
	require.Equal(t, 1, successes)
	require.Equal(t, 1, conflicts)
}

func TestPostgresDailyEmailChallengeLimitAndBoundary(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "daily.rate@example.test")
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	base := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)
	limits := goauth.EmailChallengeLimits{PerHour: 5, PerDay: 10}
	rateDigest := goauth.SecretDigest{KeyID: "rate-test", Digest: bytes.Repeat([]byte{8}, 32)}
	issue := func(index int, at time.Time) goauth.EmailChallengeIssueResult {
		t.Helper()
		result, issueErr := store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{
			ID:           fmt.Sprintf("123e4567-e89b-12d3-a456-%012d", index),
			SubjectID:    registered.Account.Subject.ID,
			IdentifierID: registered.Account.PrimaryEmail.ID,
			Purpose:      goauth.EmailChallengePurposeVerification,
			Digest:       goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{byte(index)}, 32)},
			RateDigest:   rateDigest,
			MaxAttempts:  5,
			CreatedAt:    at,
			ExpiresAt:    at.Add(time.Hour),
		}, limits)
		require.NoError(t, issueErr)
		return result
	}
	for index := 1; index <= 10; index++ {
		require.Equal(t, goauth.EmailChallengeIssued, issue(index, base.Add(time.Duration(index-1)*2*time.Hour)).Status)
	}
	require.Equal(t, goauth.EmailChallengeDailyLimit, issue(11, base.Add(20*time.Hour)).Status)
	require.Equal(
		t,
		goauth.EmailChallengeDailyLimit,
		issue(12, base.Add(24*time.Hour)).Status,
		"the exact rolling-window cutoff remains included",
	)
	require.Equal(
		t,
		goauth.EmailChallengeIssued,
		issue(13, base.Add(24*time.Hour+time.Microsecond)).Status,
	)
}

func TestPostgresSSOLinkingRequiresVerifiedEmailAndCreatesNoCredential(t *testing.T) {
	db := integrationDB(t)
	runtime, events, envelopeKeys := integrationRuntime(t, db)
	ssoOnly, err := runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        "https://idp.example.test",
		Subject:       "sso-only",
		Email:         "sso.only@example.test",
		EmailVerified: true,
	})
	require.NoError(t, err)
	var credentials int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_local_credentials WHERE subject_id = $1`, ssoOnly.Subject.ID).Scan(&credentials))
	require.Zero(t, credentials)
	resolved, err := runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        "https://idp.example.test",
		Subject:       "sso-only",
		Email:         "sso.only@example.test",
		EmailVerified: true,
	})
	require.NoError(t, err)
	require.Equal(t, ssoOnly.Subject.ID, resolved.Subject.ID)

	local := register(t, runtime, "existing.sso@example.test")
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	_, err = store.LinkIdentity(context.Background(), goauth.IdentityLink{
		ID:              "123e4567-e89b-12d3-a456-426614174204",
		SubjectID:       local.Account.Subject.ID,
		Issuer:          "https://idp.example.test",
		ExternalSubject: "sso-only",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})
	require.ErrorIs(t, err, goauth.ErrIdentityLinkConflict)
	_, err = runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        "https://idp.example.test",
		Subject:       "local-unverified",
		Email:         "existing.sso@example.test",
		EmailVerified: true,
	})
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink)
	require.NoError(t, runtime.SendEmailChallenge(
		context.Background(),
		local.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	challengeEvent := events.Events()[len(events.Events())-1]
	challengeNotification, err := testkit.DecryptNotification(envelopeKeys, challengeEvent.Envelope)
	require.NoError(t, err)
	verified, err := runtime.VerifyEmailChallenge(
		context.Background(),
		local.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		challengeNotification.Data["code"],
	)
	require.NoError(t, err)
	require.True(t, verified.EmailVerified())
	verifiedAgain, err := runtime.VerifyEmailChallenge(
		context.Background(),
		local.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		challengeNotification.Data["code"],
	)
	require.NoError(t, err)
	require.True(t, verifiedAgain.EmailVerified())
	_, err = runtime.Login(
		context.Background(),
		login("existing.sso@example.test", "Integration-Unique-Passphrase-1"),
	)
	require.NoError(t, err, "verified local identifiers must round-trip through PostgreSQL login")
	_, err = runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        "https://idp.example.test",
		Subject:       "idp-unverified",
		Email:         "existing.sso@example.test",
		EmailVerified: false,
	})
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink)
	linked, err := runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
		Issuer:        "https://idp.example.test",
		Subject:       "both-verified",
		Email:         "EXISTING.SSO@EXAMPLE.TEST",
		EmailVerified: true,
	})
	require.NoError(t, err)
	require.Equal(t, local.Account.Subject.ID, linked.Subject.ID)

	var existingLinkID string
	require.NoError(t, db.QueryRow(`
SELECT id FROM auth_identity_links
WHERE issuer = 'https://idp.example.test' AND external_subject = 'sso-only'`).Scan(&existingLinkID))
	_, err = store.LinkIdentity(context.Background(), goauth.IdentityLink{
		ID:              existingLinkID,
		SubjectID:       local.Account.Subject.ID,
		Issuer:          "https://other-idp.example.test",
		ExternalSubject: "different-subject",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})
	require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = store.LinkIdentity(canceledContext, goauth.IdentityLink{
		ID:              goauth.NewSubjectID().String(),
		SubjectID:       local.Account.Subject.ID,
		Issuer:          "https://cancelled-idp.example.test",
		ExternalSubject: "cancelled-subject",
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	})
	require.Error(t, err)
}

func TestPostgresNeverStoresRawRuntimeSecrets(t *testing.T) {
	db := integrationDB(t)
	runtime, events, envelopeKeys := integrationRuntime(t, db)
	registered := register(t, runtime, "secret.storage@example.test")
	require.NoError(t, runtime.RequestPasswordReset(context.Background(), "secret.storage@example.test"))
	resetEvent := events.Events()[len(events.Events())-1]
	resetNotification, err := testkit.DecryptNotification(envelopeKeys, resetEvent.Envelope)
	require.NoError(t, err)
	resetURL, err := url.Parse(resetNotification.Data["reset_url"])
	require.NoError(t, err)
	resetToken := resetURL.Query().Get("token")
	require.NotEmpty(t, resetToken)
	require.NoError(t, runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	challengeEvent := events.Events()[len(events.Events())-1]
	challengeNotification, err := testkit.DecryptNotification(envelopeKeys, challengeEvent.Envelope)
	require.NoError(t, err)
	code := challengeNotification.Data["code"]
	require.NotEmpty(t, code)

	checks := []struct {
		table  string
		secret string
	}{
		{"auth_refresh_tokens", registered.Tokens.RefreshToken},
		{"auth_password_reset_records", resetToken},
		{"auth_email_challenges", code},
		{"auth_local_credentials", "Integration-Unique-Passphrase-1"},
	}
	for _, check := range checks {
		var count int
		query := fmt.Sprintf(`SELECT count(*) FROM %s AS value WHERE row_to_json(value)::text LIKE '%%' || $1 || '%%'`, check.table)
		require.NoError(t, db.QueryRow(query, check.secret).Scan(&count))
		require.Zero(t, count, "%s contains a raw secret", check.table)
	}
	require.False(t, bytes.Contains(resetEvent.Envelope.Ciphertext, []byte(resetToken)))
	require.False(t, bytes.Contains(challengeEvent.Envelope.Ciphertext, []byte(code)))
}

func TestPostgresSubjectStatusRevokesSessionsAndRefreshFamilies(t *testing.T) {
	for _, status := range []goauth.SubjectStatus{
		goauth.SubjectStatusSuspended,
		goauth.SubjectStatusDisabled,
	} {
		t.Run(string(status), func(t *testing.T) {
			db := integrationDB(t)
			runtime, _, _ := integrationRuntime(t, db)
			registered := register(t, runtime, string(status)+".status@example.test")
			subject, err := runtime.SetSubjectStatus(context.Background(), registered.Account.Subject.ID, status)
			require.NoError(t, err)
			require.Equal(t, int64(2), subject.SecurityVersion)
			_, err = runtime.VerifyAccessToken(context.Background(), registered.Tokens.AccessToken, true)
			require.Error(t, err)
			_, err = runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
			require.ErrorIs(t, err, goauth.ErrSessionRevoked)

			var activeSessions, activeFamilies int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_sessions WHERE subject_id = $1 AND revoked_at IS NULL`, subject.ID).Scan(&activeSessions))
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_refresh_families WHERE subject_id = $1 AND revoked_at IS NULL`, subject.ID).Scan(&activeFamilies))
			require.Zero(t, activeSessions)
			require.Zero(t, activeFamilies)
		})
	}
}

func TestPostgresRBACUsesExplicitRolePermissions(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "rbac.integration@example.test")
	service, err := postgres.NewRBAC(db, nil)
	require.NoError(t, err)

	role, err := service.UpsertRole(context.Background(), rbac.Role{Slug: "editor", Name: "Editor"})
	require.NoError(t, err)
	require.NotZero(t, role.ID)
	role.Name = "Content editor"
	_, err = service.UpsertRole(context.Background(), role)
	require.NoError(t, err)
	read := rbac.MustPermissionKey("content", "read")
	write := rbac.MustPermissionKey("content", "write")
	for _, key := range []rbac.PermissionKey{read, write} {
		permission, permissionErr := service.UpsertPermission(context.Background(), rbac.Permission{Key: key})
		require.NoError(t, permissionErr)
		require.NotZero(t, permission.ID)
	}
	require.NoError(t, service.SetRolePermissions(context.Background(), role.Slug, []rbac.PermissionKey{read, write}))
	require.NoError(t, service.AssignRole(context.Background(), registered.Account.Subject.ID, role.Slug))
	require.NoError(t, service.AssignRole(context.Background(), registered.Account.Subject.ID, role.Slug))
	require.True(t, service.Can(context.Background(), registered.Account.Subject.ID, write))
	require.NoError(t, service.Require(context.Background(), registered.Account.Subject.ID, read))

	var hierarchy sql.NullString
	require.NoError(t, db.QueryRow(`SELECT to_regclass('public.auth_role_hierarchy')::text`).Scan(&hierarchy))
	require.False(t, hierarchy.Valid)
	require.Error(t, service.AssignRole(context.Background(), registered.Account.Subject.ID, "missing"))
	require.Error(t, service.SetRolePermissions(context.Background(), "missing", []rbac.PermissionKey{read}))
	require.Error(t, service.SetRolePermissions(
		context.Background(),
		role.Slug,
		[]rbac.PermissionKey{rbac.MustPermissionKey("missing", "permission")},
	))
}

func TestPostgresRBACManagementLifecycle(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "rbac.management@example.test")
	service, err := postgres.NewRBAC(db, nil)
	require.NoError(t, err)
	ctx := context.Background()

	read := rbac.MustPermissionKey("content", "read")
	write := rbac.MustPermissionKey("content", "write")
	for _, permission := range []rbac.Permission{
		{Key: read, Description: "Read content"},
		{Key: write, Description: "Write content"},
	} {
		created, createErr := service.UpsertPermission(ctx, permission)
		require.NoError(t, createErr)
		require.NotEmpty(t, created.PublicID)
		require.False(t, created.CreatedAt.IsZero())
	}

	systemRole, err := service.CreateRole(ctx, rbac.Role{
		Slug:        "super_admin",
		Name:        "Super admin",
		Description: "Built-in administrator",
		System:      true,
	}, []rbac.PermissionKey{read, write})
	require.NoError(t, err)
	require.NotEmpty(t, systemRole.PublicID)
	require.True(t, systemRole.System)

	editorRole, err := service.CreateRole(ctx, rbac.Role{
		Slug:        "editor",
		Name:        "Editor",
		Description: "Content editor",
	}, []rbac.PermissionKey{read})
	require.NoError(t, err)
	_, err = service.CreateRole(ctx, rbac.Role{Slug: "editor", Name: "Duplicate"}, nil)
	require.Error(t, err)

	roles, err := service.Roles(ctx, rbac.RoleFilter{IncludeSystem: true})
	require.NoError(t, err)
	require.Len(t, roles, 2)
	roles, err = service.Roles(ctx, rbac.RoleFilter{
		IDs:           []int64{editorRole.ID},
		Slugs:         []string{editorRole.Slug},
		IncludeSystem: true,
		Search:        "content",
		Limit:         1,
	})
	require.NoError(t, err)
	require.Equal(t, []rbac.Role{editorRole}, roles)
	roles, err = service.Roles(ctx, rbac.RoleFilter{Offset: 1})
	require.NoError(t, err)
	require.Empty(t, roles)
	loadedRole, err := service.Role(ctx, editorRole.ID)
	require.NoError(t, err)
	require.Equal(t, editorRole.PublicID, loadedRole.PublicID)
	_, err = service.Role(ctx, editorRole.ID+10_000)
	require.ErrorIs(t, err, rbac.ErrRoleNotFound)

	permissions, err := service.Permissions(ctx, rbac.PermissionFilter{Domain: "content", Action: "read"})
	require.NoError(t, err)
	require.Len(t, permissions, 1)
	permissions, err = service.Permissions(ctx, rbac.PermissionFilter{
		IDs:  []int64{permissions[0].ID},
		Keys: []rbac.PermissionKey{read},
	})
	require.NoError(t, err)
	require.Len(t, permissions, 1)

	updatedKeys := []rbac.PermissionKey{read, write}
	editorRole.Name = "Senior editor"
	editorRole, err = service.UpdateRole(ctx, editorRole, &updatedKeys)
	require.NoError(t, err)
	require.Equal(t, "Senior editor", editorRole.Name)
	assignedPermissions, err := service.RolePermissions(ctx, editorRole.ID)
	require.NoError(t, err)
	require.Len(t, assignedPermissions, 2)
	require.NoError(t, service.ReplaceRolePermissions(ctx, editorRole.ID, []rbac.PermissionKey{write}))
	assignedPermissions, err = service.RolePermissions(ctx, editorRole.ID)
	require.NoError(t, err)
	require.Len(t, assignedPermissions, 1)
	require.Equal(t, write, assignedPermissions[0].Key)
	require.ErrorIs(
		t,
		service.ReplaceRolePermissions(ctx, editorRole.ID, []rbac.PermissionKey{rbac.MustPermissionKey("missing", "permission")}),
		rbac.ErrPermissionNotFound,
	)
	require.ErrorIs(t, service.ReplaceRolePermissions(ctx, editorRole.ID+10_000, nil), rbac.ErrRoleNotFound)
	_, err = service.RolePermissions(ctx, editorRole.ID+10_000)
	require.ErrorIs(t, err, rbac.ErrRoleNotFound)

	require.NoError(t, service.ReplaceSubjectRoles(
		ctx,
		registered.Account.Subject.ID,
		[]int64{systemRole.ID, editorRole.ID},
	))
	subjectRoles, err := service.SubjectRoles(ctx, registered.Account.Subject.ID)
	require.NoError(t, err)
	require.Len(t, subjectRoles, 2)
	require.True(t, service.Can(ctx, registered.Account.Subject.ID, write))
	require.ErrorIs(
		t,
		service.ReplaceSubjectRoles(ctx, registered.Account.Subject.ID, []int64{editorRole.ID + 10_000}),
		rbac.ErrRoleNotFound,
	)
	require.ErrorIs(
		t,
		service.ReplaceSubjectRoles(ctx, goauth.NewSubjectID(), []int64{editorRole.ID}),
		goauth.ErrAccountNotFound,
	)

	snapshot, err := service.Snapshot(ctx)
	require.NoError(t, err)
	require.Len(t, snapshot.Roles, 2)
	require.Len(t, snapshot.Permissions, 2)
	require.Len(t, snapshot.RolePermissions, 3)
	require.Len(t, snapshot.SubjectRoles, 2)

	systemRole.System = false
	_, err = service.UpdateRole(ctx, systemRole, nil)
	require.ErrorIs(t, err, rbac.ErrSystemRoleProtected)
	require.ErrorIs(t, service.DeleteRole(ctx, systemRole.ID), rbac.ErrSystemRoleProtected)
	require.ErrorIs(t, service.DeleteRole(ctx, systemRole.ID+10_000), rbac.ErrRoleNotFound)
	require.NoError(t, service.DeleteRole(ctx, editorRole.ID))
	_, err = service.Role(ctx, editorRole.ID)
	require.ErrorIs(t, err, rbac.ErrRoleNotFound)
}

func TestPostgresRateLimitAndCleanupCapabilities(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "cleanup.integration@example.test")
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	bucket := goauth.SecretDigest{KeyID: "rate", Digest: bytes.Repeat([]byte{9}, 32)}
	request := goauth.RateLimitRequest{
		SubjectID: registered.Account.Subject.ID,
		Action:    "integration",
		Bucket:    bucket,
		Window:    time.Hour,
		Limit:     1,
		Now:       time.Now().UTC(),
	}
	result, err := store.TakeRateLimit(context.Background(), request)
	require.NoError(t, err)
	require.True(t, result.Allowed)
	result, err = store.TakeRateLimit(context.Background(), request)
	require.NoError(t, err)
	require.False(t, result.Allowed)
	require.False(t, result.RetryAt.IsZero())
	_, err = store.TakeRateLimit(context.Background(), goauth.RateLimitRequest{})
	require.Error(t, err)

	old := time.Now().UTC().Add(-120 * 24 * time.Hour)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO auth_password_reset_records (selector, subject_id, key_id, secret_digest, created_at, expires_at, consumed_at) VALUES ($1, $2, 'old', $3, $4, $4, $4)`, []any{"old-reset", registered.Account.Subject.ID, bytes.Repeat([]byte{1}, 32), old}},
		{`INSERT INTO auth_email_challenges (id, subject_id, identifier_id, purpose, key_id, code_digest, max_attempts, created_at, expires_at, verified_at) VALUES ($1, $2, $3, 'verification', 'old', $4, 5, $5, $5, $5)`, []any{"123e4567-e89b-12d3-a456-426614174201", registered.Account.Subject.ID, registered.Account.PrimaryEmail.ID, bytes.Repeat([]byte{2}, 32), old}},
		{`INSERT INTO auth_email_change_records (id, subject_id, new_display_value, new_normalized_value, key_id, code_digest, max_attempts, created_at, expires_at, consumed_at) VALUES ($1, $2, 'old@example.test', 'old@example.test', 'old', $3, 5, $4, $4, $4)`, []any{"123e4567-e89b-12d3-a456-426614174202", registered.Account.Subject.ID, bytes.Repeat([]byte{3}, 32), old}},
		{`INSERT INTO auth_rate_limit_events (subject_id, key_id, bucket_digest, action, occurred_at) VALUES ($1, 'old', $2, 'old', $3)`, []any{registered.Account.Subject.ID, bytes.Repeat([]byte{4}, 32), old}},
		{`INSERT INTO auth_security_audit_events (id, subject_id, event_type, occurred_at) VALUES ($1, $2, 'old', $3)`, []any{"123e4567-e89b-12d3-a456-426614174203", registered.Account.Subject.ID, old}},
	}
	for _, statement := range statements {
		_, err := db.Exec(statement.query, statement.args...)
		require.NoError(t, err)
	}
	cleanup, err := runtime.Cleanup(context.Background(), postgres.CleanupPolicy{})
	require.NoError(t, err)
	require.Positive(t, cleanup.PasswordResets)
	require.Positive(t, cleanup.EmailChallenges)
	require.Positive(t, cleanup.EmailChanges)
	require.Positive(t, cleanup.RateEvents)
	require.Positive(t, cleanup.AuditEvents)
	_, err = runtime.Cleanup(context.Background(), postgres.CleanupPolicy{RateEventRetention: time.Hour})
	require.Error(t, err)
}

func TestPostgresAdapterValidationAndDSNOwnership(t *testing.T) {
	_, err := postgres.NewStore(nil)
	require.EqualError(t, err, "PostgreSQL database is required")
	_, err = postgres.NewRBAC(nil, nil)
	require.EqualError(t, err, "PostgreSQL database is required")
	_, err = postgres.NewRuntime(postgres.Config{})
	require.EqualError(t, err, "PostgreSQL DB or DSN is required")
	require.ErrorIs(t, postgres.Down(context.Background(), nil, postgres.ResetConfirmation("wrong")), postgres.ErrResetConfirmationRequired)
	require.Error(t, postgres.Down(context.Background(), nil, postgres.ConfirmResetAuthState))

	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db), "Migrate must be idempotent on v0.2")
	require.NoError(t, runtime.Close(), "borrowed DB must not be closed")
	_, err = postgres.NewRuntime(postgres.Config{DB: db})
	require.Error(t, err, "an invalid Runtime config must fail after the database adapter is assembled")

	autoMigrateConfig := runtimeConfig(t)
	autoMigrated, err := postgres.NewRuntime(postgres.Config{
		DB:                 db,
		AutoMigrate:        true,
		Runtime:            autoMigrateConfig,
		NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)
	require.NoError(t, autoMigrated.Close())
	_, err = postgres.NewRuntime(postgres.Config{
		DSN:               "postgres://goauth:goauth@127.0.0.1:1/unreachable?sslmode=disable",
		ConnectionTimeout: time.Millisecond,
	})
	require.Error(t, err)

	dsn := os.Getenv("GOAUTH_TEST_POSTGRES_DSN")
	config := runtimeConfig(t)
	owned, err := postgres.NewRuntime(postgres.Config{DSN: dsn, Runtime: config, NotificationSender: integrationNotificationSender()})
	require.NoError(t, err)
	require.NoError(t, owned.Close())

	resetSchema(t, db)
	_, err = db.Exec(`CREATE TABLE auth_subjects (id UUID PRIMARY KEY, email TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = postgres.NewRuntime(postgres.Config{DB: db, AutoMigrate: true, Runtime: runtimeConfig(t), NotificationSender: integrationNotificationSender()})
	require.ErrorIs(t, err, postgres.ErrLegacySchemaRequiresReset)
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
}

func TestPostgresTypedStoreOutcomes(t *testing.T) {
	db := integrationDB(t)
	runtime, _, _ := integrationRuntime(t, db)
	registered := register(t, runtime, "typed.outcomes@example.test")
	store, err := postgres.NewStore(db)
	require.NoError(t, err)

	_, err = store.GetAccount(context.Background(), goauth.NewSubjectID())
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = store.GetLocalAccount(context.Background(), goauth.NewSubjectID())
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = store.UpdateBasicProfile(
		context.Background(),
		goauth.NewSubjectID(),
		goauth.BasicProfile{Username: "missing"},
		time.Now().UTC(),
	)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = store.ChangePassword(context.Background(), goauth.PasswordChangeStoreRequest{})
	require.Error(t, err)
	missingPasswordChange, err := store.ChangePassword(context.Background(), goauth.PasswordChangeStoreRequest{
		SubjectID:           goauth.NewSubjectID(),
		ExpectedPasswordPHC: "$argon2id$missing",
		NewPasswordPHC:      "$argon2id$new",
		Now:                 time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordChangeStoreMissing, missingPasswordChange.Status)
	passwordOutcomeAccount := register(t, runtime, "password.store.outcomes@example.test")
	passwordOutcomeLocal, err := store.GetLocalAccount(context.Background(), passwordOutcomeAccount.Account.Subject.ID)
	require.NoError(t, err)
	conflictedPasswordChange, err := store.ChangePassword(context.Background(), goauth.PasswordChangeStoreRequest{
		SubjectID:           passwordOutcomeAccount.Account.Subject.ID,
		ExpectedPasswordPHC: "$argon2id$concurrent-value",
		NewPasswordPHC:      "$argon2id$new-value",
		Now:                 time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordChangeStoreConflict, conflictedPasswordChange.Status)
	_, err = store.SetSubjectStatus(
		context.Background(),
		passwordOutcomeAccount.Account.Subject.ID,
		goauth.SubjectStatusDisabled,
		time.Now().UTC(),
	)
	require.NoError(t, err)
	_, err = store.ChangePassword(context.Background(), goauth.PasswordChangeStoreRequest{
		SubjectID:           passwordOutcomeAccount.Account.Subject.ID,
		ExpectedPasswordPHC: passwordOutcomeLocal.PasswordPHC,
		NewPasswordPHC:      "$argon2id$new-value",
		Now:                 time.Now().UTC(),
	})
	require.ErrorIs(t, err, goauth.ErrAccountUnavailable)
	require.Error(t, store.CreateSession(context.Background(), goauth.SessionRecord{}))
	revoked, err := store.RevokeSession(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.NewSubjectID().String(),
		time.Now().UTC(),
	)
	require.NoError(t, err)
	require.False(t, revoked)
	revokedAll, err := store.RevokeSubjectSessions(context.Background(), goauth.NewSubjectID(), time.Now().UTC())
	require.NoError(t, err)
	require.Zero(t, revokedAll)
	_, err = store.SetSubjectStatus(
		context.Background(),
		goauth.NewSubjectID(),
		goauth.SubjectStatusDisabled,
		time.Now().UTC(),
	)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	unchanged, err := store.SetSubjectStatus(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.SubjectStatusActive,
		time.Now().UTC(),
	)
	require.NoError(t, err)
	require.Equal(t, int64(1), unchanged.SecurityVersion)
	_, err = store.IntrospectSession(context.Background(), goauth.NewSubjectID().String())
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)

	require.Error(t, store.CreatePasswordReset(context.Background(), goauth.PasswordResetRecord{}))
	digest := goauth.SecretDigest{KeyID: "test", Digest: bytes.Repeat([]byte{7}, 32)}
	missingReset, err := store.ConsumePasswordReset(context.Background(), goauth.PasswordResetConsumeRequest{
		Selector: "missing", Digest: digest, PasswordPHC: "$argon2id$test", Now: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordResetInvalid, missingReset.Status)
	require.NoError(t, store.CreatePasswordReset(context.Background(), goauth.PasswordResetRecord{
		SubjectID:               registered.Account.Subject.ID,
		Selector:                "expired-reset",
		Digest:                  digest,
		ExpectedNormalizedEmail: registered.Account.PrimaryEmail.NormalizedValue,
		ExpectedSecurityVersion: registered.Account.Subject.SecurityVersion,
		CreatedAt:               time.Now().UTC().Add(-time.Hour),
		ExpiresAt:               time.Now().UTC().Add(-time.Minute),
	}))
	expiredReset, err := store.ConsumePasswordReset(context.Background(), goauth.PasswordResetConsumeRequest{
		Selector: "expired-reset", Digest: digest, PasswordPHC: "$argon2id$test", Now: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordResetExpired, expiredReset.Status)
	resetAccount := register(t, runtime, "used.reset@example.test")
	usedDigest := goauth.SecretDigest{KeyID: "used", Digest: bytes.Repeat([]byte{8}, 32)}
	require.NoError(t, store.CreatePasswordReset(context.Background(), goauth.PasswordResetRecord{
		SubjectID:               resetAccount.Account.Subject.ID,
		Selector:                "used-reset",
		Digest:                  usedDigest,
		ExpectedNormalizedEmail: resetAccount.Account.PrimaryEmail.NormalizedValue,
		ExpectedSecurityVersion: resetAccount.Account.Subject.SecurityVersion,
		CreatedAt:               time.Now().UTC(),
		ExpiresAt:               time.Now().UTC().Add(time.Hour),
	}))
	invalidReset, err := store.ConsumePasswordReset(context.Background(), goauth.PasswordResetConsumeRequest{
		Selector: "used-reset",
		Digest: goauth.SecretDigest{
			KeyID:  "wrong-key",
			Digest: bytes.Repeat([]byte{8}, 32),
		},
		PasswordPHC: "$argon2id$test",
		Now:         time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordResetInvalid, invalidReset.Status)
	consumedReset, err := store.ConsumePasswordReset(context.Background(), goauth.PasswordResetConsumeRequest{
		Selector: "used-reset", Digest: usedDigest, PasswordPHC: "$argon2id$test", Now: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordResetConsumed, consumedReset.Status)
	usedReset, err := store.ConsumePasswordReset(context.Background(), goauth.PasswordResetConsumeRequest{
		Selector: "used-reset", Digest: usedDigest, PasswordPHC: "$argon2id$test", Now: time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.PasswordResetUsed, usedReset.Status)

	missingChallenge, err := store.VerifyEmailChallenge(context.Background(), goauth.EmailChallengeVerifyRequest{
		SubjectID: registered.Account.Subject.ID,
		Purpose:   goauth.EmailChallengePurposeVerification,
		Digests:   []goauth.SecretDigest{digest},
		Now:       time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChallengeInvalid, missingChallenge.Status)
	_, err = store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{}, goauth.EmailChallengeLimits{})
	require.Error(t, err)
	require.NoError(t, runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	require.ErrorIs(
		t,
		runtime.SendEmailChallenge(
			context.Background(),
			registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification,
		),
		goauth.ErrConfirmationResendDelay,
	)
	expiredChallengeDigest := goauth.SecretDigest{KeyID: "expired", Digest: bytes.Repeat([]byte{4}, 32)}
	expiredRateDigest := goauth.SecretDigest{KeyID: "expired-rate", Digest: bytes.Repeat([]byte{5}, 32)}
	expiredChallengeAccount := register(t, runtime, "expired.challenge@example.test")
	expiredAt := time.Now().UTC().Add(-time.Minute)
	issued, err := store.IssueEmailChallenge(context.Background(), goauth.EmailChallengeRecord{
		ID:           goauth.NewSubjectID().String(),
		SubjectID:    expiredChallengeAccount.Account.Subject.ID,
		IdentifierID: expiredChallengeAccount.Account.PrimaryEmail.ID,
		Purpose:      goauth.EmailChallengePurposeVerification,
		Digest:       expiredChallengeDigest,
		RateDigest:   expiredRateDigest,
		MaxAttempts:  5,
		CreatedAt:    expiredAt.Add(-10 * time.Minute),
		ExpiresAt:    expiredAt,
	}, goauth.EmailChallengeLimits{MinResendInterval: time.Minute, PerHour: 5, PerDay: 10})
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChallengeIssued, issued.Status)
	expiredChallenge, err := store.VerifyEmailChallenge(context.Background(), goauth.EmailChallengeVerifyRequest{
		SubjectID: expiredChallengeAccount.Account.Subject.ID,
		Purpose:   goauth.EmailChallengePurposeVerification,
		Digests:   []goauth.SecretDigest{expiredChallengeDigest},
		Now:       time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChallengeExpired, expiredChallenge.Status)
	_, err = store.IssueEmailChange(context.Background(), goauth.EmailChangeRecord{}, goauth.EmailChallengeLimits{})
	require.Error(t, err)
	_, err = store.GetPendingEmailChange(context.Background(), registered.Account.Subject.ID, time.Now().UTC())
	require.ErrorIs(t, err, goauth.ErrEmailChangeNotFound)
	missingEmailChange, err := store.VerifyEmailChange(context.Background(), goauth.EmailChangeVerifyRequest{
		SubjectID: registered.Account.Subject.ID,
		Digests:   []goauth.SecretDigest{digest},
		Now:       time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.EmailChangeNotFound, missingEmailChange.Status)

	parts := strings.Split(registered.Tokens.RefreshToken, ".")
	require.Len(t, parts, 3)
	invalidRotation, err := store.RotateRefresh(context.Background(), goauth.RefreshRotationRequest{})
	require.NoError(t, err)
	require.Equal(t, goauth.RefreshRotationInvalid, invalidRotation.Status)
	missingRotation, err := store.RotateRefresh(context.Background(), goauth.RefreshRotationRequest{
		CurrentSelector: "missing",
		CurrentDigest:   digest,
		NextSelector:    "missing-next",
		NextDigest:      digest,
		NextExpiresAt:   time.Now().UTC().Add(time.Hour),
		Now:             time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.RefreshRotationInvalid, missingRotation.Status)
	rotation, err := store.RotateRefresh(context.Background(), goauth.RefreshRotationRequest{
		CurrentSelector: parts[1],
		CurrentDigest:   goauth.SecretDigest{KeyID: parts[0], Digest: bytes.Repeat([]byte{9}, 32)},
		NextSelector:    "invalid-next",
		NextDigest:      digest,
		NextExpiresAt:   time.Now().UTC().Add(time.Hour),
		Now:             time.Now().UTC(),
	})
	require.NoError(t, err)
	require.Equal(t, goauth.RefreshRotationInvalid, rotation.Status)
	_, err = runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.NoError(t, err, "a digest mismatch must not consume the real refresh token")

	registeredExpired := register(t, runtime, "expired.refresh@example.test")
	expiredParts := strings.Split(registeredExpired.Tokens.RefreshToken, ".")
	require.Len(t, expiredParts, 3)
	_, err = db.Exec(`UPDATE auth_refresh_tokens SET expires_at = now() - interval '1 minute' WHERE selector = $1`, expiredParts[1])
	require.NoError(t, err)
	_, err = runtime.Refresh(context.Background(), registeredExpired.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrExpiredToken)

	_, _, err = store.CreateSSOAccount(context.Background(), goauth.SSOAccountRecord{})
	require.Error(t, err)
	require.Error(t, store.RecordSecurityEvent(context.Background(), goauth.SecurityEvent{}))
	require.Error(t, postgres.Migrate(context.Background(), nil))
}

func TestPostgresLifecycleStoreFailsClosedWhenDatabaseIsUnavailable(t *testing.T) {
	dsn := os.Getenv("GOAUTH_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_TEST_POSTGRES_DSN is not configured")
	}
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	require.NoError(t, db.Close())
	store, err := postgres.NewStore(db)
	require.NoError(t, err)
	now := time.Now().UTC()
	subjectID := goauth.NewSubjectID()
	digest := goauth.SecretDigest{KeyID: "closed", Digest: bytes.Repeat([]byte{5}, 32)}

	_, err = store.UpdateBasicProfile(
		context.Background(),
		subjectID,
		goauth.BasicProfile{Username: "closed"},
		now,
	)
	require.Error(t, err)
	_, err = store.ChangePassword(context.Background(), goauth.PasswordChangeStoreRequest{
		SubjectID:           subjectID,
		ExpectedPasswordPHC: "$argon2id$current",
		NewPasswordPHC:      "$argon2id$next",
		Now:                 now,
	})
	require.Error(t, err)
	_, err = store.RevokeSession(context.Background(), subjectID, goauth.NewSubjectID().String(), now)
	require.Error(t, err)
	_, err = store.RevokeSubjectSessions(context.Background(), subjectID, now)
	require.Error(t, err)
	_, err = store.IssueEmailChange(context.Background(), goauth.EmailChangeRecord{
		ID:                 goauth.NewSubjectID().String(),
		SubjectID:          subjectID,
		NewDisplayValue:    "closed@example.test",
		NewNormalizedValue: "closed@example.test",
		Digest:             digest,
		RateDigest:         digest,
		MaxAttempts:        5,
		CreatedAt:          now,
		ExpiresAt:          now.Add(time.Minute),
	}, goauth.EmailChallengeLimits{MinResendInterval: time.Minute, PerHour: 5, PerDay: 10})
	require.Error(t, err)
	_, err = store.GetPendingEmailChange(context.Background(), subjectID, now)
	require.Error(t, err)
	_, err = store.VerifyEmailChange(context.Background(), goauth.EmailChangeVerifyRequest{
		SubjectID: subjectID,
		Digests:   []goauth.SecretDigest{digest},
		Now:       now,
	})
	require.Error(t, err)
}

func integrationRuntime(
	t *testing.T,
	db *sql.DB,
) (*postgres.Runtime, *integrationEventObserver, goauth.KeyRing) {
	t.Helper()
	resetSchema(t, db)
	require.NoError(t, postgres.Migrate(context.Background(), db))
	config := runtimeConfig(t)
	events := &integrationEventObserver{t: t, db: db}
	runtime, err := postgres.NewRuntime(postgres.Config{
		DB:                 db,
		Runtime:            config,
		NotificationSender: integrationNotificationSender(),
	})
	require.NoError(t, err)

	return runtime, events, config.OutboxAEADKeys
}

// integrationEventObserver reads committed encrypted deliveries without running
// the worker, keeping notification assertions independent of delivery timing.
type integrationEventObserver struct {
	t  *testing.T
	db *sql.DB
}

func (observer *integrationEventObserver) Events() []goauth.EncryptedEvent {
	observer.t.Helper()
	rows, err := observer.db.QueryContext(context.Background(), `
SELECT id, subject_id, event_type, reference_id, valid_until,
       key_id, nonce, ciphertext, additional_data, created_at, delete_after
FROM auth_notification_deliveries
WHERE ciphertext IS NOT NULL
ORDER BY created_at, id`)
	require.NoError(observer.t, err)
	defer func() { require.NoError(observer.t, rows.Close()) }()
	var events []goauth.EncryptedEvent
	for rows.Next() {
		var event goauth.EncryptedEvent
		require.NoError(observer.t, rows.Scan(
			&event.ID, &event.SubjectID, &event.Type, &event.ReferenceID, &event.ValidUntil,
			&event.Envelope.KeyID, &event.Envelope.Nonce, &event.Envelope.Ciphertext,
			&event.Envelope.AdditionalData, &event.Envelope.CreatedAt, &event.Envelope.DeleteAfter,
		))
		events = append(events, event)
	}
	require.NoError(observer.t, rows.Err())
	return events
}

func integrationNotificationSender() goauth.NotificationSender {
	return goauth.NotificationSenderFunc(func(context.Context, goauth.NotificationDelivery) error {
		return nil
	})
}

func runtimeConfig(t *testing.T) goauth.Config {
	t.Helper()
	return goauth.Config{
		Signing:        goauth.SigningConfig{Issuer: "https://auth.example.test", Audience: "integration", Keys: keyRing(t, "jwt", 1)},
		TokenHMACKeys:  keyRing(t, "token", 2),
		OutboxAEADKeys: keyRing(t, "outbox", 3),
		URLBuilder: goauth.URLBuilderFunc(func(_ context.Context, token string) (string, error) {
			return "https://app.example.test/reset-password?token=" + url.QueryEscape(token), nil
		}),
		MembershipGate: goauth.MembershipGateFunc(func(context.Context, goauth.Realm, goauth.Account) error {
			return nil
		}),
		ResetResponseFloor: time.Nanosecond,
	}
}

type oidcClientStoreStub struct{}

func (oidcClientStoreStub) Get(context.Context, string) (oidc.Client, error) {
	return oidc.Client{}, errors.New("not configured")
}

type oidcRequestStoreStub struct{}

func (oidcRequestStoreStub) Save(context.Context, oidc.AuthorizationRequest) error { return nil }
func (oidcRequestStoreStub) Get(context.Context, string) (oidc.AuthorizationRequest, error) {
	return oidc.AuthorizationRequest{}, oidc.ErrAuthorizationRequestNotFound
}

func (oidcRequestStoreStub) Consume(context.Context, string) (oidc.AuthorizationRequest, error) {
	return oidc.AuthorizationRequest{}, oidc.ErrAuthorizationRequestNotFound
}

type oidcCodeStoreStub struct{}

func (oidcCodeStoreStub) Save(context.Context, oidc.AuthorizationCode) error { return nil }
func (oidcCodeStoreStub) Consume(context.Context, string) (oidc.AuthorizationCode, error) {
	return oidc.AuthorizationCode{}, oidc.ErrAuthorizationCodeNotFound
}

type oidcKeyStoreStub struct {
	key *rsa.PrivateKey
}

func (s oidcKeyStoreStub) Active(context.Context) (oidc.SigningKey, error) {
	return oidc.SigningKey{ID: "test-key", Algorithm: "RS256", PrivateKey: s.key, PublicKey: &s.key.PublicKey}, nil
}

func (s oidcKeyStoreStub) Get(context.Context, string) (oidc.SigningKey, error) {
	return s.Active(context.Background())
}

func (oidcKeyStoreStub) Public(context.Context) ([]oidc.JWK, error) { return nil, nil }

func integrationDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("GOAUTH_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GOAUTH_TEST_POSTGRES_DSN is not configured")
	}
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	require.NoError(t, db.PingContext(context.Background()))
	t.Cleanup(func() { _ = db.Close() })

	return db
}

func resetSchema(t *testing.T, db *sql.DB) {
	t.Helper()
	require.NoError(t, postgres.Down(context.Background(), db, postgres.ConfirmResetAuthState))
}

func keyRing(t *testing.T, id string, fill byte) goauth.KeyRing {
	t.Helper()
	ring, err := goauth.NewKeyRing(id+"-v1", goauth.Key{ID: id + "-v1", Material: bytes.Repeat([]byte{fill}, 32)})
	require.NoError(t, err)

	return ring
}

func register(t *testing.T, runtime *postgres.Runtime, email string) goauth.RegisterResult {
	t.Helper()
	result, err := runtime.Register(context.Background(), goauth.RegisterRequest{
		Email:    email,
		Password: "Integration-Unique-Passphrase-1",
	})
	require.NoError(t, err)

	return result
}

func login(email, password string) goauth.LoginRequest {
	return goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: email},
			Password:   password,
		},
		Realm: goauth.RealmUser,
	}
}

func integrationNotificationCode(
	t *testing.T,
	runtime *postgres.Runtime,
	events *integrationEventObserver,
	eventType string,
) string {
	t.Helper()
	queued := events.Events()
	for index := len(queued) - 1; index >= 0; index-- {
		if queued[index].Type != eventType {
			continue
		}
		notification, err := runtime.DecryptNotificationEvent(queued[index])
		require.NoError(t, err)
		code := notification.Data["code"]
		require.Len(t, code, 6)

		return code
	}
	t.Fatalf("%s notification was not emitted", eventType)

	return ""
}

func differentIntegrationCode(code string) string {
	if code != "000000" {
		return "000000"
	}

	return "999999"
}
