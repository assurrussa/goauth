package goauth_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

// Synthetic test password, never a deployed credential.
const preparedReplacement = "Prepared-Account-Password-42"

func preparedChangeFixture(t *testing.T, options ...testkit.RuntimeOption) (*testkit.Fixture, goauth.Account) {
	t.Helper()
	f := localIdentityFixture(t, options...)
	account, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "prepared.change@example.test", Password: testPassword,
	})
	require.NoError(t, err)
	return f, account
}

func prepareChange(t *testing.T, f *testkit.Fixture, account goauth.Account) *goauth.PreparedPasswordChange {
	t.Helper()
	proof, err := f.Runtime.PreparePasswordChange(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: testPassword, NewPassword: preparedReplacement,
	})
	require.NoError(t, err)
	return proof
}

func TestPreparedPasswordChangeBindsRuntimeSubjectAndExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f, account := preparedChangeFixture(t, func(c *goauth.Config) { c.Now = func() time.Time { return now } })
	proof := prepareChange(t, f, account)
	foreign := localIdentityFixture(t)
	for _, tc := range []struct {
		runtime *goauth.Runtime
		subject goauth.SubjectID
		proof   *goauth.PreparedPasswordChange
	}{
		{foreign.Runtime, account.Subject.ID, proof},
		{f.Runtime, goauth.NewSubjectID(), proof},
		{f.Runtime, account.Subject.ID, nil},
		{f.Runtime, account.Subject.ID, &goauth.PreparedPasswordChange{}},
	} {
		result, err := tc.runtime.CompletePasswordChange(t.Context(), tc.subject, tc.proof)
		require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
		require.Zero(t, result)
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, value := range []any{proof, *proof} {
			output := fmt.Sprintf(format, value)
			require.NotContains(t, output, "argon2")
			require.NotContains(t, output, preparedReplacement)
			require.Equal(t, "[prepared password change]", output)
		}
	}
	now = now.Add(5 * time.Minute)
	result, err := f.Runtime.CompletePasswordChange(t.Context(), account.Subject.ID, proof)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	require.Zero(t, result)
	stored, err := f.Store.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, account.Subject.SecurityVersion, stored.Subject.SecurityVersion)
}

func TestPreparedPasswordChangeComposesAndRollsBack(t *testing.T) {
	for _, failureStage := range []string{"none", testAuditStage, testNotificationStage, testHostStage} {
		t.Run(failureStage, func(t *testing.T) {
			failure := errors.New("prepared change injected failure")
			var transaction goauth.AuthTransaction
			f, account := preparedChangeFixture(t, func(c *goauth.Config) {
				transaction = c.AuthTransaction
				if failureStage == testAuditStage {
					base := c.AuditSink
					c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
						if event.Type == goauth.SecurityEventPasswordChanged {
							return failure
						}
						return base.RecordSecurityEvent(ctx, event)
					})
				}
				if failureStage == testNotificationStage {
					c.NotificationRenderer = goauth.NotificationRendererFunc(func(context.Context, goauth.Notification) ([]byte, error) {
						return nil, failure
					})
				}
			})
			before, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			proof := prepareChange(t, f, account)
			err = transaction.InAuthTransaction(t.Context(), func(ctx context.Context) error {
				_, e := f.Runtime.CompletePasswordChange(ctx, account.Subject.ID, proof)
				if e != nil {
					return e
				}
				if failureStage == testHostStage {
					return failure
				}
				return nil
			})
			after, readErr := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, readErr)
			if failureStage != "none" {
				require.ErrorIs(t, err, failure)
				require.Equal(t, before, after)
				require.Empty(t, f.Events.Events())
				return
			}
			require.NoError(t, err)
			require.Equal(t, account.Subject.SecurityVersion+1, after.Account.Subject.SecurityVersion)
			require.NotEqual(t, before.PasswordPHC, after.PasswordPHC)
			require.Len(t, f.Events.Events(), 1)
			_, err = f.Runtime.CompletePasswordChange(t.Context(), account.Subject.ID, proof)
			require.ErrorIs(t, err, goauth.ErrPasswordChangeConflict)
		})
	}
}

func TestPreparedPasswordChangeAdmissionPrecedesOuterTransaction(t *testing.T) {
	var transaction goauth.AuthTransaction
	f, account := preparedChangeFixture(t, func(c *goauth.Config) {
		transaction = c.AuthTransaction
		c.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
	})
	proof := prepareChange(t, f, account)
	require.NoError(t, transaction.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, err := f.Runtime.CompletePasswordChange(ctx, account.Subject.ID, proof)
		return err
	}))
	_, err := f.Runtime.PreparePasswordChange(t.Context(), goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: preparedReplacement, NewPassword: testPassword,
	})
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}

func TestPreparedPasswordChangeRejectsHashTimeSecurityChanges(t *testing.T) {
	for _, mutation := range []string{localCheckerBuiltinPassword, atomicityStatus, testLogoutOperation} {
		t.Run(mutation, func(t *testing.T) {
			base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
			require.NoError(t, err)
			hasher := &trustedSetHookHasher{PasswordHasher: base}
			f, account := preparedChangeFixture(t, func(c *goauth.Config) {
				c.EnableLegacyBytes256 = false
				c.PasswordHasher = hasher
			})
			hasher.hook = func() {
				hasher.hook = nil
				switch mutation {
				case localCheckerBuiltinPassword:
					_, err = f.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
						SubjectID: account.Subject.ID, CurrentPassword: testPassword, NewPassword: "Different-Security-Winner-42",
					})
				case atomicityStatus:
					_, err = f.Runtime.SetSubjectStatus(t.Context(), account.Subject.ID, goauth.SubjectStatusDisabled)
				default:
					_, err = f.Runtime.LogoutAll(t.Context(), account.Subject.ID)
				}
				require.NoError(t, err)
			}
			proof := prepareChange(t, f, account)
			changed, err := f.Runtime.CompletePasswordChange(t.Context(), account.Subject.ID, proof)
			require.Error(t, err)
			require.Zero(t, changed)
			stored, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.EqualValues(t, 2, stored.Account.Subject.SecurityVersion)
			require.Error(t, base.VerifyPassword(stored.PasswordPHC, preparedReplacement))
		})
	}
}

type preparedChangeLockStore struct {
	goauth.RuntimeStore
	afterLock func()
}

func (s *preparedChangeLockStore) LockAccount(ctx context.Context, subject goauth.SubjectID) (goauth.Account, error) {
	account, err := s.RuntimeStore.LockAccount(ctx, subject)
	if s.afterLock != nil {
		s.afterLock()
	}
	return account, err
}

func TestPreparedPasswordChangeExpiryRecheckedAfterLock(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var store *preparedChangeLockStore
	f, account := preparedChangeFixture(t, func(c *goauth.Config) {
		c.Now = func() time.Time { return now }
		store = &preparedChangeLockStore{RuntimeStore: c.Store}
		c.Store = store
	})
	proof := prepareChange(t, f, account)
	store.afterLock = func() { now = now.Add(5 * time.Minute) }
	changed, err := f.Runtime.CompletePasswordChange(t.Context(), account.Subject.ID, proof)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	require.Zero(t, changed)
}

func TestPreparedPasswordChangeConcurrentConsumption(t *testing.T) {
	f, account := preparedChangeFixture(t)
	proof := prepareChange(t, f, account)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.Runtime.CompletePasswordChange(t.Context(), account.Subject.ID, proof)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			require.ErrorIs(t, err, goauth.ErrPasswordChangeConflict)
		}
	}
	require.Equal(t, 1, successes)
	require.Len(t, f.Events.Events(), 1)
}

func TestPreparedPasswordChangeValidationAndDenialDoNotWrite(t *testing.T) {
	for _, tc := range []struct {
		current, replacement string
		want                 error
	}{
		{"wrong password", preparedReplacement, goauth.ErrCurrentPasswordInvalid},
		{testPassword, testPassword, goauth.ErrPasswordUnchanged},
		{testPassword, testShortPassword, goauth.ErrInvalidPassword},
		{testPassword, strings.Repeat("x", 129), goauth.ErrInvalidPassword},
	} {
		f, account := preparedChangeFixture(t)
		before, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
		require.NoError(t, err)
		proof, err := f.Runtime.PreparePasswordChange(t.Context(), goauth.ChangePasswordRequest{
			SubjectID: account.Subject.ID, CurrentPassword: tc.current, NewPassword: tc.replacement,
		})
		require.ErrorIs(t, err, tc.want)
		require.Nil(t, proof)
		after, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
		require.NoError(t, err)
		require.Equal(t, before, after)
		require.Empty(t, f.Events.Events())
	}
}

func TestPreparedPasswordChangeIssuerNeverOwnsAccountOrNotification(t *testing.T) {
	f, account := preparedChangeFixture(t)
	strong, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{MemoryKiB: 65536, Iterations: 3})
	require.NoError(t, err)
	issuer := localIdentityFixture(t, func(c *goauth.Config) {
		c.EnableLegacyBytes256 = false
		c.PasswordHasher = strong
		c.NotificationDelivery = goauth.NotificationDeliveryDisabled
		c.EventSink = nil
		c.URLBuilder = nil
		c.OutboxAEADKeys = goauth.KeyRing{}
	})
	request := goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: testPassword, NewPassword: preparedReplacement,
	}
	proof, err := f.Runtime.PreparePasswordChangeWithIssuer(t.Context(), request, nil)
	require.ErrorIs(t, err, goauth.ErrPasswordVerificationUnavailable)
	require.Nil(t, proof)
	proof, err = f.Runtime.PreparePasswordChangeWithIssuer(t.Context(), request, issuer.Runtime)
	require.NoError(t, err)
	_, err = issuer.Runtime.CompletePasswordChange(t.Context(), account.Subject.ID, proof)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid, "issuer never owns verification proof")
	changed, err := f.Runtime.CompletePasswordChange(t.Context(), account.Subject.ID, proof)
	require.NoError(t, err)
	require.Equal(t, account.Subject.SecurityVersion+1, changed.Subject.SecurityVersion)
	record, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(record.PasswordPHC, "$argon2id$v=19$m=65536,t=3,p=1$"))
	require.Len(t, f.Events.Events(), 1, "verifier delivery configuration remains authoritative")
	require.Empty(t, issuer.Events.Events())
	_, err = issuer.Runtime.GetAccount(t.Context(), account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound, "issuer storage is unrelated and untouched")
	_, err = f.Runtime.VerifyCredential(t.Context(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: account.PrimaryEmail.DisplayValue},
		Password:   preparedReplacement,
	})
	require.NoError(t, err, "mixed verifier must still accept strong Unicode credentials")
}

func TestPreparedPasswordChangeWrongPasswordSpendsDurableAdmission(t *testing.T) {
	f, account := preparedChangeFixture(t, func(c *goauth.Config) {
		c.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
	})
	request := goauth.ChangePasswordRequest{
		SubjectID: account.Subject.ID, CurrentPassword: "wrong-password", NewPassword: preparedReplacement,
	}
	_, err := f.Runtime.PreparePasswordChange(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrCurrentPasswordInvalid)
	request.CurrentPassword = testPassword
	_, err = f.Runtime.PreparePasswordChange(t.Context(), request)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}
