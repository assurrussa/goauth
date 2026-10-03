package goauth_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const trustedSetPassword = "Trusted-Set-Passphrase-42"

func TestTrustedLocalPasswordPreservesStatusAndAlwaysAdvances(t *testing.T) {
	for _, status := range []goauth.SubjectStatus{
		goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled,
	} {
		t.Run(string(status), func(t *testing.T) {
			var audited []goauth.SecurityEvent
			f := localIdentityFixture(t, func(c *goauth.Config) {
				base := c.AuditSink
				c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
					if event.Type == goauth.SecurityEventTrustedLocalPasswordSet {
						audited = append(audited, event)
					}
					return base.RecordSecurityEvent(ctx, event)
				})
			})
			request := localIdentityImport(trustedSetPassword)
			request.Status = status
			original, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
			require.NoError(t, err)
			for version := int64(2); version <= 3; version++ {
				before, err := f.Store.GetLocalAccount(t.Context(), original.Subject.ID)
				require.NoError(t, err)
				account, err := f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
					SubjectID: original.Subject.ID, NewPassword: trustedSetPassword,
				})
				require.NoError(t, err)
				require.Equal(t, status, account.Subject.Status)
				require.Equal(t, version, account.Subject.SecurityVersion)
				require.Equal(t, original.Subject.CreatedAt, account.Subject.CreatedAt)
				require.Equal(t, original.Profile, account.Profile)
				require.Zero(t, account.PrimaryEmail)
				after, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
				require.NoError(t, err)
				require.Equal(t, goauth.PasswordInputPolicyUnicode, after.PasswordInputPolicy)
				require.NotEqual(t, before.PasswordPHC, after.PasswordPHC)
				hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
				require.NoError(t, err)
				require.NoError(t, hasher.VerifyPassword(after.PasswordPHC, trustedSetPassword))
			}
			require.Len(t, audited, 2)
			for _, event := range audited {
				require.Equal(t, original.Subject.ID, event.SubjectID)
				require.Empty(t, event.Attributes)
			}
			require.Empty(t, f.Events.Events())
		})
	}
}

func TestTrustedLocalPasswordRequiresExistingCredentialAndStrictIssuance(t *testing.T) {
	f := newFixture(t)
	sso, err := f.Runtime.ResolveExternalIdentity(t.Context(), goauth.ExternalIdentity{
		Issuer: testOIDCIssuer, Subject: "trusted-set-sso", Email: "sso.set@example.test", EmailVerified: true,
	})
	require.NoError(t, err)
	for _, id := range []goauth.SubjectID{goauth.NilSubjectID, goauth.NewSubjectID(), sso.Subject.ID} {
		account, err := f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
			SubjectID: id, NewPassword: trustedSetPassword,
		})
		require.ErrorIs(t, err, goauth.ErrAccountNotFound)
		require.Zero(t, account)
	}
	_, err = f.Store.GetLocalAccount(t.Context(), sso.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	account, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "strict.set@example.test", Password: testPassword,
	})
	require.NoError(t, err)
	before, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	for _, password := range []string{"mini", strings.Repeat("x", 129), string([]byte{0xff}), "qwerty123"} {
		changed, err := f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
			SubjectID: account.Subject.ID, NewPassword: password,
		})
		require.Error(t, err)
		require.Zero(t, changed)
	}
	after, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
}

type trustedSetUnsupportedStore struct{ goauth.RuntimeStore }

func TestTrustedLocalPasswordUnsupportedStore(t *testing.T) {
	f := localIdentityFixture(t, func(c *goauth.Config) { c.Store = trustedSetUnsupportedStore{c.Store} })
	account, err := f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: goauth.NewSubjectID(), NewPassword: trustedSetPassword,
	})
	require.ErrorIs(t, err, goauth.ErrTrustedLocalPasswordUnsupported)
	require.Zero(t, account)
}

func TestTrustedLocalPasswordNotificationPolicy(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "required", true: "delivery off"}[disabled], func(t *testing.T) {
			var audits int
			f := localIdentityFixture(t, func(c *goauth.Config) {
				if disabled {
					c.NotificationDelivery = goauth.NotificationDeliveryDisabled
					c.EventSink = nil
					c.URLBuilder = nil
					c.OutboxAEADKeys = goauth.KeyRing{}
				}
				base := c.AuditSink
				c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
					if event.Type == goauth.SecurityEventTrustedLocalPasswordSet {
						audits++
					}
					return base.RecordSecurityEvent(ctx, event)
				})
			})
			account, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
				Email: "notification.set@example.test", Password: testPassword,
			})
			require.NoError(t, err)
			_, err = f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
				SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
			})
			require.NoError(t, err)
			require.Equal(t, 1, audits)
			events := f.Events.Events()
			if disabled {
				require.Empty(t, events)
				return
			}
			require.Len(t, events, 1)
			notification, err := testkit.DecryptNotification(f.EnvelopeKeys, events[0].Envelope)
			require.NoError(t, err)
			require.Equal(t, "password_changed", notification.Template)
			require.Equal(t, account.PrimaryEmail.DisplayValue, notification.To)
			require.Empty(t, notification.Data)
		})
	}
}

func TestTrustedLocalPasswordFailuresRollBack(t *testing.T) {
	for _, stage := range []string{"audit", "notification", "host"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("injected trusted set failure")
			var transaction goauth.AuthTransaction
			f := localIdentityFixture(t, func(c *goauth.Config) {
				transaction = c.AuthTransaction
				if stage == "audit" {
					base := c.AuditSink
					c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
						if event.Type == goauth.SecurityEventTrustedLocalPasswordSet {
							return failure
						}
						return base.RecordSecurityEvent(ctx, event)
					})
				}
				if stage == "notification" {
					c.NotificationRenderer = goauth.NotificationRendererFunc(func(context.Context, goauth.Notification) ([]byte, error) {
						return nil, failure
					})
				}
			})
			original, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
				Email: "rollback.set@example.test", Password: testPassword,
			})
			require.NoError(t, err)
			login, err := f.Runtime.Login(t.Context(), loginRequest(original.PrimaryEmail.DisplayValue, testPassword, goauth.RealmUser))
			require.NoError(t, err)
			before, err := f.Store.GetLocalAccount(t.Context(), original.Subject.ID)
			require.NoError(t, err)
			request := goauth.SetTrustedLocalPasswordRequest{SubjectID: original.Subject.ID, NewPassword: trustedSetPassword}
			if stage == "host" {
				err = transaction.InAuthTransaction(t.Context(), func(ctx context.Context) error {
					changed, err := f.Runtime.SetTrustedLocalPassword(ctx, request)
					require.NoError(t, err)
					require.Equal(t, original.Subject.SecurityVersion+1, changed.Subject.SecurityVersion)
					return failure
				})
			} else {
				var changed goauth.Account
				changed, err = f.Runtime.SetTrustedLocalPassword(t.Context(), request)
				require.Zero(t, changed)
			}
			require.ErrorIs(t, err, failure)
			after, err := f.Store.GetLocalAccount(t.Context(), original.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.Empty(t, f.Events.Events())
			_, err = f.Runtime.VerifyAccessToken(t.Context(), login.Tokens.AccessToken, true)
			require.NoError(t, err)
		})
	}
}

func TestTrustedLocalPasswordNestedAndUnknownOutcomes(t *testing.T) {
	f := localIdentityFixture(t)
	account, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "nested-set"}, Password: testPassword,
	})
	require.NoError(t, err)
	require.NoError(t, f.Store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, err := f.Runtime.SetTrustedLocalPassword(ctx, goauth.SetTrustedLocalPasswordRequest{
			SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
		})
		return err
	}))
	unknown := localIdentityFixture(t, func(c *goauth.Config) {
		c.Store = f.Store
		c.AuditSink = f.Store
		c.AuthTransaction = localIdentityUnknownTransaction{base: f.Store}
	})
	changed, err := unknown.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
	})
	require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
	require.Zero(t, changed)
	stored, err := f.Runtime.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.EqualValues(t, 3, stored.Subject.SecurityVersion, "unknown acknowledgment must not be mistaken for rollback")
}

type trustedSetHookHasher struct {
	goauth.PasswordHasher
	hook func()
}

func (h *trustedSetHookHasher) HashPassword(password string) (string, error) {
	if h.hook != nil {
		h.hook()
	}
	return h.PasswordHasher.HashPassword(password)
}

func TestTrustedLocalPasswordRechecksStateAfterHashing(t *testing.T) {
	for _, mutation := range []string{"replace credential", "status", "logout all"} {
		t.Run(mutation, func(t *testing.T) {
			base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
			require.NoError(t, err)
			hasher := &trustedSetHookHasher{PasswordHasher: base}
			f := localIdentityFixture(t, func(c *goauth.Config) { c.EnableLegacyBytes256 = false; c.PasswordHasher = hasher })
			original, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
				Email: "concurrent.set@example.test", Password: testPassword,
			})
			require.NoError(t, err)
			var mutationErr error
			hasher.hook = func() {
				hasher.hook = nil
				switch mutation {
				case "replace credential":
					_, mutationErr = f.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
						SubjectID: original.Subject.ID, CurrentPassword: testPassword, NewPassword: "Concurrent-Password-Winner-42",
					})
				case "status":
					_, mutationErr = f.Runtime.SetSubjectStatus(t.Context(), original.Subject.ID, goauth.SubjectStatusDisabled)
				default:
					_, mutationErr = f.Runtime.LogoutAll(t.Context(), original.Subject.ID)
				}
			}
			changed, err := f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
				SubjectID: original.Subject.ID, NewPassword: trustedSetPassword,
			})
			require.NoError(t, mutationErr, "security writes during hashing must not be blocked by a subject lock")
			require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
			require.Zero(t, changed)
			stored, err := f.Store.GetLocalAccount(t.Context(), original.Subject.ID)
			require.NoError(t, err)
			require.EqualValues(t, 2, stored.Account.Subject.SecurityVersion)
			require.Error(t, base.VerifyPassword(stored.PasswordPHC, trustedSetPassword))
		})
	}
}

func TestTrustedLocalPasswordUsesSharedHashBudget(t *testing.T) {
	base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	hasher := &trustedSetHookHasher{PasswordHasher: base}
	f := localIdentityFixture(t, func(c *goauth.Config) {
		c.EnableLegacyBytes256 = false
		c.PasswordHasher = hasher
		c.MaxConcurrentPasswordHashes = 1
	})
	account, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "budget.set@example.test", Password: testPassword,
	})
	require.NoError(t, err)
	entered, release := make(chan struct{}), make(chan struct{})
	var hashes atomic.Int32
	hasher.hook = func() { hashes.Add(1); close(entered); <-release }
	result := make(chan error, 1)
	go func() {
		_, err := f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
			SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
		})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("hash did not begin")
	}
	_, err = f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
	})
	require.ErrorIs(t, err, goauth.ErrPasswordHashOverloaded)
	_, err = f.Runtime.VerifyCredential(t.Context(), goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: account.PrimaryEmail.DisplayValue},
		Password:   testPassword,
	})
	require.ErrorIs(t, err, goauth.ErrPasswordHashOverloaded)
	close(release)
	require.NoError(t, <-result)
	require.EqualValues(t, 1, hashes.Load())
}

type trustedSetFailingHasher struct {
	goauth.PasswordHasher
	fail bool
}

func (h *trustedSetFailingHasher) HashPassword(password string) (string, error) {
	if h.fail {
		return "", goauth.ErrPasswordVerificationUnavailable
	}
	return h.PasswordHasher.HashPassword(password)
}

func TestTrustedLocalPasswordHashFailureDoesNotWrite(t *testing.T) {
	base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	hasher := &trustedSetFailingHasher{PasswordHasher: base}
	f := localIdentityFixture(t, func(c *goauth.Config) { c.EnableLegacyBytes256 = false; c.PasswordHasher = hasher })
	original, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "hash-failure.set@example.test", Password: testPassword,
	})
	require.NoError(t, err)
	before, err := f.Store.GetLocalAccount(t.Context(), original.Subject.ID)
	require.NoError(t, err)
	hasher.fail = true
	changed, err := f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: original.Subject.ID, NewPassword: trustedSetPassword,
	})
	require.ErrorIs(t, err, goauth.ErrPasswordVerificationUnavailable)
	require.Zero(t, changed)
	after, err := f.Store.GetLocalAccount(t.Context(), original.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, before, after)
	require.Empty(t, f.Events.Events())
}

func TestTrustedLocalPasswordInvalidatesPreparedLogin(t *testing.T) {
	var f *testkit.Fixture
	var armed bool
	f = localIdentityFixture(t, func(c *goauth.Config) {
		c.EnableLegacyBytes256 = false
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			ctx context.Context, _ goauth.Realm, account goauth.Account, _ map[string]any,
		) error {
			if !armed {
				return nil
			}
			armed = false
			_, err := f.Runtime.SetTrustedLocalPassword(ctx, goauth.SetTrustedLocalPasswordRequest{
				SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
			})
			return err
		})
	})
	account, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "prepared-login.set@example.test", Password: testPassword,
	})
	require.NoError(t, err)
	armed = true
	result, err := f.Runtime.Login(t.Context(), loginRequest(account.PrimaryEmail.DisplayValue, testPassword, goauth.RealmUser))
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	require.Empty(t, result.Tokens.AccessToken)
	require.Empty(t, result.Tokens.RefreshToken)
	require.False(t, armed)
	stored, err := f.Runtime.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, account.Subject.SecurityVersion+1, stored.Subject.SecurityVersion)
}

func TestTrustedLocalPasswordKeepsCredentialAdmissionSeparate(t *testing.T) {
	f := localIdentityFixture(t, func(c *goauth.Config) {
		c.EnableLegacyBytes256 = false
		c.LoginRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
		c.CredentialVerificationRateLimit = goauth.RateLimitPolicy{Window: time.Minute, Limit: 1}
	})
	identifier := goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "setter-admission"}
	account, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: identifier, Password: trustedSetPassword,
	})
	require.NoError(t, err)
	require.NoError(t, f.Store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		for range 2 {
			if _, err := f.Runtime.SetTrustedLocalPassword(ctx, goauth.SetTrustedLocalPasswordRequest{
				SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
			}); err != nil {
				return err
			}
		}
		return nil
	}))
	credential := goauth.Credential{Identifier: identifier, Password: trustedSetPassword}
	_, err = f.Runtime.VerifyCredential(t.Context(), credential)
	require.NoError(t, err, "privileged sets must not spend the credential admission budget")
	_, err = f.Runtime.VerifyCredential(t.Context(), credential)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
	_, err = f.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: credential})
	require.NoError(t, err, "privileged sets must not spend the independent login budget")
}
