package goauth_test

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	employeeIdentifierScheme = goauth.IdentifierScheme("employee")
	supportRealm             = goauth.Realm("support")
	ssoOnlyEmail             = "sso.only@example.test"
	testAudience             = "test"
	testEmail                = "Security.User@Example.Test"
	invalidTestEmail         = "not-an-email"
	testNotificationTemplate = "test"
	testOIDCIssuer           = "https://idp.example.test"
	testPassword             = "Unique-Test-Passphrase-1"
)

func TestRefreshRotationAllowsExactlyOneConcurrentIssuance(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, testEmail)

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
			_, err := fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
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

func TestPasswordResetIsConsumedOnceWithConcurrentPasswords(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registerAccount(t, fixture, testEmail)

	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), testEmail))
	events := fixture.Events.Events()
	require.NotEmpty(t, events)
	notification, err := testkit.DecryptNotification(fixture.EnvelopeKeys, events[len(events)-1].Envelope)
	require.NoError(t, err)
	resetURL, err := url.Parse(notification.Data["reset_url"])
	require.NoError(t, err)
	resetToken := resetURL.Query().Get("token")
	require.NotEmpty(t, resetToken)
	require.NotContains(t, resetURL.Query(), "email")
	require.False(t, bytes.Contains(events[len(events)-1].Envelope.Ciphertext, []byte(resetToken)))

	passwords := []string{"Replacement-Passphrase-A1", "Replacement-Passphrase-B2"}
	errorsByPassword := make([]error, len(passwords))
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index, password := range passwords {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			errorsByPassword[index] = fixture.Runtime.ResetPassword(context.Background(), resetToken, password)
		}()
	}
	close(start)
	wait.Wait()

	var successCount int
	var usedCount int
	var winningPassword string
	for index, err := range errorsByPassword {
		switch {
		case err == nil:
			successCount++
			winningPassword = passwords[index]
		case errors.Is(err, goauth.ErrResetAlreadyUsed):
			usedCount++
		default:
			t.Fatalf("unexpected reset result: %v", err)
		}
	}
	require.Equal(t, 1, successCount)
	require.Equal(t, 1, usedCount)
	_, err = fixture.Runtime.Login(context.Background(), loginRequest(testEmail, winningPassword, goauth.RealmUser))
	require.NoError(t, err)
}

func TestUnverifiedAccountCanResetPasswordWithoutBecomingVerified(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "unverified.reset@example.test")
	require.False(t, registered.Account.EmailVerified())

	eventsBefore := len(fixture.Events.Events())
	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), "unverified.reset@example.test"))
	events := fixture.Events.Events()
	require.Len(t, events, eventsBefore+1)
	require.Equal(t, "password_reset", events[len(events)-1].Type)
	notification, err := testkit.DecryptNotification(fixture.EnvelopeKeys, events[len(events)-1].Envelope)
	require.NoError(t, err)
	resetURL, err := url.Parse(notification.Data["reset_url"])
	require.NoError(t, err)
	resetToken := resetURL.Query().Get("token")
	require.NotEmpty(t, resetToken)

	const replacementPassword = "Replacement-Unverified-1"
	require.NoError(t, fixture.Runtime.ResetPassword(context.Background(), resetToken, replacementPassword))
	require.ErrorIs(
		t,
		fixture.Runtime.ResetPassword(context.Background(), resetToken, "Replacement-Unverified-2"),
		goauth.ErrResetAlreadyUsed,
	)
	_, err = fixture.Runtime.Login(
		context.Background(),
		loginRequest("unverified.reset@example.test", testPassword, goauth.RealmUser),
	)
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	login, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("unverified.reset@example.test", replacementPassword, goauth.RealmUser),
	)
	require.NoError(t, err)
	require.False(t, login.Account.EmailVerified())
	require.Equal(t, goauth.SessionScopeConfirmation, login.Tokens.Session.Scope)
}

func TestPasswordResetDoesNotEmitForMissingOrInvalidEmail(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)

	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), "missing@example.test"))
	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), invalidTestEmail))
	require.Empty(t, fixture.Events.Events())
}

func TestEmailChallengePersistsFiveWrongAttemptsAndBlocksSixth(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, testEmail)
	require.NoError(t, fixture.Runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	code := latestChallengeCode(t, fixture)
	wrongCode := differentCode(code)
	for attempt := 1; attempt <= 5; attempt++ {
		_, err := fixture.Runtime.VerifyEmailChallenge(
			context.Background(),
			registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification,
			wrongCode,
		)
		require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
		require.Equal(t, attempt, fixture.Store.ChallengeAttempts(
			registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification,
		))
	}
	_, err := fixture.Runtime.VerifyEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		wrongCode,
	)
	require.ErrorIs(t, err, goauth.ErrConfirmationAttempts)
	require.Equal(t, 5, fixture.Store.ChallengeAttempts(
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
}

func TestEmailVerificationControlsSessionScope(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, testEmail)
	require.Equal(t, goauth.SessionScopeConfirmation, registered.Tokens.Session.Scope)
	loginBefore, err := fixture.Runtime.Login(context.Background(), loginRequest(testEmail, testPassword, goauth.RealmUser))
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeConfirmation, loginBefore.Tokens.Session.Scope)

	require.NoError(t, fixture.Runtime.SendEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
	))
	verified, err := fixture.Runtime.VerifyEmailChallenge(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification,
		latestChallengeCode(t, fixture),
	)
	require.NoError(t, err)
	require.True(t, verified.EmailVerified())
	_, err = fixture.Runtime.VerifyAccessToken(context.Background(), registered.Tokens.AccessToken, true)
	require.ErrorIs(t, err, goauth.ErrInvalidToken, "the old confirmation token must not survive session promotion")
	promoted, err := fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeAuthenticated, promoted.Session.Scope)
	_, err = fixture.Runtime.VerifyAccessToken(context.Background(), promoted.AccessToken, true)
	require.NoError(t, err)

	loginAfter, err := fixture.Runtime.Login(context.Background(), loginRequest(testEmail, testPassword, goauth.RealmUser))
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeAuthenticated, loginAfter.Tokens.Session.Scope)
}

func TestSuspendedSubjectLosesServerStateAndOfflineJWTIsShortLived(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, testEmail)
	require.LessOrEqual(t, registered.Tokens.AccessExpiresAt.Sub(registered.Tokens.Session.CreatedAt), goauth.MaxAccessTokenTTL)

	_, err := fixture.Runtime.SetSubjectStatus(
		context.Background(),
		registered.Account.Subject.ID,
		goauth.SubjectStatusSuspended,
	)
	require.NoError(t, err)
	_, err = fixture.Runtime.VerifyAccessToken(context.Background(), registered.Tokens.AccessToken, true)
	require.Error(t, err)
	_, err = fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
	_, err = fixture.Runtime.VerifyAccessToken(context.Background(), registered.Tokens.AccessToken, false)
	require.NoError(t, err, "offline JWT remains valid only until its short expiration")
}

func TestLoginRateLimitUsesNormalizedIdentifier(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registerAccount(t, fixture, testEmail)

	for range 10 {
		_, err := fixture.Runtime.Login(
			context.Background(),
			loginRequest(" security.user@example.test ", "wrong-password", goauth.RealmUser),
		)
		require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	}
	_, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("SECURITY.USER@EXAMPLE.TEST", testPassword, goauth.RealmUser),
	)
	require.ErrorIs(t, err, goauth.ErrAuthenticationRateLimited)
}

func TestPasswordPolicyUsesArgon2idAndBlocksCommonPasswords(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	_, err := fixture.Runtime.Register(context.Background(), goauth.RegisterRequest{
		Email:    "common.password@example.test",
		Password: "password123",
	})
	require.ErrorIs(t, err, goauth.ErrCommonPassword)

	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	phc, err := hasher.HashPassword(testPassword)
	require.NoError(t, err)
	require.Contains(t, phc, "$argon2id$v=19$m=19456,t=2,p=1$")
	require.NoError(t, hasher.VerifyPassword(phc, testPassword))
}

func TestRuntimeRejectsCrossPurposeKeyReuse(t *testing.T) {
	t.Parallel()
	material := bytes.Repeat([]byte{9}, 32)
	jwtKeys, err := goauth.NewKeyRing("jwt", goauth.Key{ID: "jwt", Material: material})
	require.NoError(t, err)
	tokenKeys, err := goauth.NewKeyRing("token", goauth.Key{ID: "token", Material: material})
	require.NoError(t, err)
	outboxKeys, err := goauth.NewKeyRing("outbox", goauth.Key{ID: "outbox", Material: bytes.Repeat([]byte{8}, 32)})
	require.NoError(t, err)
	_, err = goauth.NewRuntime(goauth.Config{
		Store:           testkit.NewStore(),
		AuthTransaction: testkit.NewStore(),
		AuditSink:       testkit.NewStore(),
		Signing:         goauth.SigningConfig{Issuer: "https://auth.example.test", Audience: testAudience, Keys: jwtKeys},
		TokenHMACKeys:   tokenKeys,
		OutboxAEADKeys:  outboxKeys,
		EventSink:       &testkit.EventSink{},
		URLBuilder: goauth.URLBuilderFunc(func(context.Context, string) (string, error) {
			return "https://app.example.test/reset", nil
		}),
	})
	require.ErrorIs(t, err, goauth.ErrKeyPurposeCollision)
}

func TestEncryptedEventRoundTripAndRetentionCleanup(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registerAccount(t, fixture, testEmail)
	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), testEmail))
	events := fixture.Events.Events()
	require.Len(t, events, 1)
	notification, err := fixture.Runtime.DecryptNotificationEvent(events[0])
	require.NoError(t, err)
	require.Equal(t, "password_reset", notification.Template)
	require.NotEmpty(t, notification.Data["reset_url"])

	deleted, err := fixture.Events.DeleteExpiredEncrypted(
		context.Background(),
		events[0].Envelope.DeleteAfter.Add(time.Nanosecond),
	)
	require.NoError(t, err)
	require.EqualValues(t, 1, deleted)
	require.Empty(t, fixture.Events.Events())
}

func FuzzNormalizeEmail(f *testing.F) {
	for _, seed := range []string{"user@example.com", " USER@Example.COM ", "", invalidTestEmail, "a@b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		normalized, err := goauth.NormalizeEmail(value)
		if err == nil {
			require.NotEmpty(t, normalized)
			require.Equal(t, normalized, string(bytes.ToLower([]byte(normalized))))
		}
	})
}

func FuzzAccessAndRefreshTokenParsing(f *testing.F) {
	fixture, err := testkit.NewRuntime()
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{"", ".", "a.b.c", "not-a-token"} {
		f.Add(seed)
	}
	f.Fuzz(func(_ *testing.T, value string) {
		_, _ = fixture.Runtime.VerifyAccessToken(context.Background(), value, false)
		_, _ = fixture.Runtime.Refresh(context.Background(), value)
	})
}

func newFixture(t *testing.T) *testkit.Fixture {
	t.Helper()
	fixture, err := testkit.NewRuntime()
	require.NoError(t, err)

	return fixture
}

func registerAccount(t *testing.T, fixture *testkit.Fixture, email string) goauth.RegisterResult {
	t.Helper()
	registered, err := fixture.Runtime.Register(context.Background(), goauth.RegisterRequest{
		Email:    email,
		Password: testPassword,
		Profile:  goauth.BasicProfile{DisplayName: "Security Test"},
	})
	require.NoError(t, err)

	return registered
}

func loginRequest(email, password string, realm goauth.Realm) goauth.LoginRequest {
	return goauth.LoginRequest{
		Credential: goauth.Credential{
			Identifier: goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: email},
			Password:   password,
		},
		Realm: realm,
	}
}

func latestChallengeCode(t *testing.T, fixture *testkit.Fixture) string {
	t.Helper()
	events := fixture.Events.Events()
	for index := len(events) - 1; index >= 0; index-- {
		if events[index].Type != "email_challenge" {
			continue
		}
		notification, err := testkit.DecryptNotification(fixture.EnvelopeKeys, events[index].Envelope)
		require.NoError(t, err)
		code := notification.Data["code"]
		require.Len(t, code, 6)
		require.False(t, bytes.Contains(events[index].Envelope.Ciphertext, []byte(code)))
		return code
	}
	t.Fatal("email challenge notification was not emitted")

	return ""
}

func differentCode(code string) string {
	if code != "000000" {
		return "000000"
	}

	return "999999"
}
