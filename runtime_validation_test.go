package goauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

type passthroughNotificationTransaction struct{}

func (passthroughNotificationTransaction) InNotificationTransaction(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}

func TestCustomNotificationTransactionPreservesRendererAndAcknowledgement(t *testing.T) {
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.NotificationTransaction = passthroughNotificationTransaction{}
		config.NotificationRenderer = goauth.NotificationRendererFunc(
			func(_ context.Context, notification goauth.Notification) ([]byte, error) {
				notification.Template = "custom_" + notification.Template
				return json.Marshal(notification)
			},
		)
	})
	require.NoError(t, err)
	registerAccount(t, fixture, "transaction.renderer@example.test")
	require.NoError(t, fixture.Runtime.RequestPasswordReset(context.Background(), "transaction.renderer@example.test"))
	events := fixture.Events.Events()
	require.Len(t, events, 1)
	require.True(t, events[0].ValidUntil.IsZero())
	notification, err := testkit.DecryptNotification(fixture.EnvelopeKeys, events[0].Envelope)
	require.NoError(t, err)
	require.Equal(t, "custom_password_reset", notification.Template)
	require.NoError(t, fixture.Runtime.AcknowledgeEncryptedEvent(context.Background(), events[0].ID))
	require.Empty(t, fixture.Events.Events())
}

func TestRuntimeConfigurationValidation(t *testing.T) {
	t.Parallel()
	valid := validRuntimeConfig(t)

	cases := []struct {
		name   string
		mutate func(*goauth.Config)
	}{
		{"store", func(config *goauth.Config) { config.Store = nil }},
		{"event sink", func(config *goauth.Config) { config.EventSink = nil }},
		{"URL builder", func(config *goauth.Config) { config.URLBuilder = nil }},
		{"access TTL", func(config *goauth.Config) { config.AccessTTL = goauth.MaxAccessTokenTTL + time.Second }},
		{"negative reset floor", func(config *goauth.Config) { config.ResetResponseFloor = -time.Second }},
		{"link age", func(config *goauth.Config) { config.IdentityLinkAuthMaxAge = time.Second }},
		{"login limit", func(config *goauth.Config) { config.LoginRateLimit = goauth.RateLimitPolicy{Limit: -1} }},
		{"realm", func(config *goauth.Config) { config.AdditionalRealms = []goauth.Realm{"Bad Realm"} }},
		{"managed without transaction", func(config *goauth.Config) {
			config.ManagedNotificationDelivery = true
		}},
		{"managed with custom renderer", func(config *goauth.Config) {
			config.ManagedNotificationDelivery = true
			config.NotificationRenderer = goauth.NotificationRendererFunc(
				func(context.Context, goauth.Notification) ([]byte, error) { return nil, nil },
			)
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			config := valid
			testCase.mutate(&config)
			_, err := goauth.NewRuntime(config)
			require.Error(t, err)
		})
	}
}

func TestRuntimeHooksAndCustomRealm(t *testing.T) {
	t.Parallel()
	var membershipCalled, claimsCalled bool
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.AdditionalRealms = []goauth.Realm{supportRealm}
		config.MembershipGate = goauth.MembershipGateFunc(func(_ context.Context, realm goauth.Realm, _ goauth.Account) error {
			membershipCalled = realm == supportRealm
			return nil
		})
		config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			_ context.Context,
			realm goauth.Realm,
			_ goauth.Account,
			claims map[string]any,
		) error {
			claimsCalled = realm == supportRealm
			claims["tenant"] = "example"
			return nil
		})
		config.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			employeeIdentifierScheme: goauth.IdentifierResolverFunc(
				func(_ context.Context, input goauth.IdentifierInput) (goauth.IdentifierInput, error) {
					input.Value = strings.ToLower(strings.TrimSpace(input.Value))
					return input, nil
				},
			),
		}
	})
	require.NoError(t, err)

	registered := registerAccount(t, fixture, "realm.user@example.test")
	verifyEmail(t, fixture, registered.Account.Subject.ID)
	loginResult, err := fixture.Runtime.Login(
		context.Background(),
		loginRequest("realm.user@example.test", testPassword, supportRealm),
	)
	require.NoError(t, err)
	require.True(t, membershipCalled)
	require.True(t, claimsCalled)
	auth, err := fixture.Runtime.VerifyAccessToken(context.Background(), loginResult.Tokens.AccessToken, true)
	require.NoError(t, err)
	require.Equal(t, "example", auth.Claims["tenant"])
}

func TestClaimsEnricherCannotOverrideSecurityClaims(t *testing.T) {
	t.Parallel()

	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			_ context.Context,
			_ goauth.Realm,
			_ goauth.Account,
			claims map[string]any,
		) error {
			claims["sub"] = goauth.NewSubjectID().String()
			return nil
		})
	})
	require.NoError(t, err)

	_, err = fixture.Runtime.Register(context.Background(), goauth.RegisterRequest{
		Email:    "reserved.claim@example.test",
		Password: "Reserved-Claim-Passphrase-1",
	})
	require.ErrorIs(t, err, goauth.ErrReservedAccessTokenClaim)
}

func TestExternalLoginRealmAndRecentExplicitLink(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.Now = func() time.Time { return now }
	})
	require.NoError(t, err)

	loginResult, err := fixture.Runtime.LoginExternal(context.Background(), goauth.ExternalLoginRequest{
		Identity: goauth.ExternalIdentity{
			Issuer:        testOIDCIssuer,
			Subject:       "verified-user",
			Email:         "verified.external@example.test",
			EmailVerified: true,
		},
		Realm: goauth.RealmAdmin,
	})
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeAuthenticated, loginResult.Tokens.Session.Scope)
	auth, err := fixture.Runtime.VerifyAccessToken(context.Background(), loginResult.Tokens.AccessToken, true)
	require.NoError(t, err)

	forged := auth
	forged.SessionID = "missing-session"
	_, err = fixture.Runtime.LinkExternalIdentity(context.Background(), forged, goauth.ExternalIdentity{
		Issuer: "https://second-idp.example.test", Subject: "forged", Email: "forged@example.test",
	})
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink)

	now = now.Add(11 * time.Minute)
	_, err = fixture.Runtime.LinkExternalIdentity(context.Background(), auth, goauth.ExternalIdentity{
		Issuer: "https://second-idp.example.test", Subject: "stale", Email: "stale@example.test",
	})
	require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink)

	unverified, err := fixture.Runtime.LoginExternal(context.Background(), goauth.ExternalLoginRequest{
		Identity: goauth.ExternalIdentity{
			Issuer: testOIDCIssuer, Subject: "unverified", Email: "unverified.external@example.test",
		},
	})
	require.NoError(t, err)
	require.Equal(t, goauth.SessionScopeConfirmation, unverified.Tokens.Session.Scope)
}

func TestPasswordResetURLAndEncryptedEventValidation(t *testing.T) {
	t.Parallel()
	fixture, err := testkit.NewRuntime(func(config *goauth.Config) {
		config.URLBuilder = goauth.URLBuilderFunc(func(context.Context, string) (string, error) {
			return "javascript:alert(1)", nil
		})
	})
	require.NoError(t, err)
	registerAccount(t, fixture, "unsafe.url@example.test")
	require.Error(t, fixture.Runtime.RequestPasswordReset(context.Background(), "unsafe.url@example.test"))

	validFixture := newFixture(t)
	registerAccount(t, validFixture, "encrypted.validation@example.test")
	require.NoError(t, validFixture.Runtime.RequestPasswordReset(context.Background(), "encrypted.validation@example.test"))
	event := validFixture.Events.Events()[0]
	tampered := event
	tampered.Type = "email_challenge"
	_, err = validFixture.Runtime.DecryptNotificationEvent(tampered)
	require.Error(t, err)
	require.Error(t, validFixture.Runtime.AcknowledgeEncryptedEvent(context.Background(), ""))
	require.NoError(t, validFixture.Runtime.AcknowledgeEncryptedEvent(context.Background(), event.ID))
	require.Empty(t, validFixture.Events.Events())
}

func TestKeyRingPasswordAndModelValidation(t *testing.T) {
	t.Parallel()
	_, err := goauth.NewKeyRing("missing")
	require.ErrorIs(t, err, goauth.ErrKeyRingInvalid)
	_, err = goauth.NewKeyRing("key", goauth.Key{ID: "key", Material: []byte("short")})
	require.ErrorIs(t, err, goauth.ErrKeyRingInvalid)
	ring, err := goauth.NewKeyRing("key", goauth.Key{ID: "key", Material: bytes.Repeat([]byte{4}, 32)})
	require.NoError(t, err)
	require.Equal(t, "key", ring.ActiveKeyID())
	_, err = ring.Get("unknown")
	require.Error(t, err)

	policy := goauth.DefaultPasswordPolicy()
	require.ErrorIs(t, policy.Validate("short"), goauth.ErrInvalidPassword)
	require.ErrorIs(t, policy.Validate(strings.Repeat("a", 129)), goauth.ErrInvalidPassword)
	invalidUTF8 := string([]byte{0xff, 0xfe})
	require.False(t, utf8.ValidString(invalidUTF8))
	require.ErrorIs(t, policy.Validate(invalidUTF8), goauth.ErrInvalidPassword)

	hasher, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	require.ErrorIs(t, hasher.VerifyPassword("not-a-phc", testPassword), goauth.ErrInvalidCredentials)
	require.ErrorIs(t, hasher.VerifyPassword("$argon2id$v=19$m=9999999,t=2,p=1$bad$bad", testPassword), goauth.ErrInvalidCredentials)

	require.Error(t, goauth.SubjectStatus("unknown").Validate())
	require.Error(t, goauth.Realm("Bad").Validate())
	require.Error(t, goauth.IdentifierScheme("1bad").Validate())
	require.Error(t, goauth.EmailChallengePurpose("phone").Validate())
}

func validRuntimeConfig(t *testing.T) goauth.Config {
	t.Helper()
	keyRing := func(id string, fill byte) goauth.KeyRing {
		ring, err := goauth.NewKeyRing(id, goauth.Key{ID: id, Material: bytes.Repeat([]byte{fill}, 32)})
		require.NoError(t, err)
		return ring
	}
	return goauth.Config{
		Store:          testkit.NewStore(),
		Signing:        goauth.SigningConfig{Issuer: "https://auth.example.test", Audience: testAudience, Keys: keyRing("jwt", 1)},
		TokenHMACKeys:  keyRing("token", 2),
		OutboxAEADKeys: keyRing("outbox", 3),
		EventSink:      &testkit.EventSink{},
		URLBuilder: goauth.URLBuilderFunc(func(context.Context, string) (string, error) {
			return "https://app.example.test/reset", nil
		}),
		ResetResponseFloor: time.Nanosecond,
	}
}
