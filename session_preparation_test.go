package goauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

type observedSessionStore struct {
	goauth.RuntimeStore
	last        goauth.SessionRecord
	afterCreate func()
}

func (s *observedSessionStore) CreateSession(ctx context.Context, record goauth.SessionRecord) error {
	s.last = record
	if err := s.RuntimeStore.CreateSession(ctx, record); err != nil {
		return err
	}
	s.afterCreate()
	return nil
}

type sessionPreparationCase struct {
	name       string
	fraction   time.Duration
	accessTTL  time.Duration
	sessionTTL time.Duration
	delay      time.Duration
	inStore    bool
}

func TestSessionIssuanceRollsBackExpiredPair(t *testing.T) {
	t.Parallel()
	for _, tc := range []sessionPreparationCase{
		{"access expiry during claims", 0, time.Second, time.Minute, time.Second, false},
		{"session expiry during claims", 0, time.Minute, time.Second, time.Second, false},
		{"JWT second precision", 250 * time.Millisecond, time.Second, time.Minute, 800 * time.Millisecond, false},
		{"access expiry during write", 0, time.Second, time.Minute, 2 * time.Second, true},
		{"session expiry during write", 0, time.Minute, time.Second, 2 * time.Second, true},
	} {
		for _, operation := range []string{"register", customHasherLoginOperation, "external login"} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				t.Parallel()
				checkExpiredSessionIssuance(t, tc, operation)
			})
		}
	}
}

func checkExpiredSessionIssuance(t *testing.T, tc sessionPreparationCase, operation string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second).Add(tc.fraction)
	var slow bool
	var store *observedSessionStore
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.Now = func() time.Time { return now }
		c.AccessTTL = tc.accessTTL
		c.SessionTTL = tc.sessionTTL
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			context.Context, goauth.Realm, goauth.Account, map[string]any,
		) error {
			if slow && !tc.inStore {
				now = now.Add(tc.delay)
			}
			return nil
		})
		store = &observedSessionStore{RuntimeStore: c.Store, afterCreate: func() {
			if slow && tc.inStore {
				now = now.Add(tc.delay)
			}
		}}
		c.Store = store
	})
	require.NoError(t, err)
	const email = "expired.session.preparation@example.test"
	if operation == customHasherLoginOperation {
		registerAccount(t, fixture, email)
	}
	external := goauth.ExternalIdentity{Issuer: testOIDCIssuer, Subject: "expired-session", Email: email, EmailVerified: true}
	attempt := func() (goauth.TokenPair, error) {
		switch operation {
		case "register":
			result, err := fixture.Runtime.Register(t.Context(), goauth.RegisterRequest{Email: email, Password: testPassword})
			return result.Tokens, err
		case customHasherLoginOperation:
			result, err := fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, goauth.RealmUser))
			return result.Tokens, err
		default:
			result, err := fixture.Runtime.LoginExternal(t.Context(), goauth.ExternalLoginRequest{Identity: external})
			return result.Tokens, err
		}
	}
	slow = true
	tokens, err := attempt()
	require.ErrorIs(t, err, goauth.ErrExpiredToken)
	require.Empty(t, tokens.AccessToken)
	require.Empty(t, tokens.RefreshToken)
	security, err := fixture.Store.IntrospectSession(t.Context(), store.last.Session.ID)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked, "failed issuance must leave no session")
	require.Empty(t, security.Session.ID)
	if operation != customHasherLoginOperation {
		_, err = fixture.Store.GetAccount(t.Context(), store.last.Session.SubjectID)
		require.ErrorIs(t, err, goauth.ErrAccountNotFound, "failed issuance must leave no provisioned account")
	}
	if operation == "external login" {
		_, _, err = fixture.Store.ResolveIdentityLink(t.Context(), external.Issuer, external.Subject)
		require.ErrorIs(t, err, goauth.ErrIdentityLinkNotFound)
	}
	require.Empty(t, fixture.Events.Events())
	slow = false
	tokens, err = attempt()
	require.NoError(t, err, "a fast retry must succeed after full rollback")
	_, err = fixture.Runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
	require.NoError(t, err)
	_, err = fixture.Runtime.Refresh(t.Context(), tokens.RefreshToken)
	require.NoError(t, err)
}
