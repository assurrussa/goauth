package goauth_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	atomicityLogoutAll = "logout all"
	atomicityStatus    = "status"
)

var errAtomicityHook = errors.New("injected auth hook failure")

func TestAuthAtomicityClaimsFailureDoesNotRegisterOrConsumeRefresh(t *testing.T) {
	t.Parallel()
	var fail atomic.Bool
	fail.Store(true)
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(context.Context, goauth.Realm, goauth.Account, map[string]any) error {
			if fail.Load() {
				return errAtomicityHook
			}
			return nil
		})
	})
	require.NoError(t, err)
	email := "atomic.claims@example.test"
	_, err = fixture.Runtime.Register(context.Background(), goauth.RegisterRequest{Email: email, Password: testPassword})
	require.ErrorIs(t, err, errAtomicityHook)
	_, err = fixture.Store.FindAccount(context.Background(), goauth.IdentifierInput{
		Scheme: goauth.IdentifierSchemeEmail, Value: email,
	})
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	fail.Store(false)
	registered := registerAccount(t, fixture, email)
	fail.Store(true)
	_, err = fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, errAtomicityHook)
	require.NoError(t, atomicityAuthenticate(fixture, registered.Tokens.AccessToken))
	fail.Store(false)
	_, err = fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.NoError(t, err)
}

func TestAuthAtomicityReplayRevokesWithoutClaimsPreparation(t *testing.T) {
	t.Parallel()
	var fail atomic.Bool
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(context.Context, goauth.Realm, goauth.Account, map[string]any) error {
			if fail.Load() {
				return errAtomicityHook
			}
			return nil
		})
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "atomic.replay@example.test")
	winner, err := fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.NoError(t, err)
	fail.Store(true)
	_, err = fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrRefreshReplay)
	require.ErrorIs(t, atomicityAuthenticate(fixture, winner.AccessToken), goauth.ErrSessionRevoked)
	fail.Store(false)
	_, err = fixture.Runtime.Refresh(context.Background(), winner.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

func TestAuthAtomicityAuditFailureRollsBack(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"logout", atomicityLogoutAll, atomicityStatus, "auto link"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			var fail atomic.Bool
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				c.AuditSink = goauth.AuditSinkFunc(func(context.Context, goauth.SecurityEvent) error {
					if fail.Load() {
						return errAtomicityHook
					}
					return nil
				})
			})
			require.NoError(t, err)
			registered := registerAccount(t, fixture, "atomic.audit@example.test")
			verifyEmail(t, fixture, registered.Account.Subject.ID)
			loggedIn, err := fixture.Runtime.Login(context.Background(),
				loginRequest("atomic.audit@example.test", testPassword, goauth.RealmUser))
			require.NoError(t, err)
			before, err := fixture.Store.GetAccount(context.Background(), registered.Account.Subject.ID)
			require.NoError(t, err)
			fail.Store(true)
			switch operation {
			case "logout":
				err = fixture.Runtime.Logout(context.Background(), before.Subject.ID, loggedIn.Tokens.Session.ID)
			case atomicityLogoutAll:
				_, err = fixture.Runtime.LogoutAll(context.Background(), before.Subject.ID)
			case atomicityStatus:
				_, err = fixture.Runtime.SetSubjectStatus(context.Background(), before.Subject.ID, goauth.SubjectStatusSuspended)
			case "auto link":
				_, err = fixture.Runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
					Issuer: testOIDCIssuer, Subject: "audit-link", Email: "atomic.audit@example.test", EmailVerified: true,
				})
			}
			require.ErrorIs(t, err, errAtomicityHook)
			require.NoError(t, atomicityAuthenticate(fixture, loggedIn.Tokens.AccessToken))
			after, err := fixture.Store.GetAccount(context.Background(), before.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, before.Subject.Status, after.Subject.Status)
			require.Equal(t, before.Subject.SecurityVersion, after.Subject.SecurityVersion)
			_, _, err = fixture.Store.ResolveIdentityLink(context.Background(), testOIDCIssuer, "audit-link")
			require.ErrorIs(t, err, goauth.ErrIdentityLinkNotFound)
		})
	}
}

func TestAuthAtomicityConcurrentRefreshReplayInvalidatesWinner(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "atomic.concurrent@example.test")
	start := make(chan struct{})
	var wait sync.WaitGroup
	results := make(chan struct {
		pair goauth.TokenPair
		err  error
	}, 8)
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			pair, err := fixture.Runtime.Refresh(context.Background(), registered.Tokens.RefreshToken)
			results <- struct {
				pair goauth.TokenPair
				err  error
			}{pair, err}
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	var winner goauth.TokenPair
	successes := 0
	for result := range results {
		if result.err == nil {
			successes++
			winner = result.pair
		} else {
			require.ErrorIs(t, result.err, goauth.ErrRefreshReplay)
		}
	}
	require.Equal(t, 1, successes)
	require.ErrorIs(t, atomicityAuthenticate(fixture, winner.AccessToken), goauth.ErrSessionRevoked)
	_, err := fixture.Runtime.Refresh(context.Background(), winner.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

func TestAuthAtomicitySessionRejectsChangedClaimsSnapshot(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{atomicityLogoutAll, "password", atomicityStatus} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			var armed atomic.Bool
			var fixture *testkit.Fixture
			var err error
			fixture, err = testkit.NewRuntime(func(c *goauth.Config) {
				c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
					ctx context.Context, _ goauth.Realm, account goauth.Account, _ map[string]any,
				) error {
					if !armed.CompareAndSwap(true, false) {
						return nil
					}
					switch operation {
					case atomicityLogoutAll:
						_, err := fixture.Runtime.LogoutAll(ctx, account.Subject.ID)
						return err
					case "password":
						_, err := fixture.Runtime.ChangePassword(ctx, goauth.ChangePasswordRequest{
							SubjectID: account.Subject.ID, CurrentPassword: testPassword,
							NewPassword: "Atomic-Replacement-Passphrase-2",
						})
						return err
					default:
						_, err := fixture.Runtime.SetSubjectStatus(ctx, account.Subject.ID, goauth.SubjectStatusSuspended)
						return err
					}
				})
			})
			require.NoError(t, err)
			registerAccount(t, fixture, "atomic.snapshot@example.test")
			armed.Store(true)
			result, err := fixture.Runtime.Login(context.Background(),
				loginRequest("atomic.snapshot@example.test", testPassword, goauth.RealmUser))
			require.Error(t, err)
			require.Empty(t, result.Tokens.AccessToken)
			require.False(t, armed.Load())
		})
	}
}

func TestAuthAtomicityExternalIdentityExactnessAndEmailOptionalForExistingLink(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	external := goauth.ExternalIdentity{
		Issuer: testOIDCIssuer + "/", Subject: " exact subject ",
		Email: "atomic.external@example.test", EmailVerified: true,
	}
	account, err := fixture.Runtime.ResolveExternalIdentity(context.Background(), external)
	require.NoError(t, err)
	external.Email = ""
	result, err := fixture.Runtime.LoginExternal(context.Background(), goauth.ExternalLoginRequest{Identity: external})
	require.NoError(t, err)
	require.Equal(t, account.Subject.ID, result.Account.Subject.ID)
	for _, different := range []goauth.ExternalIdentity{
		{Issuer: testOIDCIssuer, Subject: external.Subject},
		{Issuer: external.Issuer, Subject: "exact subject"},
	} {
		_, err := fixture.Runtime.LoginExternal(context.Background(), goauth.ExternalLoginRequest{Identity: different})
		require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
	}
}

func TestAuthAtomicityAutoLinkIssuerPolicy(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		policy  []string
		allowed bool
	}{
		{"legacy nil", nil, true},
		{"wildcard", []string{"*"}, true},
		{"disabled", []string{}, false},
		{"exact", []string{testOIDCIssuer}, true},
		{"different trailing slash", []string{testOIDCIssuer + "/"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) { c.AutoLinkVerifiedEmailIssuers = tc.policy })
			require.NoError(t, err)
			registered := registerAccount(t, fixture, "atomic.policy@example.test")
			verifyEmail(t, fixture, registered.Account.Subject.ID)
			linked, err := fixture.Runtime.ResolveExternalIdentity(context.Background(), goauth.ExternalIdentity{
				Issuer: testOIDCIssuer, Subject: "policy-subject", Email: "atomic.policy@example.test", EmailVerified: true,
			})
			if tc.allowed {
				require.NoError(t, err)
				require.Equal(t, registered.Account.Subject.ID, linked.Subject.ID)
			} else {
				require.ErrorIs(t, err, goauth.ErrExplicitIdentityLink)
			}
		})
	}
	for _, policy := range [][]string{{""}, {"*", testOIDCIssuer}, {testOIDCIssuer, "*"}} {
		_, err := testkit.NewRuntime(func(c *goauth.Config) { c.AutoLinkVerifiedEmailIssuers = policy })
		require.Error(t, err)
	}
}

func atomicityAuthenticate(fixture *testkit.Fixture, token string) error {
	_, err := fixture.Runtime.AuthenticateSession(context.Background(), token)
	return err
}

func TestAuthAtomicityEmailVerificationRollsBackAuditFailureButCommitsAttempts(t *testing.T) {
	t.Parallel()
	for _, wrongCode := range []bool{false, true} {
		t.Run(map[bool]string{false: "audit rollback", true: "wrong attempts persist"}[wrongCode], func(t *testing.T) {
			t.Parallel()
			var fail atomic.Bool
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				c.AuditSink = goauth.AuditSinkFunc(func(context.Context, goauth.SecurityEvent) error {
					if fail.Load() {
						return errAtomicityHook
					}
					return nil
				})
			})
			require.NoError(t, err)
			registered := registerAccount(t, fixture, "atomic.verification@example.test")
			require.NoError(t, fixture.Runtime.SendEmailChallenge(context.Background(), registered.Account.Subject.ID,
				goauth.EmailChallengePurposeVerification))
			code := latestChallengeCode(t, fixture)
			fail.Store(true)
			if wrongCode {
				for range 5 {
					_, err := fixture.Runtime.VerifyEmailChallenge(context.Background(), registered.Account.Subject.ID,
						goauth.EmailChallengePurposeVerification, differentCode(code))
					require.ErrorIs(t, err, goauth.ErrInvalidConfirmationCode)
				}
				fail.Store(false)
				_, err = fixture.Runtime.VerifyEmailChallenge(context.Background(), registered.Account.Subject.ID,
					goauth.EmailChallengePurposeVerification, code)
				require.ErrorIs(t, err, goauth.ErrConfirmationAttempts)
				return
			}
			_, err = fixture.Runtime.VerifyEmailChallenge(context.Background(), registered.Account.Subject.ID,
				goauth.EmailChallengePurposeVerification, code)
			require.ErrorIs(t, err, errAtomicityHook)
			account, err := fixture.Store.GetAccount(context.Background(), registered.Account.Subject.ID)
			require.NoError(t, err)
			require.False(t, account.EmailVerified())
			fail.Store(false)
			account, err = fixture.Runtime.VerifyEmailChallenge(context.Background(), registered.Account.Subject.ID,
				goauth.EmailChallengePurposeVerification, code)
			require.NoError(t, err)
			require.True(t, account.EmailVerified())
		})
	}
}
