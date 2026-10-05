package goauth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const loginConfirmationSuspend = "suspend"

type loginConfirmationStore struct {
	goauth.RuntimeStore
	afterRead func()
	afterLock func(goauth.Account) goauth.Account
	records   []goauth.SessionRecord
}

func (s *loginConfirmationStore) FindLocalAccount(
	ctx context.Context, identifier goauth.IdentifierInput,
) (goauth.LocalAccountRecord, error) {
	record, err := s.RuntimeStore.FindLocalAccount(ctx, identifier)
	if err == nil && s.afterRead != nil {
		afterRead := s.afterRead
		s.afterRead = nil
		afterRead()
	}
	return record, err
}

func (s *loginConfirmationStore) LockAccount(ctx context.Context, subjectID goauth.SubjectID) (goauth.Account, error) {
	account, err := s.RuntimeStore.LockAccount(ctx, subjectID)
	if err == nil && s.afterLock != nil {
		account = s.afterLock(account)
	}
	return account, err
}

func (s *loginConfirmationStore) CreateSession(ctx context.Context, record goauth.SessionRecord) error {
	s.records = append(s.records, record)
	return s.RuntimeStore.CreateSession(ctx, record)
}

type loginCountingHasher struct {
	goauth.PasswordHasher
	verifications int
}

func (h *loginCountingHasher) VerifyPassword(hash, password string) error {
	h.verifications++
	return h.PasswordHasher.VerifyPassword(hash, password)
}

func TestLoginRepreparesAfterConcurrentEmailConfirmation(t *testing.T) {
	t.Parallel()
	for _, afterRead := range []bool{true, false} {
		name := "during claims preparation"
		if afterRead {
			name = "after credential snapshot"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			checkLoginConfirmationRepreparation(t, afterRead)
		})
	}
}

func checkLoginConfirmationRepreparation(t *testing.T, afterRead bool) {
	t.Helper()
	hasher := &loginCountingHasher{PasswordHasher: &legacyBcryptHasher{}}
	var store *loginConfirmationStore
	var duringClaims func()
	var snapshots []bool
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		hostStore := c.Store
		store = &loginConfirmationStore{RuntimeStore: hostStore}
		c.Store = store
		c.PasswordHasher = hasher
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			ctx context.Context, _ goauth.Realm, account goauth.Account, claims map[string]any,
		) error {
			// Hooks must stay outside the write transaction, including re-preparation.
			_, lockErr := hostStore.LockAccount(ctx, account.Subject.ID)
			if lockErr == nil {
				return errors.New("claims preparation holds the subject lock")
			}
			snapshots = append(snapshots, account.EmailVerified())
			claims["email_verified"] = account.EmailVerified()
			if duringClaims != nil {
				fn := duringClaims
				duringClaims = nil
				fn()
			}
			return nil
		})
	})
	require.NoError(t, err)
	const email = "login.confirmation.race@example.test"
	registered := registerAccount(t, fixture, email)
	code := issueLoginChallenge(t, fixture, registered.Account.Subject.ID)
	confirm := func() {
		account, verifyErr := fixture.Runtime.VerifyEmailChallenge(t.Context(), registered.Account.Subject.ID,
			goauth.EmailChallengePurposeVerification, code)
		require.NoError(t, verifyErr)
		require.True(t, account.EmailVerified())
	}
	if afterRead {
		store.afterRead = confirm
	} else {
		duringClaims = confirm
	}
	snapshots = nil
	before := hasher.verifications
	loggedIn, err := fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, goauth.RealmUser))
	require.NoError(t, err)
	require.Equal(t, before+1, hasher.verifications, "the password proof must not be rerun or upgraded")
	require.Equal(t, []bool{false, true}, snapshots, "exactly one re-preparation must use the fresh verified account")
	require.Len(t, store.records, 2, "discarded preparation must not write any session or refresh family")
	require.True(t, loggedIn.Account.EmailVerified())
	require.Equal(t, registered.Account.Subject.SecurityVersion, loggedIn.Account.Subject.SecurityVersion)
	assertLoginScope(t, fixture, loggedIn.Tokens, goauth.SessionScopeAuthenticated)
	auth, err := fixture.Runtime.VerifyJWT(t.Context(), loggedIn.Tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, true, auth.Claims["email_verified"])
	assertConfirmedLoginRefresh(t, fixture, loggedIn.Tokens, code)
}

func TestLoginCommittedBeforeEmailConfirmationIsPromoted(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	const email = "login.before.confirmation@example.test"
	registered := registerAccount(t, fixture, email)
	code := issueLoginChallenge(t, fixture, registered.Account.Subject.ID)
	loggedIn, err := fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, goauth.RealmUser))
	require.NoError(t, err)
	assertLoginScope(t, fixture, loggedIn.Tokens, goauth.SessionScopeConfirmation)
	_, err = fixture.Runtime.VerifyEmailChallenge(t.Context(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification, code)
	require.NoError(t, err)
	_, err = fixture.Runtime.AuthenticateSession(t.Context(), loggedIn.Tokens.AccessToken)
	require.ErrorIs(t, err, goauth.ErrInvalidToken, "old confirmation JWT cannot impersonate its promoted scope")
	assertConfirmedLoginRefresh(t, fixture, loggedIn.Tokens, code)
}

func TestLoginConfirmationRetryPreservesRevocationFence(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{atomicityLogoutAll, loginConfirmationSuspend, "password change", "email change"} {
		t.Run(operation, func(t *testing.T) {
			t.Parallel()
			var hook func(goauth.Account) error
			var store *loginConfirmationStore
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				store = &loginConfirmationStore{RuntimeStore: c.Store}
				c.Store = store
				c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
					_ context.Context, _ goauth.Realm, account goauth.Account, _ map[string]any,
				) error {
					if hook != nil {
						return hook(account)
					}
					return nil
				})
			})
			require.NoError(t, err)
			const email = "login.confirmation.revoked@example.test"
			registered := registerAccount(t, fixture, email)
			code := issueLoginChallenge(t, fixture, registered.Account.Subject.ID)
			calls := 0
			hook = func(account goauth.Account) error {
				calls++
				if calls == 1 {
					_, verifyErr := fixture.Runtime.VerifyEmailChallenge(t.Context(), account.Subject.ID,
						goauth.EmailChallengePurposeVerification, code)
					return verifyErr
				}
				return revokeLoginPreparation(t, fixture, account.Subject.ID, operation)
			}
			result, err := fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, goauth.RealmUser))
			if operation == loginConfirmationSuspend {
				require.ErrorIs(t, err, goauth.ErrAccountUnavailable)
			} else {
				require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
			}
			require.Zero(t, result)
			require.Equal(t, 2, calls)
			require.Len(t, store.records, 1, "neither preparation may create a session")
		})
	}
}

func revokeLoginPreparation(t *testing.T, fixture *testkit.Fixture, subjectID goauth.SubjectID, operation string) error {
	t.Helper()
	switch operation {
	case atomicityLogoutAll:
		_, err := fixture.Runtime.LogoutAll(t.Context(), subjectID)
		return err
	case loginConfirmationSuspend:
		_, err := fixture.Runtime.SetSubjectStatus(t.Context(), subjectID, goauth.SubjectStatusSuspended)
		return err
	case "password change":
		_, err := fixture.Runtime.ChangePassword(t.Context(), goauth.ChangePasswordRequest{
			SubjectID: subjectID, CurrentPassword: testPassword, NewPassword: "Login-Replacement-Passphrase-2",
		})
		return err
	default:
		require.NoError(t, fixture.Runtime.RequestEmailChange(t.Context(), subjectID, "login.changed@example.test"))
		_, err := fixture.Runtime.ConfirmEmailChange(t.Context(), subjectID, latestEmailChangeCode(t, fixture))
		return err
	}
}

func TestLoginConfirmationDoesNotBypassCredentialsOrRealmGates(t *testing.T) {
	t.Parallel()
	var gateCalls int
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		c.AdditionalRealms = []goauth.Realm{supportRealm}
		c.MembershipGate = goauth.MembershipGateFunc(func(context.Context, goauth.Realm, goauth.Account) error {
			gateCalls++
			return goauth.ErrMembershipDenied
		})
	})
	require.NoError(t, err)
	const email = "login.confirmation.gates@example.test"
	registered := registerAccount(t, fixture, email)
	code := issueLoginChallenge(t, fixture, registered.Account.Subject.ID)
	_, err = fixture.Runtime.Login(t.Context(), loginRequest(email, wrongTestPassword, goauth.RealmUser))
	require.ErrorIs(t, err, goauth.ErrInvalidCredentials)
	for _, realm := range []goauth.Realm{goauth.RealmAdmin, supportRealm} {
		_, err = fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, realm))
		require.ErrorIs(t, err, goauth.ErrEmailVerificationRequired)
	}
	require.Zero(t, gateCalls)
	wrongCode := "000000"
	if code == wrongCode {
		wrongCode = "111111"
	}
	_, err = fixture.Runtime.VerifyEmailChallenge(t.Context(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification, wrongCode)
	require.Error(t, err)
	loggedIn, err := fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, goauth.RealmUser))
	require.NoError(t, err)
	assertLoginScope(t, fixture, loggedIn.Tokens, goauth.SessionScopeConfirmation)
	_, err = fixture.Runtime.VerifyEmailChallenge(t.Context(), registered.Account.Subject.ID,
		goauth.EmailChallengePurposeVerification, code)
	require.NoError(t, err)
	for _, realm := range []goauth.Realm{goauth.RealmAdmin, supportRealm} {
		result, loginErr := fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, realm))
		require.ErrorIs(t, loginErr, goauth.ErrMembershipDenied)
		require.Zero(t, result)
	}
	require.Equal(t, 2, gateCalls)
}

func TestLoginConfirmationRetryRejectsChangedIdentity(t *testing.T) {
	t.Parallel()
	for _, changed := range []string{"subject", "email ID", "email subject", "email scheme", "email value"} {
		t.Run(changed, func(t *testing.T) {
			t.Parallel()
			var store *loginConfirmationStore
			fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
				store = &loginConfirmationStore{RuntimeStore: c.Store}
				c.Store = store
			})
			require.NoError(t, err)
			const email = "login.confirmation.identity@example.test"
			registered := registerAccount(t, fixture, email)
			changeIdentity := func(account goauth.Account) goauth.Account {
				switch changed {
				case "subject":
					account.Subject.ID = goauth.NewSubjectID()
				case "email ID":
					account.PrimaryEmail.ID = "replacement-email-id"
				case "email subject":
					account.PrimaryEmail.SubjectID = goauth.NewSubjectID()
				case "email scheme":
					account.PrimaryEmail.Scheme = employeeIdentifierScheme
				default:
					account.PrimaryEmail.NormalizedValue = "other@example.test"
				}
				return account
			}
			store.afterRead = func() {
				verifyEmail(t, fixture, registered.Account.Subject.ID)
				store.afterLock = changeIdentity
			}
			result, err := fixture.Runtime.Login(t.Context(), loginRequest(email, testPassword, goauth.RealmUser))
			require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
			require.Zero(t, result)
			require.Len(t, store.records, 1)
		})
	}
}

func TestCreateSessionRejectsStaleConfirmationScope(t *testing.T) {
	t.Parallel()
	var store *loginConfirmationStore
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		store = &loginConfirmationStore{RuntimeStore: c.Store}
		c.Store = store
	})
	require.NoError(t, err)
	registered := registerAccount(t, fixture, "login.direct.scope@example.test")
	verifyEmail(t, fixture, registered.Account.Subject.ID)
	stale := store.records[0]
	stale.Session.ID = "stale-confirmation-session"
	stale.FamilyID = "stale-confirmation-family"
	stale.RefreshSelector = "stale-confirmation-selector"
	require.ErrorIs(t, fixture.Store.CreateSession(t.Context(), stale), goauth.ErrSecurityVersionMismatch)
	_, err = fixture.Store.IntrospectSession(t.Context(), stale.Session.ID)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}

func issueLoginChallenge(t *testing.T, fixture *testkit.Fixture, subjectID goauth.SubjectID) string {
	t.Helper()
	require.NoError(t, fixture.Runtime.SendEmailChallenge(t.Context(), subjectID, goauth.EmailChallengePurposeVerification))
	return latestChallengeCode(t, fixture)
}

func assertLoginScope(t *testing.T, fixture *testkit.Fixture, tokens goauth.TokenPair, scope goauth.SessionScope) {
	t.Helper()
	auth, err := fixture.Runtime.AuthenticateSession(t.Context(), tokens.AccessToken)
	require.NoError(t, err)
	require.Equal(t, scope, auth.Scope)
	require.Equal(t, scope, tokens.Session.Scope)
	stored, err := fixture.Store.IntrospectSession(t.Context(), tokens.Session.ID)
	require.NoError(t, err)
	require.Equal(t, scope, stored.Session.Scope)
}

func assertConfirmedLoginRefresh(t *testing.T, fixture *testkit.Fixture, tokens goauth.TokenPair, code string) {
	t.Helper()
	rotated, err := fixture.Runtime.Refresh(t.Context(), tokens.RefreshToken)
	require.NoError(t, err)
	assertLoginScope(t, fixture, rotated, goauth.SessionScopeAuthenticated)
	_, err = fixture.Runtime.VerifyEmailChallenge(t.Context(), tokens.Session.SubjectID,
		goauth.EmailChallengePurposeVerification, code)
	require.NoError(t, err)
	again, err := fixture.Runtime.Refresh(t.Context(), rotated.RefreshToken)
	require.NoError(t, err)
	assertLoginScope(t, fixture, again, goauth.SessionScopeAuthenticated)
}
