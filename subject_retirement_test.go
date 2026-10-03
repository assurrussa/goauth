package goauth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const (
	retirementScopeLogin    = "RetireScope"
	retirementRollbackLogin = "RetireRollback"
	retirementPreparedLogin = "RetirePrepared"
)

func retirementRequest(account goauth.Account, login string) goauth.RetireLocalIdentityRequest {
	return goauth.RetireLocalIdentityRequest{
		SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
		ExpectedIdentifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: login},
	}
}

func TestSubjectRetirementIsTerminalAndReleasesOnlySelectedLogin(t *testing.T) {
	for _, status := range []goauth.SubjectStatus{
		goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled,
	} {
		t.Run(string(status), func(t *testing.T) {
			var events []goauth.SecurityEvent
			f := localIdentityFixture(t, func(c *goauth.Config) {
				base := c.AuditSink
				c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
					if event.Type == goauth.SecurityEventSubjectRetired {
						events = append(events, event)
					}
					return base.RecordSecurityEvent(ctx, event)
				})
			})
			request := localIdentityImport(localIdentityLegacyPassword)
			request.Status = status
			account, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
			require.NoError(t, err)
			before, err := f.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, account, before.Account)
			require.Nil(t, before.RetiredAt)
			view, err := f.Runtime.RetireLocalIdentity(t.Context(), retirementRequest(account, request.Identifier.Value))
			require.NoError(t, err)
			require.Equal(t, account.Subject.ID, view.Account.Subject.ID)
			require.Equal(t, goauth.SubjectStatusDisabled, view.Account.Subject.Status)
			require.Equal(t, account.Subject.SecurityVersion+1, view.Account.Subject.SecurityVersion)
			require.Equal(t, account.Subject.CreatedAt, view.Account.Subject.CreatedAt)
			require.Equal(t, account.Profile, view.Account.Profile)
			require.Equal(t, account.PrimaryEmail, view.Account.PrimaryEmail)
			require.NotNil(t, view.RetiredAt)
			require.Equal(t, view.Account.Subject.UpdatedAt, *view.RetiredAt)
			read, err := f.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, view, read)
			// Mutating a returned timestamp must not mutate the supported in-memory store.
			*read.RetiredAt = read.RetiredAt.Add(1)
			read, err = f.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, view, read)
			_, err = f.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, localIdentityScheme)
			require.ErrorIs(t, err, goauth.ErrLocalIdentifierConflict)
			_, err = f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.ErrorIs(t, err, goauth.ErrAccountNotFound)
			repeated, err := f.Runtime.RetireLocalIdentity(t.Context(), retirementRequest(view.Account, request.Identifier.Value))
			require.ErrorIs(t, err, goauth.ErrSubjectRetired)
			require.Zero(t, repeated)
			for _, next := range []goauth.SubjectStatus{
				goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled,
			} {
				subject, err := f.Runtime.SetSubjectStatus(t.Context(), account.Subject.ID, next)
				require.ErrorIs(t, err, goauth.ErrSubjectRetired)
				require.Zero(t, subject)
			}
			_, err = f.Runtime.RenameLocalIdentity(t.Context(), renameRequest(view.Account, request.Identifier.Value, "UnusedRetired"))
			require.ErrorIs(t, err, goauth.ErrSubjectRetired)
			_, err = f.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
				SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
			})
			require.ErrorIs(t, err, goauth.ErrAccountNotFound)
			_, err = f.Store.LinkIdentity(t.Context(), goauth.IdentityLink{
				SubjectID: account.Subject.ID, Issuer: "https://retired.example.test", ExternalSubject: "retirement-link",
			})
			require.ErrorIs(t, err, goauth.ErrSubjectRetired)
			request.Identifier.Value = "AttemptSameUUID"
			_, err = f.Runtime.ImportLocalIdentity(t.Context(), request)
			require.ErrorIs(t, err, goauth.ErrIdentifierAlreadyExists)
			replacement := provisionRenameIdentity(t, f, localIdentityImport(localIdentityLegacyPassword).Identifier.Value)
			require.NotEqual(t, account.Subject.ID, replacement.Subject.ID)
			require.EqualValues(t, 1, replacement.Subject.SecurityVersion)
			require.Len(t, events, 1)
			require.Empty(t, events[0].Attributes)
			require.Empty(t, f.Events.Events())
			final, err := f.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, view, final)
		})
	}
}

func TestSubjectRetirementBoundariesAndCAS(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*goauth.RetireLocalIdentityRequest)
		want   error
	}{
		{"retire zero subject", func(r *goauth.RetireLocalIdentityRequest) {
			r.SubjectID = goauth.NilSubjectID
		}, goauth.ErrAccountNotFound},
		{"retire zero version", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedSecurityVersion = 0
		}, goauth.ErrSecurityVersionMismatch},
		{"stale version", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedSecurityVersion++
		}, goauth.ErrSecurityVersionMismatch},
		{"old login", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Value = "WrongLogin"
		}, goauth.ErrLocalIdentifierConflict},
		{"retire email scheme", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Scheme = goauth.IdentifierSchemeEmail
		}, goauth.ErrInvalidIdentifierScheme},
		{"missing scheme", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Scheme = ""
		}, goauth.ErrInvalidIdentifierScheme},
		{"unregistered scheme", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Scheme = "unregistered"
		}, goauth.ErrInvalidIdentifierScheme},
		{"empty", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Value = ""
		}, goauth.ErrInvalidIdentifier},
		{"retire NUL", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Value = "retire\x00login"
		}, goauth.ErrInvalidIdentifier},
		{"retire UTF8", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Value = string([]byte{0xff})
		}, goauth.ErrInvalidIdentifier},
		{"long", func(r *goauth.RetireLocalIdentityRequest) {
			r.ExpectedIdentifier.Value = strings.Repeat("é", 129)
		}, goauth.ErrInvalidIdentifier},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := localIdentityFixture(t)
			account := provisionRenameIdentity(t, f, "RetireBounded")
			request := retirementRequest(account, "RetireBounded")
			test.change(&request)
			view, err := f.Runtime.RetireLocalIdentity(t.Context(), request)
			require.ErrorIs(t, err, test.want)
			require.Zero(t, view)
			current, err := f.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Nil(t, current.RetiredAt)
			require.Equal(t, account, current.Account)
		})
	}
}

func TestSubjectLifecycleUnsupportedAndForeignScope(t *testing.T) {
	f := localIdentityFixture(t)
	account := provisionRenameIdentity(t, f, retirementScopeLogin)
	unsupported := localIdentityFixture(t, func(c *goauth.Config) { c.Store = trustedSetUnsupportedStore{c.Store} })
	view, err := unsupported.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrSubjectLifecycleUnsupported)
	require.Zero(t, view)
	view, err = unsupported.Runtime.RetireLocalIdentity(t.Context(), retirementRequest(account, retirementScopeLogin))
	require.ErrorIs(t, err, goauth.ErrLocalIdentityRetirementUnsupported)
	require.Zero(t, view)
	for _, id := range []goauth.SubjectID{goauth.NilSubjectID, goauth.NewSubjectID()} {
		view, err = f.Runtime.GetSubjectLifecycle(t.Context(), id)
		require.ErrorIs(t, err, goauth.ErrAccountNotFound)
		require.Zero(t, view)
	}
	foreign := testkit.NewStore()
	require.NoError(t, foreign.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		view, err := f.Runtime.GetSubjectLifecycle(ctx, account.Subject.ID)
		require.Error(t, err)
		require.Zero(t, view)
		view, err = f.Runtime.RetireLocalIdentity(ctx, retirementRequest(account, retirementScopeLogin))
		require.Error(t, err)
		require.Zero(t, view)
		return nil
	}))
}

func TestSubjectRetirementAuditAndOuterRollback(t *testing.T) {
	for _, audit := range []bool{true, false} {
		t.Run(map[bool]string{true: "retirement audit", false: "retirement outer"}[audit], func(t *testing.T) {
			failure := errors.New("synthetic retirement rollback")
			var transaction goauth.AuthTransaction
			f := localIdentityFixture(t, func(c *goauth.Config) {
				transaction = c.AuthTransaction
				base := c.AuditSink
				c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
					if audit && event.Type == goauth.SecurityEventSubjectRetired {
						return failure
					}
					return base.RecordSecurityEvent(ctx, event)
				})
			})
			account := provisionRenameIdentity(t, f, retirementRollbackLogin)
			if audit {
				view, err := f.Runtime.RetireLocalIdentity(t.Context(), retirementRequest(account, retirementRollbackLogin))
				require.ErrorIs(t, err, failure)
				require.Zero(t, view)
			} else {
				err := transaction.InAuthTransaction(t.Context(), func(ctx context.Context) error {
					view, err := f.Runtime.RetireLocalIdentity(ctx, retirementRequest(account, retirementRollbackLogin))
					require.NoError(t, err)
					read, err := f.Runtime.GetSubjectLifecycle(ctx, account.Subject.ID)
					require.NoError(t, err)
					require.Equal(t, view, read)
					return failure
				})
				require.ErrorIs(t, err, failure)
			}
			read, err := f.Runtime.GetSubjectLifecycle(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, account, read.Account)
			require.Nil(t, read.RetiredAt)
			_, err = f.Runtime.VerifyCredential(t.Context(), goauth.Credential{
				Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: retirementRollbackLogin}, Password: testPassword,
			})
			require.NoError(t, err)
		})
	}
}

func TestSubjectRetirementDeniesPreparedLoginAndPasswordSet(t *testing.T) {
	var f *testkit.Fixture
	armed := false
	f = localIdentityFixture(t, func(c *goauth.Config) {
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			ctx context.Context, _ goauth.Realm, account goauth.Account, _ map[string]any,
		) error {
			if !armed {
				return nil
			}
			armed = false
			_, err := f.Runtime.RetireLocalIdentity(ctx, retirementRequest(account, retirementPreparedLogin))
			return err
		})
	})
	provisionRenameIdentity(t, f, retirementPreparedLogin)
	armed = true
	result, err := f.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: retirementPreparedLogin}, Password: testPassword,
	}})
	require.Error(t, err)
	require.Empty(t, result.Tokens.AccessToken)
	base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	hasher := &trustedSetHookHasher{PasswordHasher: base}
	setter := localIdentityFixture(t, func(c *goauth.Config) { c.PasswordHasher = hasher; c.EnableLegacyBytes256 = false })
	account := provisionRenameIdentity(t, setter, "RetireHash")
	hasher.hook = func() {
		hasher.hook = nil
		_, err := setter.Runtime.RetireLocalIdentity(t.Context(), retirementRequest(account, "RetireHash"))
		require.NoError(t, err)
	}
	changed, err := setter.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
	})
	require.ErrorIs(t, err, goauth.ErrSubjectRetired)
	require.Zero(t, changed)
	_, err = setter.Store.GetLocalAccount(t.Context(), account.Subject.ID)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
}

func TestSubjectRetirementUsesRegisteredNormalizer(t *testing.T) {
	malformed := false
	fixture := localIdentityFixture(t, func(c *goauth.Config) {
		c.IdentifierResolvers[localIdentityScheme] = goauth.IdentifierResolverFunc(func(
			_ context.Context, input goauth.IdentifierInput,
		) (goauth.IdentifierInput, error) {
			input.Value = strings.ToLower(input.Value)
			if malformed {
				input.Value = ""
			}
			return input, nil
		})
	})
	account := provisionRenameIdentity(t, fixture, "RetireNormalized")
	malformed = true
	view, err := fixture.Runtime.RetireLocalIdentity(t.Context(), retirementRequest(account, "RETIRENORMALIZED"))
	require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
	require.Zero(t, view)
	malformed = false
	view, err = fixture.Runtime.RetireLocalIdentity(t.Context(), retirementRequest(account, "RETIRENORMALIZED"))
	require.NoError(t, err)
	require.NotNil(t, view.RetiredAt)
}
