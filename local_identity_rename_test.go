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
	renameCollision       = "collision"
	renameHostFailure     = "host failure"
	renameResolverFailure = "resolver error"
	renameOtherScheme     = "rename_other"
	renameUnknownScheme   = "rename_missing"
	renameUnknownOutcome  = "unknown rename outcome"
)

func renameRequest(account goauth.Account, old, next string) goauth.RenameLocalIdentityRequest {
	return goauth.RenameLocalIdentityRequest{
		SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
		ExpectedIdentifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: old},
		NewIdentifier:      goauth.IdentifierInput{Scheme: localIdentityScheme, Value: next},
	}
}

func provisionRenameIdentity(t *testing.T, f *testkit.Fixture, value string) goauth.Account {
	t.Helper()
	account, err := f.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: value}, Password: testPassword,
		Profile: goauth.BasicProfile{Username: "profile-only", DisplayName: "Profile"},
	})
	require.NoError(t, err)
	return account
}

func TestLocalIdentityRenamePreservesIdentityAndCredential(t *testing.T) {
	for _, status := range []goauth.SubjectStatus{
		goauth.SubjectStatusActive, goauth.SubjectStatusSuspended, goauth.SubjectStatusDisabled,
	} {
		t.Run(string(status), func(t *testing.T) {
			var audits []goauth.SecurityEvent
			f := localIdentityFixture(t, func(c *goauth.Config) {
				base := c.AuditSink
				c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
					if event.Type == goauth.SecurityEventLocalIdentityRenamed {
						audits = append(audits, event)
					}
					return base.RecordSecurityEvent(ctx, event)
				})
			})
			request := localIdentityImport(localIdentityLegacyPassword)
			request.Status, request.Profile = status, goauth.BasicProfile{Username: "unrelated", DisplayName: "Preserved"}
			account, err := f.Runtime.ImportLocalIdentity(t.Context(), request)
			require.NoError(t, err)
			before, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			identifier, err := f.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, localIdentityScheme)
			require.NoError(t, err)
			require.Equal(t, request.Identifier.Value, identifier.DisplayValue)
			changed, err := f.Runtime.RenameLocalIdentity(t.Context(), renameRequest(account, request.Identifier.Value, "legacylogin"))
			require.NoError(t, err)
			require.Equal(t, account.Subject.ID, changed.Account.Subject.ID)
			require.Equal(t, status, changed.Account.Subject.Status)
			require.Equal(t, account.Subject.SecurityVersion+1, changed.Account.Subject.SecurityVersion)
			require.Equal(t, account.Subject.CreatedAt, changed.Account.Subject.CreatedAt)
			require.Equal(t, account.Profile, changed.Account.Profile)
			require.Equal(t, account.PrimaryEmail, changed.Account.PrimaryEmail)
			require.Equal(t, identifier.ID, changed.Identifier.ID)
			require.Equal(t, identifier.CreatedAt, changed.Identifier.CreatedAt)
			require.Equal(t, "legacylogin", changed.Identifier.DisplayValue)
			require.Equal(t, "legacylogin", changed.Identifier.NormalizedValue)
			after, err := f.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, before.PasswordPHC, after.PasswordPHC)
			require.Equal(t, before.PasswordInputPolicy, after.PasswordInputPolicy)
			_, err = f.Runtime.FindAccount(t.Context(), request.Identifier)
			require.ErrorIs(t, err, goauth.ErrAccountNotFound)
			found, err := f.Runtime.FindAccount(t.Context(), goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "legacylogin"})
			require.NoError(t, err)
			require.Equal(t, account.Subject.ID, found.Subject.ID)
			if status == goauth.SubjectStatusActive {
				verified, err := f.Runtime.VerifyCredential(t.Context(), goauth.Credential{
					Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "legacylogin"}, Password: localIdentityLegacyPassword,
				})
				require.NoError(t, err)
				require.Equal(t, account.Subject.ID, verified.Subject.ID)
			}
			replacement := provisionRenameIdentity(t, f, request.Identifier.Value)
			require.NotEqual(t, account.Subject.ID, replacement.Subject.ID)
			require.EqualValues(t, 1, replacement.Subject.SecurityVersion)
			require.Len(t, audits, 1)
			require.Equal(t, account.Subject.ID, audits[0].SubjectID)
			require.Empty(t, audits[0].Attributes)
			require.Empty(t, f.Events.Events())
		})
	}
}

func TestLocalIdentityRenameNormalizedDisplayAndCAS(t *testing.T) {
	f := localIdentityFixture(t, func(c *goauth.Config) {
		c.IdentifierResolvers[localIdentityScheme] = goauth.IdentifierResolverFunc(func(
			_ context.Context, in goauth.IdentifierInput,
		) (goauth.IdentifierInput, error) {
			in.Value = strings.ToLower(in.Value)
			return in, nil
		})
	})
	account := provisionRenameIdentity(t, f, "Alice")
	original, err := f.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, localIdentityScheme)
	require.NoError(t, err)
	changed, err := f.Runtime.RenameLocalIdentity(t.Context(), renameRequest(account, "ALICE", "ALIce"))
	require.NoError(t, err)
	require.Equal(t, "ALIce", changed.Identifier.DisplayValue)
	require.Equal(t, "alice", changed.Identifier.NormalizedValue)
	require.EqualValues(t, 2, changed.Account.Subject.SecurityVersion)
	noOp := renameRequest(changed.Account, "alice", "ALIce")
	empty, err := f.Runtime.RenameLocalIdentity(t.Context(), noOp)
	require.ErrorIs(t, err, goauth.ErrIdentifierUnchanged)
	require.Zero(t, empty)
	noOp.ExpectedSecurityVersion = 1
	_, err = f.Runtime.RenameLocalIdentity(t.Context(), noOp)
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	back, err := f.Runtime.RenameLocalIdentity(t.Context(), renameRequest(changed.Account, "alice", "Alice"))
	require.NoError(t, err)
	require.EqualValues(t, 3, back.Account.Subject.SecurityVersion)
	require.Equal(t, original.ID, back.Identifier.ID)
	_, err = f.Runtime.RenameLocalIdentity(t.Context(), renameRequest(account, "Alice", "Bob"))
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	wrong := renameRequest(back.Account, "nobody", "Bob")
	_, err = f.Runtime.RenameLocalIdentity(t.Context(), wrong)
	require.ErrorIs(t, err, goauth.ErrLocalIdentifierConflict)
}

func TestLocalIdentityRenameInputBoundaries(t *testing.T) {
	for _, field := range []string{
		"empty scheme", "email", renameUnknownOutcome, "different scheme", "zero subject", "zero version", "negative version",
		"empty old", "empty new", "long old", "long new", "NUL", "UTF8",
		"normalized long", "normalized NUL", "normalized UTF8", "normalized empty", "normalized scheme", renameResolverFailure,
	} {
		t.Run(field, func(t *testing.T) {
			failure := errors.New("resolver failed")
			mutate := false
			f := localIdentityFixture(t, func(c *goauth.Config) {
				c.IdentifierResolvers[localIdentityScheme] = goauth.IdentifierResolverFunc(func(
					_ context.Context, in goauth.IdentifierInput,
				) (goauth.IdentifierInput, error) {
					if !mutate {
						return in, nil
					}
					switch field {
					case "normalized long":
						in.Value = strings.Repeat("x", 257)
					case "normalized NUL":
						in.Value = "a\x00b"
					case "normalized UTF8":
						in.Value = string([]byte{0xff})
					case "normalized empty":
						in.Value = ""
					case "normalized scheme":
						in.Scheme = renameOtherScheme
					case renameResolverFailure:
						return goauth.IdentifierInput{}, failure
					}
					return in, nil
				})
			})
			account := provisionRenameIdentity(t, f, "Before")
			request := renameRequest(account, "Before", "After")
			expected := goauth.ErrInvalidIdentifier
			switch field {
			case "empty scheme":
				request.ExpectedIdentifier.Scheme = ""
				request.NewIdentifier.Scheme = ""
				expected = goauth.ErrInvalidIdentifierScheme
			case "email":
				request.ExpectedIdentifier.Scheme = goauth.IdentifierSchemeEmail
				request.NewIdentifier.Scheme = goauth.IdentifierSchemeEmail
				expected = goauth.ErrInvalidIdentifierScheme
			case renameUnknownOutcome:
				request.ExpectedIdentifier.Scheme = renameUnknownScheme
				request.NewIdentifier.Scheme = renameUnknownScheme
				expected = goauth.ErrInvalidIdentifierScheme
			case "different scheme":
				request.NewIdentifier.Scheme = renameOtherScheme
				expected = goauth.ErrInvalidIdentifierScheme
			case "zero subject":
				request.SubjectID = goauth.NilSubjectID
				expected = goauth.ErrAccountNotFound
			case "zero version":
				request.ExpectedSecurityVersion = 0
				expected = goauth.ErrSecurityVersionMismatch
			case "negative version":
				request.ExpectedSecurityVersion = -1
				expected = goauth.ErrSecurityVersionMismatch
			case "empty old":
				request.ExpectedIdentifier.Value = ""
			case "empty new":
				request.NewIdentifier.Value = ""
			case "long old":
				request.ExpectedIdentifier.Value = strings.Repeat("x", 257)
			case "long new":
				request.NewIdentifier.Value = strings.Repeat("é", 129)
			case "NUL":
				request.NewIdentifier.Value = "a\x00b"
			case "UTF8":
				request.NewIdentifier.Value = string([]byte{0xff})
			case renameResolverFailure:
				expected = failure
			}
			mutate = true
			result, err := f.Runtime.RenameLocalIdentity(t.Context(), request)
			require.ErrorIs(t, err, expected)
			require.Zero(t, result)
			stored, err := f.Runtime.GetAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			require.Equal(t, account, stored)
			current, err := f.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, localIdentityScheme)
			require.NoError(t, err)
			require.Equal(t, "Before", current.DisplayValue)
		})
	}
}

func TestLocalIdentifierReaderBoundariesAndUnsupported(t *testing.T) {
	f := localIdentityFixture(t)
	account := provisionRenameIdentity(t, f, "Reader")
	for _, scheme := range []goauth.IdentifierScheme{"", goauth.IdentifierSchemeEmail, renameUnknownOutcome} {
		value, err := f.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, scheme)
		require.ErrorIs(t, err, goauth.ErrInvalidIdentifierScheme)
		require.Zero(t, value)
	}
	_, err := f.Runtime.GetLocalIdentifier(t.Context(), goauth.NilSubjectID, localIdentityScheme)
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	_, err = f.Runtime.GetLocalIdentifier(t.Context(), goauth.NewSubjectID(), localIdentityScheme)
	require.ErrorIs(t, err, goauth.ErrLocalIdentifierConflict)
	missing := goauth.Account{Subject: goauth.Subject{ID: goauth.NewSubjectID(), SecurityVersion: 1}}
	_, err = f.Runtime.RenameLocalIdentity(t.Context(), renameRequest(missing, "Reader", "Next"))
	require.ErrorIs(t, err, goauth.ErrAccountNotFound)
	email, err := f.Runtime.ProvisionTrustedLocalAccount(t.Context(), goauth.RegisterRequest{
		Email: "reader@example.test", Password: testPassword,
	})
	require.NoError(t, err)
	_, err = f.Runtime.RenameLocalIdentity(t.Context(), renameRequest(email, "Reader", "Next"))
	require.ErrorIs(t, err, goauth.ErrLocalIdentifierConflict)
	unsupported := localIdentityFixture(t, func(c *goauth.Config) { c.Store = trustedSetUnsupportedStore{c.Store} })
	_, err = unsupported.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, localIdentityScheme)
	require.ErrorIs(t, err, goauth.ErrLocalIdentifierUnsupported)
	result, err := unsupported.Runtime.RenameLocalIdentity(t.Context(), renameRequest(account, "Reader", "Next"))
	require.ErrorIs(t, err, goauth.ErrLocalIdentityRenameUnsupported)
	require.Zero(t, result)
}

func TestLocalIdentityRenameCollisionAndRollback(t *testing.T) {
	for _, stage := range []string{renameCollision, "mandatory audit failure", renameHostFailure, renameUnknownOutcome} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("host audit failed")
			var transaction goauth.AuthTransaction
			f := localIdentityFixture(t, func(c *goauth.Config) {
				transaction = c.AuthTransaction
				if stage == "mandatory audit failure" {
					base := c.AuditSink
					c.AuditSink = goauth.AuditSinkFunc(func(ctx context.Context, event goauth.SecurityEvent) error {
						if event.Type == goauth.SecurityEventLocalIdentityRenamed {
							return failure
						}
						return base.RecordSecurityEvent(ctx, event)
					})
				}
			})
			account := provisionRenameIdentity(t, f, "Before")
			login, err := f.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: goauth.Credential{
				Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "Before"}, Password: testPassword,
			}})
			require.NoError(t, err)
			if stage == renameCollision {
				provisionRenameIdentity(t, f, "After")
			}
			request := renameRequest(account, "Before", "After")
			switch stage {
			case renameHostFailure:
				err = transaction.InAuthTransaction(t.Context(), func(ctx context.Context) error {
					view, e := f.Runtime.RenameLocalIdentity(ctx, request)
					require.NoError(t, e)
					require.EqualValues(t, 2, view.Account.Subject.SecurityVersion)
					read, e := f.Runtime.GetLocalIdentifier(ctx, account.Subject.ID, localIdentityScheme)
					require.NoError(t, e)
					require.Equal(t, view.Identifier, read)
					return failure
				})
			case renameUnknownOutcome:
				uncertain := localIdentityFixture(t, func(c *goauth.Config) {
					c.Store = f.Store
					c.AuditSink = f.Store
					c.AuthTransaction = localIdentityUnknownTransaction{base: f.Store}
				})
				view, e := uncertain.Runtime.RenameLocalIdentity(t.Context(), request)
				err = e
				require.Zero(t, view)
			default:
				view, e := f.Runtime.RenameLocalIdentity(t.Context(), request)
				err = e
				require.Zero(t, view)
			}
			expected := failure
			if stage == renameCollision {
				expected = goauth.ErrIdentifierAlreadyExists
			}
			if stage == renameUnknownOutcome {
				expected = goauth.ErrOperationOutcomeUnknown
			}
			require.ErrorIs(t, err, expected)
			stored, err := f.Runtime.GetAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			identifier, err := f.Runtime.GetLocalIdentifier(t.Context(), account.Subject.ID, localIdentityScheme)
			require.NoError(t, err)
			_, sessionErr := f.Runtime.VerifyAccessToken(t.Context(), login.Tokens.AccessToken, true)
			if stage == renameUnknownOutcome {
				require.EqualValues(t, 2, stored.Subject.SecurityVersion)
				require.Equal(t, "After", identifier.DisplayValue)
				require.Error(t, sessionErr)
			} else {
				require.Equal(t, account, stored)
				require.Equal(t, "Before", identifier.DisplayValue)
				require.NoError(t, sessionErr)
			}
		})
	}
}

func TestLocalIdentityRenameInvalidatesPreparedLoginAndPasswordSet(t *testing.T) {
	var fixture *testkit.Fixture
	armed := false
	fixture = localIdentityFixture(t, func(c *goauth.Config) {
		c.ClaimsEnricher = goauth.ClaimsEnricherFunc(func(
			ctx context.Context, _ goauth.Realm, account goauth.Account, _ map[string]any,
		) error {
			if !armed {
				return nil
			}
			armed = false
			_, err := fixture.Runtime.RenameLocalIdentity(ctx, renameRequest(account, "Before", "After"))
			return err
		})
	})
	account := provisionRenameIdentity(t, fixture, "Before")
	armed = true
	result, err := fixture.Runtime.Login(t.Context(), goauth.LoginRequest{Credential: goauth.Credential{
		Identifier: goauth.IdentifierInput{Scheme: localIdentityScheme, Value: "Before"}, Password: testPassword,
	}})
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	require.Empty(t, result.Tokens.AccessToken)
	base, err := goauth.NewArgon2idHasher(goauth.Argon2idConfig{})
	require.NoError(t, err)
	hasher := &trustedSetHookHasher{PasswordHasher: base}
	setter := localIdentityFixture(t, func(c *goauth.Config) {
		c.Store = fixture.Store
		c.AuditSink = fixture.Store
		c.AuthTransaction = fixture.Store
		c.EnableLegacyBytes256 = false
		c.PasswordHasher = hasher
	})
	hasher.hook = func() {
		hasher.hook = nil
		current, e := fixture.Runtime.GetAccount(t.Context(), account.Subject.ID)
		require.NoError(t, e)
		_, e = fixture.Runtime.RenameLocalIdentity(t.Context(), renameRequest(current, "After", "Before"))
		require.NoError(t, e)
	}
	changed, err := setter.Runtime.SetTrustedLocalPassword(t.Context(), goauth.SetTrustedLocalPasswordRequest{
		SubjectID: account.Subject.ID, NewPassword: trustedSetPassword,
	})
	require.ErrorIs(t, err, goauth.ErrSecurityVersionMismatch)
	require.Zero(t, changed)
}
