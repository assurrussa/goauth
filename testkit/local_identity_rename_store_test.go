//nolint:testpackage // Exercises primary/secondary storage boundaries and fail-closed overflow.
package testkit

import (
	"context"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

const (
	renameStoreBefore = "Before"
	renameStoreAfter  = "After"
	renameStoreScheme = "custom"
)

func TestLocalIdentifierStorePrimaryOnlyAndRenameGuards(t *testing.T) {
	store := NewStore()
	id := goauth.NewSubjectID()
	now := time.Now().UTC()
	primary := goauth.Identifier{
		ID: "synthetic-primary", SubjectID: id, Scheme: renameStoreScheme, DisplayValue: renameStoreBefore,
		NormalizedValue: renameStoreBefore, CreatedAt: now, UpdatedAt: now,
	}
	account, err := store.CreateLocalIdentity(t.Context(), goauth.LocalIdentityRecord{
		LocalAccountRecord: goauth.LocalAccountRecord{
			Account: goauth.Account{Subject: goauth.Subject{
				ID: id, Status: goauth.SubjectStatusActive, SecurityVersion: 1, CreatedAt: now, UpdatedAt: now,
			}},
			PasswordPHC: "synthetic-phc", PasswordInputPolicy: goauth.PasswordInputPolicyUnicode,
		},
		Identifier: primary,
	})
	require.NoError(t, err)
	store.identifiers[identifierKey("alias_only", "Alias")] = id.String()
	_, err = store.GetLocalIdentifier(t.Context(), id, "alias_only")
	require.ErrorIs(t, err, goauth.ErrLocalIdentifierConflict)
	store.identifiers[identifierKey(renameStoreScheme, "Alias")] = id.String()
	base := goauth.RenameLocalIdentityStoreRequest{
		SubjectID: id, Scheme: renameStoreScheme, ExpectedNormalizedValue: renameStoreBefore, ExpectedSecurityVersion: 1,
		NewDisplayValue: renameStoreAfter, NewNormalizedValue: renameStoreAfter, Now: now,
	}
	for _, field := range []string{
		"subject", "scheme", "email-scheme", "version", "timestamp", "display", "normalized",
		"expected", "conflict", "alias", "overflow", "credential", "primary",
	} {
		t.Run(field, func(t *testing.T) {
			request := base
			expected := goauth.ErrInvalidIdentifier
			switch field {
			case "subject":
				request.SubjectID = goauth.NilSubjectID
				expected = goauth.ErrAccountNotFound
			case "scheme":
				request.Scheme = ""
				expected = goauth.ErrInvalidIdentifierScheme
			case "email-scheme":
				request.Scheme = goauth.IdentifierSchemeEmail
				expected = goauth.ErrInvalidIdentifierScheme
			case "version":
				request.ExpectedSecurityVersion = 0
				expected = goauth.ErrSecurityVersionMismatch
			case "timestamp":
				request.Now = time.Time{}
				expected = nil
			case "display":
				request.NewDisplayValue = strings.Repeat("x", 257)
			case "normalized":
				request.NewNormalizedValue = "x\x00"
			case "expected":
				request.ExpectedNormalizedValue = string([]byte{0xff})
			case "conflict":
				request.ExpectedNormalizedValue = "Wrong"
				expected = goauth.ErrLocalIdentifierConflict
			case "alias":
				request.NewNormalizedValue = "Alias"
				expected = goauth.ErrIdentifierAlreadyExists
			case "overflow":
				current := account
				current.Subject.SecurityVersion = math.MaxInt64
				store.accounts[id.String()] = current
				request.ExpectedSecurityVersion = math.MaxInt64
				expected = nil
			case "credential":
				delete(store.passwords, id.String())
				expected = goauth.ErrAccountNotFound
			case "primary":
				delete(store.localIdentifiers, localIdentifierKey(id, renameStoreScheme))
				expected = goauth.ErrLocalIdentifierConflict
			}
			result, err := store.RenameLocalIdentity(t.Context(), request)
			require.Error(t, err)
			require.Zero(t, result)
			if expected != nil {
				require.ErrorIs(t, err, expected)
			}
			require.Equal(t, id.String(), store.identifiers[identifierKey(renameStoreScheme, renameStoreBefore)])
			require.NotContains(t, store.identifiers, identifierKey(renameStoreScheme, renameStoreAfter))
			store.accounts[id.String()] = account
			store.passwords[id.String()] = "synthetic-phc"
			store.localIdentifiers[localIdentifierKey(id, renameStoreScheme)] = primary
		})
	}
	// A getter snapshot and a rolled-back transaction must not mutate stored pointers.
	verified := now
	primary.VerifiedAt = &verified
	store.localIdentifiers[localIdentifierKey(id, renameStoreScheme)] = primary
	copied, err := store.GetLocalIdentifier(t.Context(), id, renameStoreScheme)
	require.NoError(t, err)
	*copied.VerifiedAt = now.Add(time.Hour)
	require.Equal(t, now, *store.localIdentifiers[localIdentifierKey(id, renameStoreScheme)].VerifiedAt)
	require.NoError(t, store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		_, err := store.RenameLocalIdentity(ctx, base)
		return err
	}))
	changed, err := store.GetLocalIdentifier(t.Context(), id, renameStoreScheme)
	require.NoError(t, err)
	require.Equal(t, renameStoreAfter, changed.NormalizedValue)
}

func TestLocalIdentityRenameRejectsForeignTestkitTransaction(t *testing.T) {
	configure := func(c *goauth.Config) {
		c.IdentifierResolvers = map[goauth.IdentifierScheme]goauth.IdentifierResolver{
			renameStoreScheme: goauth.IdentifierResolverFunc(func(
				_ context.Context, input goauth.IdentifierInput,
			) (goauth.IdentifierInput, error) {
				return input, nil
			}),
		}
	}
	first, err := NewRuntime(configure)
	require.NoError(t, err)
	second, err := NewRuntime(configure)
	require.NoError(t, err)
	account, err := second.Runtime.ProvisionLocalIdentity(t.Context(), goauth.ProvisionLocalIdentityRequest{
		Identifier: goauth.IdentifierInput{Scheme: renameStoreScheme, Value: renameStoreBefore},
		Password:   "Synthetic-Foreign-Rename-Passphrase-42",
	})
	require.NoError(t, err)
	before, err := second.Store.GetLocalIdentifier(t.Context(), account.Subject.ID, renameStoreScheme)
	require.NoError(t, err)
	audits := len(second.Store.audits)
	request := goauth.RenameLocalIdentityRequest{
		SubjectID: account.Subject.ID, ExpectedSecurityVersion: account.Subject.SecurityVersion,
		ExpectedIdentifier: goauth.IdentifierInput{Scheme: renameStoreScheme, Value: renameStoreBefore},
		NewIdentifier:      goauth.IdentifierInput{Scheme: renameStoreScheme, Value: renameStoreAfter},
	}
	err = first.Store.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		read, err := second.Store.GetLocalIdentifier(ctx, account.Subject.ID, renameStoreScheme)
		require.ErrorIs(t, err, errForeignStoreTransaction)
		require.Zero(t, read)
		read, err = second.Runtime.GetLocalIdentifier(ctx, account.Subject.ID, renameStoreScheme)
		require.ErrorIs(t, err, errForeignStoreTransaction)
		require.Zero(t, read)
		direct, err := second.Store.RenameLocalIdentity(ctx, goauth.RenameLocalIdentityStoreRequest{
			SubjectID: account.Subject.ID, Scheme: renameStoreScheme, ExpectedSecurityVersion: account.Subject.SecurityVersion,
			ExpectedNormalizedValue: renameStoreBefore, NewDisplayValue: renameStoreAfter,
			NewNormalizedValue: renameStoreAfter, Now: time.Now(),
		})
		require.ErrorIs(t, err, errForeignStoreTransaction)
		require.Zero(t, direct)
		nested, err := second.Runtime.RenameLocalIdentity(ctx, request)
		require.ErrorIs(t, err, errForeignStoreTransaction)
		require.Zero(t, nested)
		require.ErrorIs(t, second.Store.InAuthTransaction(ctx, func(context.Context) error {
			t.Error("foreign transaction callback ran")
			return nil
		}), errForeignStoreTransaction)
		return errForeignStoreTransaction
	})
	require.ErrorIs(t, err, errForeignStoreTransaction)
	after, err := second.Store.GetLocalIdentifier(t.Context(), account.Subject.ID, renameStoreScheme)
	require.NoError(t, err)
	require.Equal(t, before, after)
	stored, err := second.Runtime.GetAccount(t.Context(), account.Subject.ID)
	require.NoError(t, err)
	require.Equal(t, account, stored)
	require.Len(t, second.Store.audits, audits)
}
