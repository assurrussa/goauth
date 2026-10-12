package goauth_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

const mfaStatusKeyID = "status-key"

type mfaStatusStore struct {
	goauth.RuntimeStore
	goauth.MFAStore
	account   goauth.Account
	session   goauth.SessionSecurity
	factor    goauth.MFAFactorRecord
	factorErr error
}

func (s *mfaStatusStore) LockAccount(context.Context, goauth.SubjectID) (goauth.Account, error) {
	return s.account, nil
}

func (s *mfaStatusStore) IntrospectSession(context.Context, string) (goauth.SessionSecurity, error) {
	return s.session, nil
}

func (s *mfaStatusStore) LockMFAFactor(context.Context, goauth.SubjectID) (goauth.MFAFactorRecord, error) {
	return s.factor, s.factorErr
}

type mfaStatusTransaction struct {
	goauth.AuthTransaction
	err error
}

func (s *mfaStatusTransaction) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if s.err != nil {
		return s.err
	}
	return fn(ctx)
}

func newMFAStatusFixture(t *testing.T, configured bool) (
	*goauth.Runtime, goauth.AuthContext, *mfaStatusStore, *mfaStatusTransaction,
) {
	t.Helper()
	now := time.Now().UTC()
	auth := goauth.AuthContext{
		SubjectID: goauth.NewSubjectID(), SessionID: "status-session", Realm: goauth.RealmUser,
		Scope: goauth.SessionScopeAuthenticated, SecurityVersion: 1,
	}
	store := &mfaStatusStore{
		account: goauth.Account{
			Subject: goauth.Subject{
				ID: auth.SubjectID, Status: goauth.SubjectStatusActive, SecurityVersion: auth.SecurityVersion,
			},
			PrimaryEmail: goauth.Identifier{
				SubjectID: auth.SubjectID, Scheme: goauth.IdentifierSchemeEmail, VerifiedAt: &now,
			},
		},
		session: goauth.SessionSecurity{
			Session: goauth.Session{
				ID: auth.SessionID, SubjectID: auth.SubjectID, Realm: auth.Realm, Scope: auth.Scope,
				SecurityVersion: auth.SecurityVersion, ExpiresAt: now.Add(time.Hour),
			},
			SubjectStatus: goauth.SubjectStatusActive, CurrentVersion: auth.SecurityVersion,
		},
	}
	transaction := &mfaStatusTransaction{}
	keys, err := goauth.NewKeyRing(mfaStatusKeyID, goauth.Key{
		ID: mfaStatusKeyID, Material: bytes.Repeat([]byte{94}, 32),
	})
	require.NoError(t, err)
	fixture, err := testkit.NewRuntime(func(c *goauth.Config) {
		store.RuntimeStore = c.Store
		transaction.AuthTransaction = c.AuthTransaction
		c.Store = store
		c.AuthTransaction = transaction
		c.Now = func() time.Time { return now }
		if configured {
			c.MFAKeys = &keys
		}
	})
	require.NoError(t, err)
	return fixture.Runtime, auth, store, transaction
}

func TestMFAStatusSeparatesEnrollmentFromAvailability(t *testing.T) {
	for _, test := range []struct {
		name       string
		configured bool
		enabled    bool
		keyID      string
		wantErr    error
	}{
		{name: "unenrolled without keys", wantErr: goauth.ErrMFAUnavailable},
		{name: "enrolled without keys", enabled: true, keyID: mfaStatusKeyID, wantErr: goauth.ErrMFAUnavailable},
		{name: "unenrolled with keys", configured: true},
		{name: "enrolled with keys", configured: true, enabled: true, keyID: mfaStatusKeyID},
		{
			name: "enrolled with missing historical key", configured: true, enabled: true,
			keyID: "retired-key", wantErr: goauth.ErrMFAUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, auth, store, _ := newMFAStatusFixture(t, test.configured)
			store.factor = goauth.MFAFactorRecord{Enabled: test.enabled, KeyID: test.keyID}
			enabled, err := runtime.MFAStatus(t.Context(), auth)
			require.ErrorIs(t, err, test.wantErr)
			require.Equal(t, test.enabled, enabled)
		})
	}
}

func TestMFAStatusPreservesAuthorizationAndStorageErrors(t *testing.T) {
	fault := errors.New("status storage unavailable")
	for _, test := range []struct {
		name    string
		mutate  func(*goauth.AuthContext, *mfaStatusStore, *mfaStatusTransaction)
		wantErr error
	}{
		{
			name: "unauthenticated request", wantErr: goauth.ErrMFALoginDenied,
			mutate: func(auth *goauth.AuthContext, _ *mfaStatusStore, _ *mfaStatusTransaction) {
				auth.Scope = goauth.SessionScopeConfirmation
			},
		},
		{
			name: "revoked session", wantErr: goauth.ErrMFALoginDenied,
			mutate: func(_ *goauth.AuthContext, store *mfaStatusStore, _ *mfaStatusTransaction) {
				revoked := time.Now()
				store.session.Session.RevokedAt = &revoked
			},
		},
		{
			name: "factor read failure", wantErr: fault,
			mutate: func(_ *goauth.AuthContext, store *mfaStatusStore, _ *mfaStatusTransaction) {
				store.factorErr = fault
			},
		},
		{
			name: "transaction failure", wantErr: fault,
			mutate: func(_ *goauth.AuthContext, _ *mfaStatusStore, transaction *mfaStatusTransaction) {
				transaction.err = fault
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, auth, store, transaction := newMFAStatusFixture(t, false)
			store.factor.Enabled = true
			test.mutate(&auth, store, transaction)
			enabled, err := runtime.MFAStatus(t.Context(), auth)
			require.ErrorIs(t, err, test.wantErr)
			require.False(t, enabled)
		})
	}
}
