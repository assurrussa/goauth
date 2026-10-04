package postgres //nolint:testpackage // Exercise rejection before any SQL and immutable migration bytes.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestSessionOIDCRequiresManagedTransaction(t *testing.T) {
	t.Parallel()
	trace := &ownedTransactionTrace{}
	runtime := ownedTransactionRuntime(t, trace)
	runtime.oidcRefreshTokens = &OIDCRefreshTokenStore{db: runtime.db}
	state, err := NewSessionOIDCState(runtime)
	require.NoError(t, err)
	for _, operation := range []func(context.Context) error{
		func(ctx context.Context) error { return state.SaveRequest(ctx, oidc.SessionRequest{}) },
		func(ctx context.Context) error {
			return state.MarkLoginComplete(ctx, "x", "y", oidc.RequestLoginCompletion{})
		},
		func(ctx context.Context) error { _, err := state.ConsumeRequest(ctx, "x"); return err },
		func(ctx context.Context) error { return state.SaveCode(ctx, oidc.SessionCode{}) },
		func(ctx context.Context) error { _, err := state.LockCode(ctx, "x"); return err },
		func(ctx context.Context) error { _, err := state.ConsumeCode(ctx, "x", "", time.Now()); return err },
		func(ctx context.Context) error { _, err := state.LockRefresh(ctx, "x"); return err },
		func(ctx context.Context) error { return state.SaveRefresh(ctx, oidc.SessionRefresh{}) },
		func(ctx context.Context) error {
			return state.RotateRefresh(ctx, oidc.SessionRefresh{}, oidc.SessionRefresh{}, time.Now())
		},
		func(ctx context.Context) error { return state.RevokeFamily(ctx, "x", oidc.SessionRevoked, time.Now()) },
		func(ctx context.Context) error { _, err := state.LockFamily(ctx, "x"); return err },
	} {
		require.ErrorContains(t, operation(t.Context()), "requires managed auth transaction")
	}
	require.Zero(t, trace.begins.Load())
	require.Zero(t, trace.writes.Load())
	foreign := ownedTransactionRuntime(t, &ownedTransactionTrace{})
	require.NoError(t, foreign.InAuthTransaction(t.Context(), func(ctx context.Context) error {
		require.ErrorIs(t, state.SaveRequest(ctx, oidc.SessionRequest{}), errForeignNotificationTransaction)
		_, err := state.ReadCode(ctx, "x")
		require.ErrorIs(t, err, errForeignNotificationTransaction)
		_, err = state.ReadRefresh(ctx, "x")
		require.ErrorIs(t, err, errForeignNotificationTransaction)
		_, err = state.ReadRequest(ctx, "x")
		require.ErrorIs(t, err, errForeignNotificationTransaction)
		return nil
	}))
	_, err = NewSessionOIDCState(nil)
	require.Error(t, err)
	require.NoError(t, state.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
		called := false
		err := state.InOwnedAuthTransaction(ctx, func(context.Context) error { called = true; return nil })
		require.ErrorIs(t, err, ErrAuthTransactionAlreadyActive)
		require.False(t, called)
		return nil
	}))
}

func TestSessionOIDCMigrationPreservesSchema7(t *testing.T) {
	t.Parallel()
	require.Equal(t, 8, schemaVersion)
	data, err := migrationFiles.ReadFile("migrations/00006_rate_event_cleanup.sql")
	require.NoError(t, err)
	checksum := sha256.Sum256(data)
	require.Equal(t, "73d3cbce006273a6dc3db1202bd046bb2de9a0e95cf5766ad67eba6d67ca4552", hex.EncodeToString(checksum[:]))
}
