package goauth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestConsumedRefreshSelectorRequiresValidSecretForReplay(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	registered := registerAccount(t, fixture, "refresh.selector@example.test")
	ctx := context.Background()

	rotated, err := fixture.Runtime.Refresh(ctx, registered.Tokens.RefreshToken)
	require.NoError(t, err)

	parts := strings.Split(registered.Tokens.RefreshToken, ".")
	require.Len(t, parts, 3)
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	_, err = fixture.Runtime.Refresh(ctx, strings.Join(parts, "."))
	require.ErrorIs(t, err, goauth.ErrInvalidToken)

	security, err := fixture.Store.IntrospectSession(ctx, rotated.Session.ID)
	require.NoError(t, err)
	require.Nil(t, security.Session.RevokedAt, "wrong secret must not revoke the active session")
	continued, err := fixture.Runtime.Refresh(ctx, rotated.RefreshToken)
	require.NoError(t, err, "the active refresh family must remain usable")

	_, err = fixture.Runtime.Refresh(ctx, registered.Tokens.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrRefreshReplay)
	security, err = fixture.Store.IntrospectSession(ctx, rotated.Session.ID)
	require.NoError(t, err)
	require.NotNil(t, security.Session.RevokedAt, "authenticated replay must revoke the session")
	_, err = fixture.Runtime.Refresh(ctx, continued.RefreshToken)
	require.ErrorIs(t, err, goauth.ErrSessionRevoked)
}
