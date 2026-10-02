package provider //nolint:testpackage // Verify clock propagation at the provider's storage boundary.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
)

type clockCheckingRefreshStore struct {
	oidc.RefreshTokenStore
	check func(context.Context)
}

func (s *clockCheckingRefreshStore) Rotate(
	ctx context.Context, current string, next oidc.RefreshToken, rotatedAt time.Time,
) error {
	s.check(ctx)
	return s.RefreshTokenStore.Rotate(ctx, current, next, rotatedAt)
}

func TestRefreshPropagatesConfiguredClockToRotation(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	h.now = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	opts := providerOptions(h)
	checks := 0
	opts.RefreshTokens = &clockCheckingRefreshStore{RefreshTokenStore: h.refreshTokens, check: func(ctx context.Context) {
		checks++
		require.Equal(t, h.now, authclock.Now(ctx, time.Time{}, time.Now()))
	}}
	var err error
	h.service, err = New(opts)
	require.NoError(t, err)
	require.NoError(t, h.refreshTokens.Save(t.Context(), oidc.RefreshToken{
		Token: "clock-refresh-current", SubjectID: h.subject.Subject.ID.String(), ClientID: h.client.ID,
		Scopes: []string{oidc.ScopeOpenID, oidc.ScopeOfflineAccess}, SecurityVersion: h.subject.Subject.SecurityVersion,
		AuthenticatedAt: h.now, CreatedAt: h.now, ExpiresAt: h.now.Add(time.Hour),
	}))
	_, err = h.service.ExchangeToken(t.Context(), oidc.TokenRequest{
		GrantType: grantTypeRefreshToken, RefreshToken: "clock-refresh-current", ClientID: h.client.ID,
	})
	require.NoError(t, err)
	require.Equal(t, 1, checks)
}
