//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
	"github.com/assurrussa/goauth/oidc/provider"
)

type legacyReplayClients map[string]oidc.Client

func (clients legacyReplayClients) Get(_ context.Context, id string) (oidc.Client, error) {
	client, ok := clients[id]
	if !ok {
		return oidc.Client{}, errors.New("unknown synthetic client")
	}
	return client, nil
}

// Exercise the real legacy provider together with PostgreSQL. The token has
// already rotated: ownership and current secret authentication must precede any
// replay write, and the valid owner's denial must durably revoke exactly once.
func TestSessionOIDCLegacyProviderReplayAuthenticatesOwnerBeforeMutation(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		name := "exchange"
		if revoke {
			name = "revoke"
		}
		t.Run(name, func(t *testing.T) {
			runtime, _, r := sessionOIDCFixture(t)
			ctx := t.Context()
			store := runtime.OIDCRefreshTokens()
			require.NoError(t, store.Save(ctx, r.RefreshToken))
			next := r.RefreshToken
			next.Token = "provider-replay-next-" + uuid.NewString()
			next.CreatedAt = r.CreatedAt.Add(time.Second)
			require.NoError(t, store.Rotate(ctx, r.Token, next, next.CreatedAt))
			const ownerSecret = "synthetic-owner-secret"
			const otherSecret = "synthetic-other-secret"
			const otherID = "synthetic-other-client"
			clients := legacyReplayClients{
				r.ClientID: {ID: r.ClientID, Secret: ownerSecret, TokenEndpointAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic},
				otherID:    {ID: otherID, Secret: otherSecret, TokenEndpointAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic},
			}
			service, err := provider.New(provider.Options{
				Clients: clients, Requests: oidcRequestStoreStub{}, Codes: oidcCodeStoreStub{}, Keys: oidcKeyStoreStub{},
				RefreshTokens: store, Claims: runtime, Issuer: "https://synthetic-issuer.example.test",
				GenerateToken: func() (string, error) {
					t.Error("replay must not prepare tokens")
					return "", errors.New("unexpected token generation")
				},
			})
			require.NoError(t, err)
			invoke := func(id, secret string) error {
				if revoke {
					return service.Revoke(ctx, oidc.RevokeRequest{
						Token: r.Token, ClientID: id, ClientSecret: secret,
						ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
					})
				}
				response, err := service.ExchangeToken(ctx, oidc.TokenRequest{
					GrantType: "refresh_token", RefreshToken: r.Token,
					ClientID: id, ClientSecret: secret, ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
				})
				require.Nil(t, response)
				return err
			}
			assertUnchanged := func() {
				live, err := store.Get(ctx, next.Token)
				require.NoError(t, err)
				require.Nil(t, live.RevokedAt)
				var audits int
				require.NoError(t, runtime.Database().QueryRowContext(ctx,
					`SELECT count(*) FROM auth_security_audit_events WHERE event_type='oidc_refresh.replay'`).Scan(&audits))
				require.Zero(t, audits)
			}
			err = invoke(otherID, otherSecret)
			if !revoke {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assertUnchanged()
			require.Error(t, invoke(r.ClientID, "synthetic-wrong-secret"))
			assertUnchanged()
			err = invoke(r.ClientID, ownerSecret)
			if !revoke {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			live, err := store.Get(ctx, next.Token)
			require.NoError(t, err)
			require.NotNil(t, live.RevokedAt)
			var audits int
			require.NoError(t, runtime.Database().QueryRowContext(ctx,
				`SELECT count(*) FROM auth_security_audit_events WHERE event_type='oidc_refresh.replay'`).Scan(&audits))
			require.Equal(t, 1, audits)
		})
	}
}
