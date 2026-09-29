//nolint:testpackage,goconst // Exercises shared refresh state and protocol claims.
package verifier

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestVerifierCanceledUnknownKeyDoesNotSpendCooldown(t *testing.T) {
	t.Parallel()
	key := testRSAKey(t)
	oldJWK := testJWK(t, "old", &key.PublicKey)
	newJWK := testJWK(t, "new", &key.PublicKey)
	var fetches atomic.Int32
	service, err := New(Options{
		Issuer: testIssuer, Audience: "app",
		HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			if err := r.Context().Err(); err != nil {
				return nil, err
			}
			if strings.Contains(r.URL.Path, ".well-known") {
				return jsonResponse(oidc.DiscoveryMetadata{Issuer: testIssuer, JWKSURI: testIssuer + "/jwks"}), nil
			}
			keys := []oidc.JWK{oldJWK}
			if fetches.Add(1) > 1 {
				keys = append(keys, newJWK)
			}
			return jsonResponse(oidc.JWKS{Keys: keys}), nil
		})},
	})
	require.NoError(t, err)
	require.NoError(t, service.ensureJWKS(context.Background(), false))
	claims := jwt.MapClaims{
		"iss": testIssuer, "aud": "app", "sub": "subject", "token_use": "access",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = service.VerifyAccessToken(ctx, signToken(t, key, "attacker", claims))
	require.ErrorIs(t, err, context.Canceled)
	require.EqualValues(t, 1, fetches.Load())
	service.mu.RLock()
	spentCooldown := !service.unknownRefreshAt.IsZero()
	service.mu.RUnlock()
	require.False(t, spentCooldown)
	_, err = service.VerifyAccessToken(context.Background(), signToken(t, key, "new", claims))
	require.NoError(t, err)
	require.EqualValues(t, 2, fetches.Load())
}

func TestVerifierInitiatorCancellationDoesNotCancelSharedFetch(t *testing.T) {
	t.Parallel()
	for _, force := range []bool{false, true} {
		name := "cold"
		if force {
			name = "rotation"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key := testRSAKey(t)
			jwk := testJWK(t, "new", &key.PublicKey)
			started, release := make(chan struct{}), make(chan struct{}, 1)
			defer close(release)
			var fetches atomic.Int32
			service, err := New(Options{
				Issuer: testIssuer, Audience: "app", HTTPTimeout: 2 * time.Second,
				HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
					if strings.Contains(r.URL.Path, ".well-known") {
						return jsonResponse(oidc.DiscoveryMetadata{Issuer: testIssuer, JWKSURI: testIssuer + "/jwks"}), nil
					}
					fetches.Add(1)
					close(started)
					select {
					case <-r.Context().Done():
						return nil, r.Context().Err()
					case <-release:
						return jsonResponse(oidc.JWKS{Keys: []oidc.JWK{jwk}}), nil
					}
				})},
			})
			require.NoError(t, err)
			if force {
				service.jwks["old"] = &key.PublicKey
				service.jwksFetched = time.Now()
				service.discovery = oidc.DiscoveryMetadata{Issuer: testIssuer, JWKSURI: testIssuer + "/jwks"}
				service.discoveryFetched = time.Now()
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- service.ensureJWKS(ctx, force) }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("shared fetch did not start")
			}
			service.mu.RLock()
			flight := service.refresh
			service.mu.RUnlock()
			require.NotNil(t, flight)
			cancel()
			select {
			case err := <-result:
				require.ErrorIs(t, err, context.Canceled)
			case <-time.After(time.Second):
				t.Fatal("initiator did not return promptly on cancellation")
			}
			select {
			case <-flight.done:
				t.Fatalf("caller cancellation ended shared flight: %v", flight.err)
			default:
			}
			// The next caller must join the same flight and receive its successful result.
			waiter := make(chan error, 1)
			go func() { waiter <- service.ensureJWKS(context.Background(), force) }()
			release <- struct{}{}
			select {
			case err := <-waiter:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("shared fetch did not finish")
			}
			require.EqualValues(t, 1, fetches.Load())
			require.Contains(t, service.snapshotJWKS(), "new")
		})
	}
}

func TestVerifierAbandonedSharedFetchRemainsBounded(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	service, err := New(Options{
		Issuer: testIssuer, Audience: "app", HTTPTimeout: 100 * time.Millisecond,
		HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			close(started)
			<-r.Context().Done()
			return nil, r.Context().Err()
		})},
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- service.ensureJWKS(ctx, true) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("shared fetch did not start")
	}
	service.mu.RLock()
	flight := service.refresh
	service.mu.RUnlock()
	require.NotNil(t, flight)
	cancel()
	select {
	case err := <-result:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("initiator did not return promptly on cancellation")
	}
	select {
	case <-flight.done:
		require.ErrorIs(t, flight.err, context.DeadlineExceeded)
	case <-time.After(time.Second):
		t.Fatal("abandoned shared fetch outlived its timeout")
	}
}
