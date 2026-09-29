//nolint:testpackage,goconst // Tests exercise internal security boundaries and repeat protocol claim names.
package verifier

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVerifierRequiresExpirationSubjectAndExactIssuer(t *testing.T) {
	t.Parallel()
	now := time.Now().Truncate(time.Second)
	key := testRSAKey(t)
	issuer := testIssuer + "/"
	transport := transportFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, ".well-known") {
			require.Equal(t, testIssuer+"/.well-known/openid-configuration", r.URL.String())
			return jsonResponse(oidc.DiscoveryMetadata{Issuer: issuer, JWKSURI: testIssuer + "/jwks"}), nil
		}
		return jsonResponse(oidc.JWKS{Keys: []oidc.JWK{testJWK(t, "key", &key.PublicKey)}}), nil
	})
	service, err := New(Options{Issuer: issuer, Audience: "app", HTTPClient: &http.Client{Transport: transport}})
	require.NoError(t, err)
	for _, tc := range []struct {
		name, issuer, subject string
		exp                   bool
		want                  string
	}{
		{"valid", issuer, "subject", true, ""},
		{"missing exp", issuer, "subject", false, "exp claim is required"},
		{"empty sub", issuer, "", true, "subject is required"},
		{"different slash", testIssuer, "subject", true, "invalid issuer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := jwt.MapClaims{"token_use": "access", "iss": tc.issuer, "aud": "app", "sub": tc.subject}
			if tc.exp {
				claims["exp"] = now.Add(time.Minute).Unix()
			}
			_, err := service.VerifyAccessToken(context.Background(), signToken(t, key, "key", claims))
			if tc.want == "" {
				require.NoError(t, err)
			} else {
				require.ErrorContains(t, err, tc.want)
			}
		})
	}
}

func TestVerifierRejectsDiscoveryIssuerAndInsecureJWKS(t *testing.T) {
	t.Parallel()
	for _, metadata := range []oidc.DiscoveryMetadata{
		{Issuer: testIssuer + "/", JWKSURI: testIssuer + "/jwks"},
		{Issuer: testIssuer, JWKSURI: "http://localhost/jwks"},
	} {
		service, err := New(Options{
			Issuer: testIssuer, Audience: "app",
			HTTPClient: &http.Client{Transport: transportFunc(func(_ *http.Request) (*http.Response, error) {
				return jsonResponse(metadata), nil
			})},
		})
		require.NoError(t, err)
		require.Error(t, service.ensureJWKS(context.Background(), false))
	}
}

func TestVerifierHTTPPolicyAndResponseLimit(t *testing.T) {
	t.Parallel()
	_, err := New(Options{Issuer: "http://localhost", Audience: "app"})
	require.ErrorContains(t, err, "HTTPS")
	_, err = New(Options{Issuer: " " + testIssuer, Audience: "app"})
	require.Error(t, err)
	var deadlineChecked atomic.Bool
	service, err := New(Options{
		Issuer: testIssuer, Audience: "app",
		HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			deadline, ok := r.Context().Deadline()
			require.True(t, ok)
			require.InDelta(t, 5, time.Until(deadline).Seconds(), .5)
			deadlineChecked.Store(true)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(strings.Repeat(" ", int(defaultMaxResponseBytes)+1))),
			}, nil
		})},
	})
	require.NoError(t, err)
	require.ErrorContains(t, service.ensureJWKS(context.Background(), false), "maximum size")
	require.True(t, deadlineChecked.Load())
	// A timeoutless custom client still gets a request deadline.
	service, err = New(Options{
		Issuer: testIssuer, Audience: "app", HTTPTimeout: 10 * time.Millisecond,
		HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			<-r.Context().Done()
			return nil, r.Context().Err()
		})},
	})
	require.NoError(t, err)
	require.ErrorIs(t, service.ensureJWKS(context.Background(), false), context.DeadlineExceeded)
}

func TestVerifierDoesNotFollowRedirectsOrMutateClient(t *testing.T) {
	t.Parallel()
	var destinationCalls atomic.Int32
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "destination.example" {
			destinationCalls.Add(1)
			return jsonResponse(oidc.DiscoveryMetadata{}), nil
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://destination.example"}},
			Body:       io.NopCloser(strings.NewReader("")), Request: r,
		}, nil
	})}
	service, err := New(Options{Issuer: "http://localhost", Audience: "app", AllowInsecureHTTP: true, HTTPClient: client})
	require.NoError(t, err)
	require.ErrorContains(t, service.ensureJWKS(context.Background(), false), "unexpected status 302")
	require.Zero(t, destinationCalls.Load())
	require.Nil(t, client.CheckRedirect)
	require.Zero(t, client.Timeout)
}

func TestVerifierCoalescesRefreshAndRecoversAfterFailureCooldown(t *testing.T) {
	t.Parallel()
	now := time.Now()
	oldKey := testRSAKey(t)
	newKey := testRSAKey(t)
	oldJWK := testJWK(t, "old", &oldKey.PublicKey)
	newJWK := testJWK(t, "new", &newKey.PublicKey)
	var discoveries, fetches atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	transport := transportFunc(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, ".well-known") {
			discoveries.Add(1)
			return jsonResponse(oidc.DiscoveryMetadata{Issuer: testIssuer, JWKSURI: testIssuer + "/jwks"}), nil
		}
		n := fetches.Add(1)
		if n > 1 && fail.Load() {
			return nil, errors.New("temporary JWKS failure")
		}
		keys := []oidc.JWK{oldJWK}
		if n > 1 {
			keys = append(keys, newJWK)
		}
		return jsonResponse(oidc.JWKS{Keys: keys}), nil
	})
	service, err := New(Options{
		Issuer: testIssuer, Audience: "app", HTTPClient: &http.Client{Transport: transport},
		Now: func() time.Time { return now },
	})
	require.NoError(t, err)
	require.NoError(t, service.ensureJWKS(context.Background(), false))
	token := signToken(t, newKey, "new", jwt.MapClaims{
		"token_use": "access",
		"iss":       testIssuer, "aud": "app", "sub": "subject", "exp": now.Add(time.Hour).Unix(),
	})
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, verifyErr := service.VerifyAccessToken(context.Background(), token)
			results <- verifyErr
		}()
	}
	wg.Wait()
	close(results)
	for verifyErr := range results {
		require.Error(t, verifyErr)
	}
	require.EqualValues(t, 2, fetches.Load())
	require.EqualValues(t, 1, discoveries.Load())
	// A failed rotation never discards the last valid key set.
	oldToken := signToken(t, oldKey, "old", jwt.MapClaims{
		"token_use": "access",
		"iss":       testIssuer, "aud": "app", "sub": "subject", "exp": now.Add(time.Hour).Unix(),
	})
	_, err = service.VerifyAccessToken(context.Background(), oldToken)
	require.NoError(t, err)
	fail.Store(false)
	_, err = service.VerifyAccessToken(context.Background(), token)
	require.ErrorIs(t, err, errUnknownKeyID)
	require.EqualValues(t, 2, fetches.Load())
	now = now.Add(unknownKeyRefreshCooldown)
	_, err = service.VerifyAccessToken(context.Background(), token)
	require.NoError(t, err)
	require.EqualValues(t, 3, fetches.Load())
	require.EqualValues(t, 1, discoveries.Load())
}

func TestVerifierCoalescesColdFetchAndWaiterCancellation(t *testing.T) {
	t.Parallel()
	key := testRSAKey(t)
	started, release := make(chan struct{}), make(chan struct{})
	var fetches atomic.Int32
	service, err := New(Options{
		Issuer: testIssuer, Audience: "app",
		HTTPClient: &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
			if strings.Contains(r.URL.Path, ".well-known") {
				return jsonResponse(oidc.DiscoveryMetadata{Issuer: testIssuer, JWKSURI: testIssuer + "/jwks"}), nil
			}
			fetches.Add(1)
			close(started)
			<-release
			return jsonResponse(oidc.JWKS{Keys: []oidc.JWK{testJWK(t, "key", &key.PublicKey)}}), nil
		})},
	})
	require.NoError(t, err)
	first := make(chan error, 1)
	go func() { first <- service.ensureJWKS(context.Background(), false) }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, service.ensureJWKS(ctx, false), context.Canceled)
	var wg sync.WaitGroup
	results := make(chan error, 32)
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); results <- service.ensureJWKS(context.Background(), false) }()
	}
	close(release)
	require.NoError(t, <-first)
	wg.Wait()
	close(results)
	for refreshErr := range results {
		require.NoError(t, refreshErr)
	}
	require.EqualValues(t, 1, fetches.Load())
}

func TestVerifierDiscoveryURLIsSeparateFromIssuerIdentity(t *testing.T) {
	t.Parallel()
	discoveryURL := "https://discovery.example/config?version=1"
	jwksURL := "https://keys.example/jwks?version=1"
	key := testRSAKey(t)
	transport := transportFunc(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case discoveryURL:
			return jsonResponse(oidc.DiscoveryMetadata{Issuer: testIssuer + "/", JWKSURI: jwksURL}), nil
		case jwksURL:
			return jsonResponse(oidc.JWKS{Keys: []oidc.JWK{testJWK(t, "key", &key.PublicKey)}}), nil
		default:
			return nil, errors.New("unexpected endpoint")
		}
	})
	service, err := New(Options{
		Issuer: testIssuer + "/", Audience: "app", DiscoveryURL: discoveryURL,
		HTTPClient: &http.Client{Transport: transport},
	})
	require.NoError(t, err)
	token := signToken(t, key, "key", jwt.MapClaims{
		"token_use": "access",
		"iss":       testIssuer + "/", "aud": "app", "sub": "subject", "exp": time.Now().Add(time.Minute).Unix(),
	})
	verified, err := service.VerifyAccessToken(context.Background(), token)
	require.NoError(t, err)
	require.Equal(t, testIssuer+"/", verified.Issuer)
}
