//nolint:testpackage // Verifies private strict claims and transactional denial paths.
package provider

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
)

func TestSessionBoundHappyPathAndNamespacedMetadata(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	ctx := context.Background()
	response := h.issue(t)
	require.NotEmpty(t, response.RefreshToken, "refresh does not require offline_access")
	require.LessOrEqual(t, response.ExpiresIn, int64(300))
	info, err := h.service.UserInfo(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Equal(t, h.admission.Projection.ProjectID, info.ProjectID)
	require.Equal(t, "display", info.Profile["name"])
	require.Equal(t, "unverified metadata", info.Profile[oidc.ScopeEmail])
	require.Equal(t, "blue", info.Project["team"])
	_, err = h.service.UserInfo(ctx, response.IDToken)
	requireOAuthError(t, err, "invalid_token")
	claims, err := h.service.parseSessionAccessToken(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Empty(t, claims.Profile)
	require.Equal(t, h.admission.Binding.AuthenticatedAt, claims.BindingAuthenticatedAt)
	d := h.service.Discovery(ctx)
	require.Equal(t, []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}, d.ScopesSupported)
	require.Contains(t, d.ClaimsSupported, "project_id")
	require.False(t, d.RequestURIParameterSupported)
	keys, err := h.service.JWKS(ctx)
	require.NoError(t, err)
	require.Len(t, keys.Keys, 1)
	h.admission.Projection.Profile["name"] = testSessionCurrent
	info, err = h.service.UserInfo(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Equal(t, testSessionCurrent, info.Profile["name"])
}

func TestSessionBoundProjectClaimWithoutProfile(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	req := h.authorizeRequest()
	req.Scope = oidc.ScopeOpenID
	ctx := context.Background()
	result, err := h.service.Authorize(ctx, req, h.browser())
	require.NoError(t, err)
	u, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	response, err := h.service.ExchangeToken(ctx, h.codeRequest(u.Query().Get(responseTypeCode)))
	require.NoError(t, err)
	info, err := h.service.UserInfo(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Equal(t, h.admission.Projection.ProjectID, info.ProjectID)
	require.Empty(t, info.Profile)
	claims := &sessionTokenClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(response.IDToken, claims)
	require.NoError(t, err)
	require.Equal(t, info.ProjectID, claims.ProjectID)
	require.Empty(t, claims.Profile)
}

func TestSessionRequestBoundMarkerEqualClockAndCookieGeneration(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	ctx := context.Background()
	req := h.authorizeRequest()
	req.Prompt = []string{testSessionLogin}
	result, err := h.service.Authorize(ctx, req, h.browser())
	require.NoError(t, err)
	u, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	challenge := u.Query().Get("oidc_challenge")
	require.NotEmpty(t, challenge)
	_, err = h.service.ContinueAuthorization(ctx, challenge, h.browser(), req.BrowserBinding)
	requireOAuthError(t, err, sessionErrorInvalidRequest)
	// Recent/equal timestamps cannot replace a marker for this exact request.
	h.admission.Binding.AuthenticatedAt = h.now
	other := h.requests[challenge]
	other.Challenge = "other-request"
	h.requests[other.Challenge] = other
	completion := oidc.RequestLoginCompletion{SessionID: h.browser().SessionID, CookieDigest: h.cookie, AuthenticatedAt: h.now}
	require.NoError(t, h.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
		return h.MarkLoginComplete(tx, other.Challenge, req.BrowserBinding, completion)
	}))
	_, err = h.service.ContinueAuthorization(ctx, challenge, h.browser(), req.BrowserBinding)
	requireOAuthError(t, err, sessionErrorInvalidRequest)
	require.NoError(t, h.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
		return h.MarkLoginComplete(tx, challenge, req.BrowserBinding, completion)
	}))
	oldCookie := h.cookie
	h.cookie = strings.Repeat("d", 64)
	_, err = h.service.ContinueAuthorization(ctx, challenge, h.browser(), req.BrowserBinding)
	requireOAuthError(t, err, sessionErrorInvalidRequest)
	h.cookie = oldCookie
	result, err = h.service.ContinueAuthorization(ctx, challenge, h.browser(), req.BrowserBinding)
	require.NoError(t, err)
	require.Contains(t, result.RedirectURI, "code=")
	require.NotNil(t, h.requests[challenge].ConsumedAt)
	_, err = h.service.ContinueAuthorization(ctx, challenge, h.browser(), req.BrowserBinding)
	requireOAuthError(t, err, sessionErrorInvalidRequest)
	require.ErrorIs(t, h.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
		return h.MarkLoginComplete(tx, challenge, req.BrowserBinding, completion)
	}), oidc.ErrSessionStateConflict)
}

func TestSessionBoundPromptAgeAndProtocolErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		change func(*oidc.SessionAuthorizeRequest)
		want   string
	}{
		{"unsupported scope", func(r *oidc.SessionAuthorizeRequest) { r.Scope = testSessionOfflineScope }, "invalid_scope"},
		{"api scope", func(r *oidc.SessionAuthorizeRequest) { r.Scope = "openid api:read" }, "invalid_scope"},
		{"response", func(r *oidc.SessionAuthorizeRequest) { r.ResponseType = "token" }, "unsupported_response_type"},
		{"missing PKCE", func(r *oidc.SessionAuthorizeRequest) { r.CodeChallenge = "" }, sessionErrorInvalidRequest},
		{"plain PKCE", func(r *oidc.SessionAuthorizeRequest) { r.CodeChallengeMethod = "plain" }, sessionErrorInvalidRequest},
		{"mixed none", func(r *oidc.SessionAuthorizeRequest) {
			r.Prompt = []string{oidc.TokenEndpointAuthMethodNone, testSessionLogin}
		}, sessionErrorInvalidRequest},
		{"unknown prompt", func(r *oidc.SessionAuthorizeRequest) { r.Prompt = []string{"future"} }, sessionErrorInvalidRequest},
		{
			"duplicate prompt",
			func(r *oidc.SessionAuthorizeRequest) {
				r.Prompt = []string{
					testSessionLogin,
					testSessionLogin,
				}
			},
			sessionErrorInvalidRequest,
		},

		{"consent", func(r *oidc.SessionAuthorizeRequest) { r.Prompt = []string{"consent"} }, "consent_required"},
		{"account", func(r *oidc.SessionAuthorizeRequest) { r.Prompt = []string{"select_account"} }, "account_selection_required"},
		{"negative age", func(r *oidc.SessionAuthorizeRequest) { v := int64(-1); r.MaxAgeSeconds = &v }, sessionErrorInvalidRequest},
		{
			"overflow age",
			func(r *oidc.SessionAuthorizeRequest) { v := int64(1 << 62); r.MaxAgeSeconds = &v },
			sessionErrorInvalidRequest,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			req := h.authorizeRequest()
			tc.change(&req)
			r, err := h.service.Authorize(context.Background(), req, h.browser())
			require.NoError(t, err)
			require.Contains(t, r.RedirectURI, "error="+tc.want)
			require.Empty(t, h.codes)
		})
	}
	t.Run("none without session", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		req := h.authorizeRequest()
		req.Prompt = []string{oidc.TokenEndpointAuthMethodNone}
		r, err := h.service.Authorize(context.Background(), req, nil)
		require.NoError(t, err)
		require.Contains(t, r.RedirectURI, "login_required")
		require.Empty(t, h.requests)
	})
	t.Run("none with session", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		req := h.authorizeRequest()
		req.Prompt = []string{oidc.TokenEndpointAuthMethodNone}
		r, err := h.service.Authorize(context.Background(), req, h.browser())
		require.NoError(t, err)
		require.Contains(t, r.RedirectURI, "code=")
	})
	t.Run("zero requires exact marker", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		req := h.authorizeRequest()
		zero := int64(0)
		req.MaxAgeSeconds = &zero
		r, err := h.service.Authorize(context.Background(), req, h.browser())
		require.NoError(t, err)
		require.Contains(t, r.RedirectURI, "oidc_challenge=")
		require.Empty(t, h.codes)
	})
	t.Run("positive age stale", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		h.admission.Binding.AuthenticatedAt = h.now.Add(-time.Hour)
		req := h.authorizeRequest()
		v := int64(60)
		req.MaxAgeSeconds = &v
		r, err := h.service.Authorize(context.Background(), req, h.browser())
		require.NoError(t, err)
		require.Contains(t, r.RedirectURI, "oidc_challenge=")
	})
	t.Run("callback exact", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		req := h.authorizeRequest()
		req.RedirectURI += " "
		r, err := h.service.Authorize(context.Background(), req, h.browser())
		require.Nil(t, r)
		requireOAuthError(t, err, sessionErrorInvalidRequest)
	})
}

func TestSessionCodeOwnerBurnAndReplayCommit(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	ctx := context.Background()
	code := h.authorizeCode(t)
	request := h.codeRequest(code)
	wrong := request
	wrong.ClientID = testSessionOtherClient
	_, err := h.service.ExchangeToken(ctx, wrong)
	requireOAuthError(t, err, "invalid_grant")
	require.Nil(t, h.codes[code].ConsumedAt)
	wrong = request
	wrong.ClientSecret = testSessionWrong
	_, err = h.service.ExchangeToken(ctx, wrong)
	requireOAuthError(t, err, "invalid_client")
	require.Nil(t, h.codes[code].ConsumedAt)
	wrong = request
	wrong.CodeVerifier = strings.Repeat("z", 43)
	_, err = h.service.ExchangeToken(ctx, wrong)
	requireOAuthError(t, err, "invalid_grant")
	require.NotNil(t, h.codes[code].ConsumedAt)
	require.Empty(t, h.families)
	code = h.authorizeCode(t)
	request = h.codeRequest(code)
	response, err := h.service.ExchangeToken(ctx, request)
	require.NoError(t, err)
	require.NotEmpty(t, response.RefreshToken)
	_, err = h.service.ExchangeToken(ctx, request)
	requireOAuthError(t, err, "invalid_grant")
	require.Equal(t, 1, h.replays)
	require.NotNil(t, h.families[h.codes[code].FamilyID].RevokedAt)
	_, err = h.service.UserInfo(ctx, response.AccessToken)
	requireOAuthError(t, err, "invalid_token")
}

func TestSessionRefreshOwnerIsolationAndAbsoluteEnd(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	ctx := context.Background()
	response := h.issue(t)
	first := h.tokens[response.RefreshToken]
	h.now = h.now.Add(6 * 24 * time.Hour)
	h.admission.Binding.AuthenticatedAt = h.now // Actual same-account reauthentication does not move family auth_time.
	next, err := h.service.ExchangeToken(ctx, h.refreshRequest(response.RefreshToken))
	require.NoError(t, err)
	record := h.tokens[next.RefreshToken]
	require.Equal(t, first.Binding, record.Binding)
	require.Equal(t, first.ExpiresAt, record.ExpiresAt)
	require.Equal(t, first.FamilyID, record.FamilyID)
	wrong := h.refreshRequest(response.RefreshToken)
	wrong.ClientID = testSessionOtherClient
	_, err = h.service.ExchangeToken(ctx, wrong)
	requireOAuthError(t, err, "invalid_grant")
	require.Zero(t, h.replays)
	require.Nil(t, h.families[first.FamilyID].RevokedAt)
	wrong = h.refreshRequest(response.RefreshToken)
	wrong.ClientSecret = testSessionWrong
	_, err = h.service.ExchangeToken(ctx, wrong)
	requireOAuthError(t, err, "invalid_client")
	require.Zero(t, h.replays)
	h.now = first.ExpiresAt.Truncate(time.Second).Add(-time.Second)
	final, err := h.service.ExchangeToken(ctx, h.refreshRequest(next.RefreshToken))
	require.NoError(t, err)
	require.Equal(t, int64(1), final.ExpiresIn)
	require.Equal(t, first.ExpiresAt, h.tokens[final.RefreshToken].ExpiresAt)
	h.now = first.ExpiresAt
	_, err = h.service.ExchangeToken(ctx, h.refreshRequest(final.RefreshToken))
	requireOAuthError(t, err, "invalid_grant")
	require.NotNil(t, h.families[first.FamilyID].RevokedAt)
}

func TestSessionRefreshParallelWinnerReplayLoser(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	response := h.issue(t)
	request := h.refreshRequest(response.RefreshToken)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := h.service.ExchangeToken(context.Background(), request)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success, denied := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else {
			requireOAuthError(t, err, "invalid_grant")
			denied++
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, denied)
	require.Equal(t, 1, h.replays)
	require.NotNil(t, h.families[h.tokens[response.RefreshToken].FamilyID].RevokedAt)
}

func TestSessionRevokeDisabledOwnerAndDeniedBinding(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"grant", "client", "project", testSessionSubject, testSessionStamp, testSessionSID} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			response := h.issue(t)
			switch change {
			case "grant":
				h.admission.Allowed = false
			case "client", "project":
				h.admission.Client.Trusted = false
			case testSessionSubject:
				h.admission.Account.Subject.Status = goauth.SubjectStatusDisabled
			case testSessionStamp:
				h.admission.Binding.PolicyStamp = "v1:changed"
			case testSessionSID:
				h.admission.Binding.SessionID = uuid.NewString()
			}
			request := oidc.RevokeRequest{
				Token:            response.RefreshToken,
				ClientID:         h.admission.Client.ID,
				ClientSecret:     testSessionSecret,
				ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
			}
			require.NoError(t, h.service.Revoke(context.Background(), request))
			require.NotNil(t, h.families[h.tokens[response.RefreshToken].FamilyID].RevokedAt)
		})
	}
}

func TestSessionInactiveBindingDenialPersists(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{responseTypeCode, testSessionRefresh} {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			var request oidc.TokenRequest
			if kind == responseTypeCode {
				request = h.codeRequest(h.authorizeCode(t))
			} else {
				request = h.refreshRequest(h.issue(t).RefreshToken)
			}
			h.admission.Client.Trusted = false
			h.admission.Allowed = false
			_, err := h.service.ExchangeToken(context.Background(), request)
			requireOAuthError(t, err, "invalid_grant")
			if kind == responseTypeCode {
				require.NotNil(t, h.codes[request.Code].ConsumedAt)
			} else {
				require.NotNil(t, h.families[h.tokens[request.RefreshToken].FamilyID].RevokedAt)
			}
		})
	}
}

func TestSessionPreparedOutputRollbackAndUnknownCommit(t *testing.T) {
	t.Parallel()
	for _, op := range []string{testSessionRefresh, "consume_code"} {
		t.Run(op, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			code := h.authorizeCode(t)
			h.failWrite = op
			r, err := h.service.ExchangeToken(context.Background(), h.codeRequest(code))
			require.Error(t, err)
			require.Nil(t, r)
			require.Nil(t, h.codes[code].ConsumedAt)
			require.Empty(t, h.tokens)
		})
	}
	t.Run("unknown commit", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		code := h.authorizeCode(t)
		h.commitErr = goauth.ErrOperationOutcomeUnknown
		r, err := h.service.ExchangeToken(context.Background(), h.codeRequest(code))
		require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
		require.Nil(t, r)
		require.NotNil(t, h.codes[code].ConsumedAt)
	})
	t.Run("signing failure", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		code := h.authorizeCode(t)
		h.keys.activeID = "absent"
		r, err := h.service.ExchangeToken(context.Background(), h.codeRequest(code))
		require.Error(t, err)
		require.Nil(t, r)
		require.Nil(t, h.codes[code].ConsumedAt)
		require.Empty(t, h.tokens)
	})
	t.Run("replay mutation failure", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		response := h.issue(t)
		_, err := h.service.ExchangeToken(context.Background(), h.refreshRequest(response.RefreshToken))
		require.NoError(t, err)
		h.revokeErr = errors.New("audit unavailable")
		r, err := h.service.ExchangeToken(context.Background(), h.refreshRequest(response.RefreshToken))
		require.ErrorContains(t, err, "audit unavailable")
		require.Nil(t, r)
		require.Zero(t, h.replays)
	})
}

func TestSessionExpiryAfterWaitWriteAndCommit(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{"admission", "lock_code", testSessionRefresh, "consume_code", "commit"} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			code := h.authorizeCode(t)
			expiry := h.codes[code].ExpiresAt
			switch stage {
			case "admission":
				h.afterAdmission = func() { h.now = expiry }
			case "commit":
				h.afterCommit = func() { h.now = h.now.Add(5 * time.Minute) }
			default:
				h.afterWrite = func(op string) {
					if op == stage {
						h.now = expiry
					}
				}
			}
			r, err := h.service.ExchangeToken(context.Background(), h.codeRequest(code))
			require.Error(t, err)
			require.Nil(t, r)
		})
	}
	t.Run("positive age after code write", func(t *testing.T) {
		t.Parallel()
		h := newSessionFixture(t)
		req := h.authorizeRequest()
		v := int64(1)
		req.MaxAgeSeconds = &v
		h.afterWrite = func(op string) {
			if op == responseTypeCode {
				h.now = h.now.Add(2 * time.Second)
			}
		}
		r, err := h.service.Authorize(context.Background(), req, h.browser())
		require.Error(t, err)
		require.Nil(t, r)
		require.Empty(t, h.codes)
	})
}

func TestSessionStrictJWTRejectsChangedClaimsAndHeader(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	response := h.issue(t)
	base, err := h.service.parseSessionAccessToken(context.Background(), response.AccessToken)
	require.NoError(t, err)
	key, err := h.keys.Active(context.Background())
	require.NoError(t, err)
	changes := map[string]func(*sessionTokenClaims){
		testSessionSubject: func(c *sessionTokenClaims) { c.Subject = "" },
		"version":          func(c *sessionTokenClaims) { c.SecurityVersion = 0 },
		testSessionSID:     func(c *sessionTokenClaims) { c.SessionID = uuid.NewString() },
		testSessionStamp:   func(c *sessionTokenClaims) { c.PolicyStamp = testSessionWrong },

		"family":          func(c *sessionTokenClaims) { c.FamilyID = uuid.NewString() },
		"project missing": func(c *sessionTokenClaims) { c.ProjectID = "" },

		"project different": func(c *sessionTokenClaims) { c.ProjectID = uuid.NewString() },
		"project client":    func(c *sessionTokenClaims) { c.ProjectID = c.ClientID },

		"issuer":   func(c *sessionTokenClaims) { c.Issuer = "https://wrong.example" },
		"audience": func(c *sessionTokenClaims) { c.Audience = jwt.ClaimStrings{testSessionWrong} },

		"extra audience": func(c *sessionTokenClaims) {
			c.Audience = append(c.Audience,
				testSessionOther)
		},
		"type": func(c *sessionTokenClaims) { c.TokenUse = "id" },

		"missing iat": func(c *sessionTokenClaims) { c.IssuedAt = nil },
		"missing nbf": func(c *sessionTokenClaims) { c.NotBefore = nil },

		"long expiry": func(c *sessionTokenClaims) { c.ExpiresAt = jwt.NewNumericDate(h.now.Add(6 * time.Minute)) },
		"future iat":  func(c *sessionTokenClaims) { c.IssuedAt = jwt.NewNumericDate(h.now.Add(time.Minute)) },

		"scope":               func(c *sessionTokenClaims) { c.Scope = testSessionOfflineScope },
		"authentication time": func(c *sessionTokenClaims) { c.AuthTime++ },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			claims := *base
			change(&claims)
			raw, err := h.service.base.signToken(key, claims, "at+jwt")
			require.NoError(t, err)
			_, err = h.service.UserInfo(context.Background(), raw)
			requireOAuthError(t, err, "invalid_token")
		})
	}
	for _, header := range []string{"missing kid", "wrong kid", "wrong typ"} {
		t.Run(header, func(t *testing.T) {
			t.Parallel()
			token := jwt.NewWithClaims(jwt.SigningMethodRS256, *base)
			token.Header["kid"] = key.ID
			token.Header["typ"] = "at+jwt"
			switch header {
			case "missing kid":
				delete(token.Header, "kid")
			case "wrong kid":
				token.Header["kid"] = "missing"
			case "wrong typ":
				token.Header["typ"] = "JWT"
			}
			raw, err := token.SignedString(key.PrivateKey)
			require.NoError(t, err)
			_, err = h.service.UserInfo(context.Background(), raw)
			requireOAuthError(t, err, "invalid_token")
		})
	}
}

func TestSessionConstructorAndMetadataBounds(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	_, err := NewSessionBound(SessionOptions{})
	require.Error(t, err)
	for _, issuer := range []string{
		"http://issuer.example",
		"https://issuer.example?x=1",
		"https://user@issuer.example",
		"https://issuer.example#x",
		" https://issuer.example",
	} {
		_,
			err = NewSessionBound(SessionOptions{
			State:     h,
			Admission: h,
			ClientSecretVerifier: oidc.ClientSecretVerifierFunc(func(context.Context,
				string,
				string,
			) error {
				return nil
			}),
			Keys:   h.keys,
			Issuer: issuer,
		})
		require.Error(t, err)
	}
	require.True(t, validMetadataMap(map[string]string{oidc.ScopeEmail: "optional", "name": "x", "preferred_username": "y"}))
	for _, value := range []map[string]string{
		{"project_id": "x"},
		{"email_verified": "true"},
		{"role_admin": "true"},
		{"Name": "x"},
		{"a-b": "x"},
		{"x": strings.Repeat("a",
			257)},
		{"x": "x\u0085"},
	} {
		require.False(t, validMetadataMap(value))
	}
	for _, projection := range []oidc.SessionProjection{
		{},
		{ProjectID: testSessionClient},
		{
			ProjectID: uuid.NewString(),
			Profile:   map[string]string{"roles": "admin"},
		},
	} {
		h.admission.Projection = projection
		_,
			_,
			_,
			err = h.service.prepareTokens(context.Background(),
			h.admission,
			h.admission.Binding,
			[]string{oidc.ScopeOpenID},
			"",
			uuid.NewString())
		require.Error(t, err)
	}
}

type legacyRevokeFailure struct {
	oidc.RefreshTokenStore
	calls   int
	failure error
}

func (s *legacyRevokeFailure) Revoke(context.Context, string, time.Time) error {
	s.calls++
	return s.failure
}

func TestLegacyRefreshReadSignalAuthenticatesBeforeReplay(t *testing.T) {
	t.Parallel()
	h := newOIDCTestHarness(t)
	ctx := context.Background()
	now := h.now
	record := oidc.RefreshToken{
		Token:     "used",
		SubjectID: h.subject.Subject.ID.String(),
		ClientID:  h.client.ID,
		Scopes: []string{
			oidc.ScopeOpenID,
			"offline_access",
		},
		SecurityVersion: h.subject.Subject.SecurityVersion,
		AuthenticatedAt: now,
		CreatedAt:       now,
		ExpiresAt:       now.Add(time.Hour),
		RevokedAt:       &now,
	}
	require.NoError(t, h.refreshTokens.Save(ctx, record))
	store := &legacyRevokeFailure{RefreshTokenStore: h.refreshTokens, failure: errors.New("audit unavailable")}
	h.service.refreshTokens = store
	request := oidc.TokenRequest{
		GrantType:        "refresh_token",
		RefreshToken:     "used",
		ClientID:         h.client.ID,
		ClientAuthMethod: oidc.TokenEndpointAuthMethodNone,
	}
	_, err := h.service.ExchangeToken(ctx, request)
	require.ErrorContains(t, err, "audit unavailable")
	require.Equal(t, 1, store.calls)
	h.service.clients = &memoryClientStore{items: map[string]oidc.Client{testSessionOther: {
		ID:                      testSessionOther,
		TokenEndpointAuthMethod: oidc.TokenEndpointAuthMethodNone,
	}}}
	request.ClientID = testSessionOther
	_, err = h.service.ExchangeToken(ctx, request)
	requireOAuthError(t, err, "invalid_grant")
	require.Equal(t, 1, store.calls)
	// Read-only inactive snapshots cannot be used as a cross-client revocation gadget.
	observed, err := h.refreshTokens.Get(ctx, "used")
	require.NoError(t, err)
	require.Equal(t, record, observed)
}

func TestSessionCodeParallelOneWinnerAndOwnedReplay(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	ctx := context.Background()
	code := h.authorizeCode(t)
	request := h.codeRequest(code)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := h.service.ExchangeToken(ctx, request); results <- err }()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			requireOAuthError(t, err, "invalid_grant")
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, h.replays)
}

func TestSessionContinuationParallelOneCodeAndRevisionFence(t *testing.T) {
	t.Parallel()
	for _, revisionChanged := range []bool{false, true} {
		t.Run(map[bool]string{false: "parallel", true: "revision changed"}[revisionChanged], func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			ctx := context.Background()
			req := h.authorizeRequest()
			req.Prompt = []string{testSessionLogin}
			result, err := h.service.Authorize(ctx, req, h.browser())
			require.NoError(t, err)
			u, err := url.Parse(result.RedirectURI)
			require.NoError(t, err)
			challenge := u.Query().Get("oidc_challenge")
			require.NoError(t, h.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
				return h.MarkLoginComplete(tx,
					challenge,
					req.BrowserBinding,
					oidc.RequestLoginCompletion{
						SessionID:       h.browser().SessionID,
						CookieDigest:    h.cookie,
						AuthenticatedAt: h.now,
					})
			}))
			if revisionChanged {
				h.admission.ClientRevision++
				result, err = h.service.ContinueAuthorization(ctx, challenge, h.browser(), req.BrowserBinding)
				require.NoError(t, err)
				assertSessionDenialRedirect(t, result, req)
				require.NotNil(t, h.requests[challenge].ConsumedAt)
				require.Empty(t, h.codes)
				return
			}
			var wg sync.WaitGroup
			results := make(chan error, 2)
			for range 2 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := h.service.ContinueAuthorization(ctx, challenge, h.browser(), req.BrowserBinding)
					results <- err
				}()
			}
			wg.Wait()
			close(results)
			success := 0
			for err := range results {
				if err == nil {
					success++
				} else {
					requireOAuthError(t, err, sessionErrorInvalidRequest)
				}
			}
			require.Equal(t, 1, success)
			require.Len(t, h.codes, 1)
		})
	}
}

func TestSessionEmailLessAccountAndWrongOwnerCodeReplay(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Account.PrimaryEmail = goauth.Identifier{}
	ctx := context.Background()
	code := h.authorizeCode(t)
	response, err := h.service.ExchangeToken(ctx, h.codeRequest(code))
	require.NoError(t, err)
	info, err := h.service.UserInfo(ctx, response.AccessToken)
	require.NoError(t, err)
	require.Empty(t, info.Email)
	require.Nil(t, info.EmailVerified)
	wrong := h.codeRequest(code)
	wrong.ClientID = testSessionOtherClient
	_, err = h.service.ExchangeToken(ctx, wrong)
	requireOAuthError(t, err, "invalid_grant")
	require.Zero(t, h.replays)
	wrong = h.codeRequest(code)
	wrong.ClientSecret = testSessionWrong
	_, err = h.service.ExchangeToken(ctx, wrong)
	requireOAuthError(t, err, "invalid_client")
	require.Zero(t, h.replays)
	require.Nil(t, h.families[h.codes[code].FamilyID].RevokedAt)
}
