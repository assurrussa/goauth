//nolint:testpackage // This fixture checks private serialization and JWT boundaries.
package provider

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const (
	testSessionSubject      = "subject"
	testSessionStamp        = "stamp"
	testSessionClient       = "client-1"
	testSessionOtherClient  = "other-client"
	testSessionWrong        = "wrong"
	testSessionSecret       = "secret"
	testSessionCurrent      = "current"
	testSessionRefresh      = "refresh"
	testSessionLogin        = "login"
	testSessionSID          = "sid"
	testSessionOther        = "other"
	testSessionOfflineScope = "openid offline_access"
)

type (
	sessionFixtureKey struct{}
	sessionFixture    struct {
		mu             sync.Mutex
		now            time.Time
		service        *SessionService
		keys           *memoryKeyStore
		admission      oidc.SessionAdmissionResult
		cookie         string
		requests       map[string]oidc.SessionRequest
		codes          map[string]oidc.SessionCode
		tokens         map[string]oidc.SessionRefresh
		families       map[string]oidc.SessionFamily
		generation     int
		commits        int
		replays        int
		failWrite      string
		afterWrite     func(string)
		afterAdmission func()
		afterCommit    func()
		commitErr      error
		secretErr      error
		revokeErr      error
	}
)

func newSessionFixture(t *testing.T) *sessionFixture {
	t.Helper()
	legacy := newOIDCTestHarness(t)
	now := time.Date(2026, 10, 4, 10, 0, 0, 123456000, time.UTC)
	h := &sessionFixture{
		now:  now,
		keys: legacy.keys,
		cookie: strings.Repeat("c",
			64),
		requests: map[string]oidc.SessionRequest{},
		codes:    map[string]oidc.SessionCode{},
		tokens:   map[string]oidc.SessionRefresh{},
		families: map[string]oidc.SessionFamily{},
	}
	h.admission = oidc.SessionAdmissionResult{
		Client: oidc.Client{
			ID:           testSessionClient,
			RedirectURIs: []string{"https://app.example/callback"},
			AllowedScopes: []string{
				oidc.ScopeOpenID,
				oidc.ScopeProfile,
				oidc.ScopeEmail,
			},
			TokenEndpointAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
			RequirePKCE:             true,
			Trusted:                 true,
		},

		ClientRevision: 1,
		Binding: oidc.SessionBinding{
			SubjectID:         legacy.subject.Subject.ID.String(),
			SecurityVersion:   legacy.subject.Subject.SecurityVersion,
			ClientID:          testSessionClient,
			SessionID:         uuid.NewString(),
			PolicyStamp:       "v1:project:1:1:1",
			AuthenticatedAt:   now,
			AbsoluteExpiresAt: now.Add(7 * 24 * time.Hour),
		},

		Account: legacy.subject,
		Projection: oidc.SessionProjection{
			ProjectID: uuid.NewString(),
			Profile: map[string]string{
				"name":          "display",
				oidc.ScopeEmail: "unverified metadata",
			},
			Project: map[string]string{"team": "blue"},
		},
		Allowed: true,
	}
	var err error
	h.service,
		err = NewSessionBound(SessionOptions{
		State:     h,
		Admission: h,
		ClientSecretVerifier: oidc.ClientSecretVerifierFunc(func(ctx context.Context,
			id,
			secret string,
		) error {
			if ctx.Value(sessionFixtureKey{}) != h {
				return errors.New("secret verification outside transaction")
			}
			if h.secretErr != nil {
				return h.secretErr
			}
			if (id != h.admission.Client.ID && id != testSessionOtherClient) || secret != testSessionSecret {
				return errors.New("wrong client secret")
			}
			return nil
		}),
		Keys:   h.keys,
		Issuer: "https://issuer.example",
		Now:    func() time.Time { return h.now },
		GenerateToken: func() (string,
			error,
		) {
			h.generation++
			return fmt.Sprintf("synthetic-high-entropy-token-%064d", h.generation), nil
		},
	})
	require.NoError(t, err)
	return h
}

func (h *sessionFixture) browser() *oidc.BrowserSession {
	return &oidc.BrowserSession{SessionID: h.admission.Binding.SessionID, CookieDigest: h.cookie}
}

func (h *sessionFixture) authorizeRequest() oidc.SessionAuthorizeRequest {
	return oidc.SessionAuthorizeRequest{
		AuthorizeRequest: oidc.AuthorizeRequest{
			ClientID:            h.admission.Client.ID,
			RedirectURI:         h.admission.Client.RedirectURIs[0],
			ResponseType:        responseTypeCode,
			Scope:               "openid profile email",
			State:               "state",
			Nonce:               "nonce",
			CodeChallenge:       codeChallengeFor(testPKCEVerifier),
			CodeChallengeMethod: codeChallengeMethodS256,
		},
		BrowserBinding: strings.Repeat("b",
			64),
	}
}

func (h *sessionFixture) authorizeCode(t *testing.T) string {
	t.Helper()
	result, err := h.service.Authorize(context.Background(), h.authorizeRequest(), h.browser())
	require.NoError(t, err)
	parsed, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	code := parsed.Query().Get(responseTypeCode)
	require.NotEmpty(t, code)
	return code
}

func (h *sessionFixture) codeRequest(code string) oidc.TokenRequest {
	return oidc.TokenRequest{
		GrantType:        "authorization_code",
		Code:             code,
		RedirectURI:      h.admission.Client.RedirectURIs[0],
		CodeVerifier:     testPKCEVerifier,
		ClientID:         h.admission.Client.ID,
		ClientSecret:     testSessionSecret,
		ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
	}
}

func (h *sessionFixture) refreshRequest(raw string) oidc.TokenRequest {
	return oidc.TokenRequest{
		GrantType:        "refresh_token",
		RefreshToken:     raw,
		ClientID:         h.admission.Client.ID,
		ClientSecret:     testSessionSecret,
		ClientAuthMethod: oidc.TokenEndpointAuthMethodClientSecretBasic,
	}
}

func (h *sessionFixture) issue(t *testing.T) *oidc.TokenResponse {
	t.Helper()
	response, err := h.service.ExchangeToken(context.Background(), h.codeRequest(h.authorizeCode(t)))
	require.NoError(t, err)
	return response
}

func (h *sessionFixture) Lock(ctx context.Context, req oidc.SessionAdmissionRequest) (oidc.SessionAdmissionResult, error) {
	if ctx.Value(sessionFixtureKey{}) != h {
		return oidc.SessionAdmissionResult{}, errors.New("admission outside transaction")
	}
	result := h.admission
	if req.ClientID == testSessionOtherClient {
		result.Client.ID = req.ClientID
		result.Allowed = false
	} else if req.ClientID != result.Client.ID {
		result.Client = oidc.Client{}
		result.Allowed = false
	}
	if req.SessionID == "" || req.SessionID != result.Binding.SessionID {
		result.Allowed = false
	}
	if req.Browser != nil && req.Browser.CookieDigest != h.cookie {
		result.Allowed = false
	}
	if h.afterAdmission != nil {
		h.afterAdmission()
	}
	return result, nil
}

func (h *sessionFixture) InOwnedAuthTransaction(ctx context.Context, fn func(context.Context) error) error {
	if ctx.Value(sessionFixtureKey{}) != nil {
		return errors.New("ambient scope")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	requests,
		codes,
		tokens,
		families,
		replays := maps.Clone(h.requests),
		maps.Clone(h.codes),
		maps.Clone(h.tokens),
		maps.Clone(h.families),
		h.replays
	err := fn(context.WithValue(ctx, sessionFixtureKey{}, h))
	if err != nil {
		h.requests, h.codes, h.tokens, h.families, h.replays = requests, codes, tokens, families, replays
		return err
	}
	h.commits++
	if h.afterCommit != nil {
		h.afterCommit()
	}
	return h.commitErr
}

func (h *sessionFixture) write(ctx context.Context, op string) error {
	if ctx.Value(sessionFixtureKey{}) != h {
		return errors.New("write outside scope")
	}
	if h.failWrite == op {
		return errors.New("injected write failure")
	}
	if h.afterWrite != nil {
		h.afterWrite(op)
	}
	return nil
}

func (h *sessionFixture) readLock(ctx context.Context) func() {
	if ctx.Value(sessionFixtureKey{}) == h {
		return func() {}
	}
	h.mu.Lock()
	return h.mu.Unlock
}

func (h *sessionFixture) SaveRequest(ctx context.Context, v oidc.SessionRequest) error {
	if err := h.write(ctx, "request"); err != nil {
		return err
	}
	h.requests[v.Challenge] = v
	return nil
}

func (h *sessionFixture) ReadRequest(ctx context.Context, key string) (oidc.SessionRequest, error) {
	done := h.readLock(ctx)
	defer done()
	v, ok := h.requests[key]
	if !ok {
		return v, oidc.ErrAuthorizationRequestNotFound
	}
	return v, nil
}

func (h *sessionFixture) MarkLoginComplete(ctx context.Context, key, browser string, v oidc.RequestLoginCompletion) error {
	if err := h.write(ctx, "marker"); err != nil {
		return err
	}
	r, ok := h.requests[key]
	if !ok || r.LoginCompletion != nil || r.ConsumedAt != nil || !h.now.Before(r.ExpiresAt) || r.BrowserBinding != browser {
		return oidc.ErrSessionStateConflict
	}
	r.LoginCompletion = &v
	h.requests[key] = r
	return nil
}

func (h *sessionFixture) ConsumeRequest(ctx context.Context, key string) (oidc.SessionRequest, error) {
	if err := h.write(ctx, "consume_request"); err != nil {
		return oidc.SessionRequest{}, err
	}
	v, ok := h.requests[key]
	if !ok || v.ConsumedAt != nil || !h.now.Before(v.ExpiresAt) {
		return v, oidc.ErrAuthorizationRequestNotFound
	}
	next := v
	now := h.now
	next.ConsumedAt = &now
	h.requests[key] = next
	return v, nil
}

func (h *sessionFixture) SaveCode(ctx context.Context, v oidc.SessionCode) error {
	if err := h.write(ctx, responseTypeCode); err != nil {
		return err
	}
	h.codes[v.Code] = v
	return nil
}

func (h *sessionFixture) ReadCode(ctx context.Context, key string) (oidc.SessionCode, error) {
	done := h.readLock(ctx)
	defer done()
	v, ok := h.codes[key]
	if !ok {
		return v, oidc.ErrAuthorizationCodeNotFound
	}
	return v, nil
}

func (h *sessionFixture) LockCode(ctx context.Context, key string) (oidc.SessionCode, error) {
	if err := h.write(ctx, "lock_code"); err != nil {
		return oidc.SessionCode{}, err
	}
	return h.ReadCode(ctx, key)
}

func (h *sessionFixture) ConsumeCode(ctx context.Context, key, family string, now time.Time) (oidc.SessionCode, error) {
	if err := h.write(ctx, "consume_code"); err != nil {
		return oidc.SessionCode{}, err
	}
	v, ok := h.codes[key]
	if !ok || v.ConsumedAt != nil {
		return v, oidc.ErrAuthorizationCodeNotFound
	}
	v.ConsumedAt = &now
	v.FamilyID = family
	h.codes[key] = v
	return v, nil
}

func (h *sessionFixture) ReadRefresh(ctx context.Context, key string) (oidc.SessionRefresh, error) {
	done := h.readLock(ctx)
	defer done()
	v, ok := h.tokens[key]
	if !ok {
		return v, oidc.ErrRefreshTokenNotFound
	}
	family := h.families[v.FamilyID]
	v.RevokedAt = family.RevokedAt
	return v, nil
}

func (h *sessionFixture) LockRefresh(ctx context.Context, key string) (oidc.SessionRefresh, error) {
	if err := h.write(ctx, "lock_refresh"); err != nil {
		return oidc.SessionRefresh{}, err
	}
	return h.ReadRefresh(ctx, key)
}

func (h *sessionFixture) SaveRefresh(ctx context.Context, v oidc.SessionRefresh) error {
	if err := h.write(ctx, testSessionRefresh); err != nil {
		return err
	}
	h.tokens[v.Token] = v
	h.families[v.FamilyID] = oidc.SessionFamily{FamilyID: v.FamilyID, Binding: v.Binding, Scopes: v.Scopes}
	return nil
}

func (h *sessionFixture) RotateRefresh(ctx context.Context, current, next oidc.SessionRefresh, now time.Time) error {
	if err := h.write(ctx, "rotate"); err != nil {
		return err
	}
	v, ok := h.tokens[current.Token]
	if !ok || v.ConsumedAt != nil {
		return oidc.ErrSessionStateConflict
	}
	v.ConsumedAt = &now
	h.tokens[current.Token] = v
	h.tokens[next.Token] = next
	return nil
}

func (h *sessionFixture) RevokeFamily(ctx context.Context, key string, reason oidc.SessionRevocationReason, now time.Time) error {
	if err := h.write(ctx, "revoke"); err != nil {
		return err
	}
	if h.revokeErr != nil {
		return h.revokeErr
	}
	v, ok := h.families[key]
	if !ok {
		return oidc.ErrRefreshTokenNotFound
	}
	if v.RevokedAt == nil {
		v.RevokedAt = &now
	}
	if reason == oidc.SessionReplay && v.ReplayedAt == nil {
		v.ReplayedAt = &now
		h.replays++
	}
	h.families[key] = v
	return nil
}

func (h *sessionFixture) LockFamily(ctx context.Context, key string) (oidc.SessionFamily, error) {
	if err := h.write(ctx, "lock_family"); err != nil {
		return oidc.SessionFamily{}, err
	}
	v, ok := h.families[key]
	if !ok {
		return v, oidc.ErrRefreshTokenNotFound
	}
	return v, nil
}

var (
	_ oidc.SessionStateStore = (*sessionFixture)(nil)
	_ oidc.SessionAdmission  = (*sessionFixture)(nil)
)
