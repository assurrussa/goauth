package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/internal/generate_token"
	"github.com/assurrussa/goauth/oidc"
)

// SessionOptions configures the explicit confidential, session-bound profile.
// It intentionally has no subject-only claims resolver or standalone stores.
type SessionOptions struct {
	State                oidc.SessionStateStore
	Admission            oidc.SessionAdmission
	ClientSecretVerifier oidc.ClientSecretVerifier
	Keys                 oidc.TokenSigningKeyStore
	Issuer               string
	FrontendLoginURL     string
	Now                  func() time.Time
	GenerateToken        func() (string, error)
}

// SessionService issues only live-session-bound code/refresh grants. Every final
// admission, one-time transition and durable expected denial shares one owned
// transaction. It never releases prepared tokens before confirmed commit.
type SessionService struct {
	state     oidc.SessionStateStore
	admission oidc.SessionAdmission
	base      *Service
}

func NewSessionBound(opts SessionOptions) (*SessionService, error) {
	if opts.State == nil || opts.Admission == nil || opts.ClientSecretVerifier == nil || opts.Keys == nil {
		return nil, errors.New("session state, admission, client secret verifier and keys are required")
	}
	if !strictHTTPSURL(opts.Issuer, false) {
		return nil, errors.New("exact HTTPS issuer without query or fragment is required")
	}
	login := opts.FrontendLoginURL
	if login == "" {
		login = "/sso/login"
	}
	u, err := url.Parse(login)
	if err != nil || u.Fragment != "" || u.RawQuery != "" || u.User != nil ||
		(u.IsAbs() &&
			!strictHTTPSURL(login,
				false)) ||
		(!u.IsAbs() &&
			(!strings.HasPrefix(login,
				"/") ||
				strings.HasPrefix(login,
					"//"))) {
		return nil, errors.New("valid configured login URL is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	gen := opts.GenerateToken
	if gen == nil {
		gen = generate_token.GenerateToken
	}
	return &SessionService{state: opts.State, admission: opts.Admission, base: &Service{
		enabled: true, clientSecretVerifier: opts.ClientSecretVerifier, keys: opts.Keys,
		issuer: opts.Issuer, frontendLoginURL: login, now: now, generateToken: gen,
		tokenEndpointAuthMethods: []string{oidc.TokenEndpointAuthMethodClientSecretBasic},
		accessTokenTTL:           5 * time.Minute,
	}}, nil
}

func (s *SessionService) Discovery(ctx context.Context) oidc.SessionDiscoveryMetadata {
	d := s.base.Discovery(ctx)
	d.ScopesSupported = []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail}
	d.ClaimsSupported = append(d.ClaimsSupported, "project_id", "authhub_profile", "authhub_project", "sid")
	return oidc.SessionDiscoveryMetadata{DiscoveryMetadata: d}
}
func (s *SessionService) JWKS(ctx context.Context) (oidc.JWKS, error) { return s.base.JWKS(ctx) }
func (s *SessionService) now() time.Time                              { return s.base.now().UTC() }
func (s *SessionService) owned(ctx context.Context, fn func(context.Context) error) error {
	return s.state.InOwnedAuthTransaction(authclock.With(ctx, s.now), fn)
}

func sessionError(code string) *oidc.OAuthError {
	status := http.StatusBadRequest
	if code == "invalid_client" || code == "invalid_token" {
		status = http.StatusUnauthorized
	}
	return &oidc.OAuthError{Code: code, Description: "request cannot be completed", StatusCode: status}
}

func sessionUnavailable(err error) error { return fmt.Errorf("session OIDC operation failed: %w", err) }

const sessionErrorInvalidRequest = "invalid_request"

var errSessionExpired = errors.New("session OIDC result expired before delivery")

//nolint:gocognit // One visible owned boundary keeps admission, expected denials and response release auditable.
func (s *SessionService) Authorize(ctx context.Context,
	req oidc.SessionAuthorizeRequest,
	browser *oidc.BrowserSession) (*oidc.AuthorizeResult,
	error,
) {
	var result *oidc.AuthorizeResult
	var denial *oidc.OAuthError
	var deadline time.Time
	err := s.owned(ctx, func(tx context.Context) error {
		input := oidc.SessionAdmissionRequest{ClientID: req.ClientID, Browser: browser}
		if browser != nil {
			input.SessionID = browser.SessionID
		}
		current, err := s.admission.Lock(tx, input)
		if err != nil {
			return err
		}
		if current.Client.ID != req.ClientID || !strictRedirectAllowed(current.Client, req.RedirectURI) {
			denial = sessionError(sessionErrorInvalidRequest)
			return nil
		}
		scopes, protocol := s.validateAuthorize(current.Client, req)
		if protocol != nil {
			result, err = s.errorRedirect(req.RedirectURI, req.State, protocol)
			return err
		}
		ready := validAdmission(current, nil, s.now()) && browser != nil && current.Binding.SessionID == browser.SessionID
		forced := slices.Contains(req.Prompt, "login") || (req.MaxAgeSeconds != nil && *req.MaxAgeSeconds == 0)
		if ready && !forced && freshAuthentication(current.Binding.AuthenticatedAt, req.MaxAgeSeconds, s.now()) {
			result, deadline, err = s.issueCode(tx, req.AuthorizeRequest, scopes, current.Binding)
			if err == nil && !freshAuthentication(current.Binding.AuthenticatedAt, req.MaxAgeSeconds, s.now()) {
				return errSessionExpired
			}
			return err
		}
		if slices.Contains(req.Prompt, "none") {
			result, err = s.errorRedirect(req.RedirectURI,
				req.State,
				sessionError("login_required"))
			return err
		}
		if !validDigest(req.BrowserBinding) || current.ClientRevision <= 0 {
			denial = sessionError(sessionErrorInvalidRequest)
			return nil
		}
		challenge, err := s.base.generateToken()
		if err != nil {
			return err
		}
		now := s.now()
		deadline = now.Add(10 * time.Minute)
		pending := oidc.SessionRequest{
			AuthorizationRequest: oidc.AuthorizationRequest{
				Challenge: challenge, ClientID: req.ClientID, RedirectURI: req.RedirectURI, State: req.State, Nonce: req.Nonce,
				Scopes: scopes, CodeChallenge: req.CodeChallenge, CodeChallengeMethod: req.CodeChallengeMethod,
				RequestedAt: now, ExpiresAt: deadline,
			},
			ClientRevision: current.ClientRevision,
			Prompt:         slices.Clone(req.Prompt),
			MaxAgeSeconds:  req.MaxAgeSeconds,
			BrowserBinding: req.BrowserBinding,
		}
		if err := s.state.SaveRequest(tx, pending); err != nil {
			return err
		}
		result = &oidc.AuthorizeResult{RedirectURI: s.base.loginRedirect(challenge)}
		if !s.now().Before(deadline) {
			return errSessionExpired
		}
		return nil
	})
	if err != nil {
		return nil, sessionUnavailable(err)
	}
	if denial != nil {
		return nil, denial
	}
	if !deadline.IsZero() && !s.now().Before(deadline) {
		return nil, sessionUnavailable(errSessionExpired)
	}
	return result, nil
}

//nolint:gocognit // Keep safe callback admission, terminal denial and response release in one owned boundary.
func (s *SessionService) ContinueAuthorization(ctx context.Context,
	challenge string,
	browser *oidc.BrowserSession,
	browserBinding string) (*oidc.AuthorizeResult,
	error,
) {
	hint, err := s.state.ReadRequest(ctx, challenge)
	if err != nil {
		return nil, stateReadError(err, sessionErrorInvalidRequest)
	}
	if !requestCompletionMatches(hint, browser, browserBinding, s.now()) {
		return nil, sessionError(sessionErrorInvalidRequest)
	}
	var result *oidc.AuthorizeResult
	var deadline time.Time
	var denial *oidc.OAuthError
	err = s.owned(ctx, func(tx context.Context) error {
		current, err := s.admission.Lock(tx, oidc.SessionAdmissionRequest{
			ClientID: hint.ClientID, SessionID: browser.SessionID, Browser: browser, ClientRevision: hint.ClientRevision,
		})
		if err != nil {
			return err
		}
		// A current trusted callback can receive a denial even when issuance is
		// no longer allowed. Never redirect to a removed or untrusted target.
		if current.Client.ID != hint.ClientID || !current.Client.Trusted ||
			!strictRedirectAllowed(current.Client, hint.RedirectURI) {
			denial = sessionError("access_denied")
			return nil
		}
		record, err := s.state.ConsumeRequest(tx, challenge)
		if err != nil {
			return err
		}
		if !requestCompletionMatches(record,
			browser,
			browserBinding,
			s.now()) ||
			record.Challenge != challenge || record.ClientID != hint.ClientID ||
			record.ClientRevision != hint.ClientRevision || record.RedirectURI != hint.RedirectURI {
			// No durable effect is intended: rollback the tentative consumption.
			return oidc.ErrSessionStateConflict
		}
		if current.ClientRevision != record.ClientRevision || !validAdmission(current, nil, s.now()) ||
			current.Binding.SessionID != browser.SessionID {
			// This request is terminal, without creating a code or grant. Use only
			// the consumed record's state and withhold output until confirmed commit.
			deadline = record.ExpiresAt
			result, err = s.errorRedirect(record.RedirectURI, record.State, sessionError("access_denied"))
			if err != nil {
				return err
			}
			if !s.now().Before(deadline) {
				return errSessionExpired
			}
			return nil
		}
		binding := current.Binding
		binding.AuthenticatedAt = record.LoginCompletion.AuthenticatedAt
		if !freshAuthentication(binding.AuthenticatedAt, record.MaxAgeSeconds, s.now()) || !validBinding(binding, s.now()) {
			return oidc.ErrSessionStateConflict
		}
		input := oidc.AuthorizeRequest{
			ClientID: record.ClientID, RedirectURI: record.RedirectURI, State: record.State, Nonce: record.Nonce,
			ResponseType:        "code",
			Scope:               oidc.ScopeString(record.Scopes),
			CodeChallenge:       record.CodeChallenge,
			CodeChallengeMethod: record.CodeChallengeMethod,
		}
		if _, bad := s.validateAuthorize(current.Client, oidc.SessionAuthorizeRequest{AuthorizeRequest: input}); bad != nil {
			return oidc.ErrSessionStateConflict
		}
		result, deadline, err = s.issueCode(tx, input, record.Scopes, binding)
		if err != nil {
			return err
		}
		if !s.now().Before(record.ExpiresAt) || !freshAuthentication(binding.AuthenticatedAt, record.MaxAgeSeconds, s.now()) {
			return errSessionExpired
		}
		return nil
	})
	if isStateMissing(err) {
		return nil, sessionError(sessionErrorInvalidRequest)
	}
	if err != nil {
		return nil, sessionUnavailable(err)
	}
	if denial != nil {
		return nil, denial
	}
	if !s.now().Before(deadline) {
		return nil, sessionUnavailable(errSessionExpired)
	}
	return result, nil
}

// errorRedirect is used only after exact current-client/callback validation.
// Keep the strict profile's opaque state semantics separate from legacy behavior.
func (s *SessionService) errorRedirect(redirectURI, state string, protocol *oidc.OAuthError) (*oidc.AuthorizeResult, error) {
	callback, err := url.Parse(s.base.redirectWithError(redirectURI, state, protocol))
	if err != nil {
		return nil, err
	}
	query := callback.Query()
	query.Del("state")
	if state != "" {
		query.Set("state", state)
	}
	callback.RawQuery = query.Encode()
	return &oidc.AuthorizeResult{RedirectURI: callback.String()}, nil
}

func (s *SessionService) ExchangeToken(ctx context.Context, req oidc.TokenRequest) (*oidc.TokenResponse, error) {
	if req.ClientID == "" || req.ClientSecret == "" || req.ClientAuthMethod != oidc.TokenEndpointAuthMethodClientSecretBasic {
		return nil, sessionError("invalid_client")
	}
	switch req.GrantType {
	case grantTypeAuthorizationCode:
		return s.exchangeCode(ctx, req)
	case grantTypeRefreshToken:
		return s.exchangeRefresh(ctx, req)
	default:
		return nil, sessionError("unsupported_grant_type")
	}
}

func (s *SessionService) authenticate(ctx context.Context,
	current oidc.SessionAdmissionResult,
	id,
	secret,
	method string,
) *oidc.OAuthError {
	if id == "" || secret == "" || current.Client.ID != id ||
		method != oidc.TokenEndpointAuthMethodClientSecretBasic || current.Client.TokenEndpointAuthMethod != method {
		return sessionError("invalid_client")
	}
	if err := s.base.clientSecretVerifier.VerifyClientSecret(ctx, id, secret); err != nil {
		return sessionError("invalid_client")
	}
	return nil
}

//nolint:gocognit,nilerr // Expected denials commit deliberate burns/replay effects; infrastructure failures roll back.
func (s *SessionService) exchangeCode(ctx context.Context, req oidc.TokenRequest) (*oidc.TokenResponse, error) {
	hint, lookupErr := s.state.ReadCode(ctx, req.Code)
	if lookupErr != nil && !isStateMissing(lookupErr) {
		return nil, sessionUnavailable(lookupErr)
	}
	var result *oidc.TokenResponse
	var deadline time.Time
	var denial *oidc.OAuthError
	err := s.owned(ctx, func(tx context.Context) error {
		input := oidc.SessionAdmissionRequest{ClientID: req.ClientID}
		if lookupErr == nil && hint.ClientID == req.ClientID {
			input.Expected = &hint.Binding
			input.SessionID = hint.Binding.SessionID
		}
		current, err := s.admission.Lock(tx, input)
		if err != nil {
			return err
		}
		if denial = s.authenticate(tx, current, req.ClientID, req.ClientSecret, req.ClientAuthMethod); denial != nil {
			return nil
		}
		if lookupErr != nil || hint.ClientID != req.ClientID {
			denial = sessionError("invalid_grant")
			return nil
		}
		code, err := s.state.LockCode(tx, req.Code)
		if isStateMissing(err) {
			denial = sessionError("invalid_grant")
			return nil
		}
		if err != nil {
			return err
		}
		if code.ClientID != req.ClientID || !sameBinding(code.Binding, hint.Binding) {
			denial = sessionError("invalid_grant")
			return nil
		}
		if code.ConsumedAt != nil {
			if code.FamilyID != "" {
				if err := s.state.RevokeFamily(tx, code.FamilyID, oidc.SessionReplay, s.now()); err != nil {
					return err
				}
			}
			denial = sessionError("invalid_grant")
			return nil
		}
		if !validCodeSnapshot(code) || !s.now().Before(code.ExpiresAt) || !validAdmission(current, &code.Binding, s.now()) ||
			code.RedirectURI != req.RedirectURI ||
			!validPKCEMetadata(true,
				code.CodeChallenge,
				code.CodeChallengeMethod) ||
			!verifyCodeVerifier(req.CodeVerifier,
				code.CodeChallenge) {
			if _, err := s.state.ConsumeCode(tx, req.Code, "", s.now()); err != nil {
				return err
			}
			denial = sessionError("invalid_grant")
			return nil
		}
		familyID := uuid.NewString()
		var next oidc.SessionRefresh
		result, next, deadline, err = s.prepareTokens(tx, current, code.Binding, code.Scopes, code.Nonce, familyID)
		if err != nil {
			return err
		}
		if !s.now().Before(code.ExpiresAt) || !s.now().Before(deadline) {
			return errSessionExpired
		}
		if err := s.state.SaveRefresh(tx, next); err != nil {
			return err
		}
		if _, err := s.state.ConsumeCode(tx, req.Code, familyID, s.now()); err != nil {
			return err
		}
		if !s.now().Before(code.ExpiresAt) || !s.now().Before(deadline) {
			return errSessionExpired
		}
		return nil
	})
	return s.tokenOutcome(result, deadline, denial, err)
}

//nolint:gocognit,nilerr // Keep replay-before-signing and expected-denial commit in the same owned boundary.
func (s *SessionService) exchangeRefresh(ctx context.Context, req oidc.TokenRequest) (*oidc.TokenResponse, error) {
	hint, lookupErr := s.state.ReadRefresh(ctx, req.RefreshToken)
	if lookupErr != nil && !isStateMissing(lookupErr) {
		return nil, sessionUnavailable(lookupErr)
	}
	var result *oidc.TokenResponse
	var deadline time.Time
	var denial *oidc.OAuthError
	err := s.owned(ctx, func(tx context.Context) error {
		input := oidc.SessionAdmissionRequest{ClientID: req.ClientID}
		if lookupErr == nil && hint.ClientID == req.ClientID {
			input.Expected = &hint.Binding
			input.SessionID = hint.Binding.SessionID
		}
		current, err := s.admission.Lock(tx, input)
		if err != nil {
			return err
		}
		if denial = s.authenticate(tx, current, req.ClientID, req.ClientSecret, req.ClientAuthMethod); denial != nil {
			return nil
		}
		if lookupErr != nil || hint.ClientID != req.ClientID {
			denial = sessionError("invalid_grant")
			return nil
		}
		token, err := s.state.LockRefresh(tx, req.RefreshToken)
		if isStateMissing(err) {
			denial = sessionError("invalid_grant")
			return nil
		}
		if err != nil {
			return err
		}
		if token.ClientID != req.ClientID || token.FamilyID != hint.FamilyID || !sameBinding(token.Binding, hint.Binding) {
			denial = sessionError("invalid_grant")
			return nil
		}
		reason := oidc.SessionRevoked
		if token.ConsumedAt != nil {
			reason = oidc.SessionReplay
		}
		if token.ConsumedAt != nil ||
			token.RevokedAt != nil ||
			!validRefreshSnapshot(token) ||
			!s.now().Before(token.ExpiresAt) ||
			!validAdmission(current,
				&token.Binding,
				s.now()) {
			if err := s.state.RevokeFamily(tx, token.FamilyID, reason, s.now()); err != nil {
				return err
			}
			denial = sessionError("invalid_grant")
			return nil
		}
		var next oidc.SessionRefresh
		result, next, deadline, err = s.prepareTokens(tx, current, token.Binding, token.Scopes, "", token.FamilyID)
		if err != nil {
			return err
		}
		if !s.now().Before(token.ExpiresAt) || !s.now().Before(deadline) {
			return errSessionExpired
		}
		if err := s.state.RotateRefresh(tx, token, next, s.now()); err != nil {
			return err
		}
		if !s.now().Before(token.ExpiresAt) || !s.now().Before(deadline) {
			return errSessionExpired
		}
		return nil
	})
	return s.tokenOutcome(result, deadline, denial, err)
}

func (s *SessionService) tokenOutcome(result *oidc.TokenResponse,
	deadline time.Time,
	denial *oidc.OAuthError,
	err error) (*oidc.TokenResponse,
	error,
) {
	if err != nil {
		return nil, sessionUnavailable(err)
	}
	if denial != nil {
		return nil, denial
	}
	deliveryTime := s.now()
	remainingSeconds := int64(deadline.Sub(deliveryTime) / time.Second)
	if result == nil || !deliveryTime.Before(deadline) || remainingSeconds <= 0 {
		return nil, sessionUnavailable(errSessionExpired)
	}
	// Remaining lifetime, never the configured TTL, is disclosed at delivery.
	result.ExpiresIn = remainingSeconds
	return result, nil
}

//nolint:nilerr // Authenticated unknown-token revocation commits a non-disclosing no-op.
func (s *SessionService) Revoke(ctx context.Context, req oidc.RevokeRequest) error {
	if req.Token == "" {
		return sessionError(sessionErrorInvalidRequest)
	}
	hint, lookupErr := s.state.ReadRefresh(ctx, req.Token)
	if lookupErr != nil && !isStateMissing(lookupErr) {
		return sessionUnavailable(lookupErr)
	}
	var denial *oidc.OAuthError
	err := s.owned(ctx, func(tx context.Context) error {
		input := oidc.SessionAdmissionRequest{ClientID: req.ClientID}
		if lookupErr == nil && hint.ClientID == req.ClientID {
			input.Expected = &hint.Binding
			input.SessionID = hint.Binding.SessionID
		}
		current, err := s.admission.Lock(tx, input)
		if err != nil {
			return err
		}
		if denial = s.authenticate(tx, current, req.ClientID, req.ClientSecret, req.ClientAuthMethod); denial != nil {
			return nil
		}
		if lookupErr != nil || hint.ClientID != req.ClientID {
			return nil
		}
		token, err := s.state.LockRefresh(tx, req.Token)
		if isStateMissing(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if token.ClientID != req.ClientID || token.FamilyID != hint.FamilyID || !sameBinding(token.Binding, hint.Binding) {
			return nil
		}
		reason := oidc.SessionRevoked
		if token.ConsumedAt != nil {
			reason = oidc.SessionReplay
		}
		return s.state.RevokeFamily(tx, token.FamilyID, reason, s.now())
	})
	if err != nil {
		return sessionUnavailable(err)
	}
	if denial != nil {
		return denial
	}
	return nil
}

func (s *SessionService) UserInfo(ctx context.Context, token string) (oidc.SessionUserInfo, error) {
	claims, err := s.parseSessionAccessToken(ctx, token)
	if err != nil {
		return oidc.SessionUserInfo{}, sessionError("invalid_token")
	}
	binding := claims.binding()
	var result oidc.SessionUserInfo
	var denial *oidc.OAuthError
	err = s.owned(ctx, func(tx context.Context) error {
		current,
			err := s.admission.Lock(tx,
			oidc.SessionAdmissionRequest{
				ClientID:  claims.ClientID,
				SessionID: binding.SessionID,
				Expected:  &binding,
			})
		if err != nil {
			return err
		}
		if !validAdmission(current, &binding, s.now()) || current.Projection.ProjectID != claims.ProjectID {
			denial = sessionError("invalid_token")
			return nil
		}
		family, err := s.state.LockFamily(tx, claims.FamilyID)
		if isStateMissing(err) {
			denial = sessionError("invalid_token")
			return nil
		}
		if err != nil {
			return err
		}
		if family.RevokedAt != nil || family.ReplayedAt != nil || !sameBinding(family.Binding, binding) ||
			oidc.ScopeString(family.Scopes) != claims.Scope || !s.now().Before(claims.ExpiresAt.Time) {
			denial = sessionError("invalid_token")
			return nil
		}
		result = s.userInfo(current, oidc.ParseScope(claims.Scope))
		if !s.now().Before(claims.ExpiresAt.Time) || !validBinding(binding, s.now()) {
			denial = sessionError("invalid_token")
		}
		return nil
	})
	if err != nil {
		return oidc.SessionUserInfo{}, sessionUnavailable(err)
	}
	if denial != nil {
		return oidc.SessionUserInfo{}, denial
	}
	if !s.now().Before(claims.ExpiresAt.Time) || !validBinding(binding, s.now()) {
		return oidc.SessionUserInfo{}, sessionError("invalid_token")
	}
	return result, nil
}

func (s *SessionService) issueCode(ctx context.Context,
	req oidc.AuthorizeRequest,
	scopes []string,
	binding oidc.SessionBinding) (*oidc.AuthorizeResult,
	time.Time,
	error,
) {
	raw, err := s.base.generateToken()
	if err != nil {
		return nil, time.Time{}, err
	}
	now := s.now()
	end := minTime(now.Add(time.Minute), binding.AbsoluteExpiresAt)
	if !validBinding(binding, now) {
		return nil, time.Time{}, errSessionExpired
	}
	code := oidc.SessionCode{AuthorizationCode: oidc.AuthorizationCode{
		Code: raw, SubjectID: binding.SubjectID, SecurityVersion: binding.SecurityVersion, ClientID: binding.ClientID,
		RedirectURI: req.RedirectURI, Scopes: slices.Clone(scopes), Nonce: req.Nonce, CodeChallenge: req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod, AuthenticatedAt: binding.AuthenticatedAt, CreatedAt: now, ExpiresAt: end,
	}, Binding: binding}
	if err := s.state.SaveCode(ctx, code); err != nil {
		return nil, time.Time{}, err
	}
	if !s.now().Before(end) {
		return nil, time.Time{}, errSessionExpired
	}
	target, err := url.Parse(req.RedirectURI)
	if err != nil {
		return nil, time.Time{}, err
	}
	q := target.Query()
	q.Set("code", raw)
	if req.State != "" {
		q.Set("state", req.State)
	}
	target.RawQuery = q.Encode()
	return &oidc.AuthorizeResult{RedirectURI: target.String()}, end, nil
}

func (s *SessionService) validateAuthorize(client oidc.Client, req oidc.SessionAuthorizeRequest) ([]string, *oidc.OAuthError) {
	if !client.Trusted || client.TokenEndpointAuthMethod != oidc.TokenEndpointAuthMethodClientSecretBasic {
		return nil, sessionError("unauthorized_client")
	}
	if req.ResponseType != responseTypeCode {
		return nil, sessionError("unsupported_response_type")
	}
	scopes := oidc.ParseScope(req.Scope)
	if !validSessionScopes(scopes) {
		return nil, sessionError("invalid_scope")
	}
	for _, scope := range scopes {
		if !oidc.HasScope(client.AllowedScopes, scope) {
			return nil, sessionError("invalid_scope")
		}
	}
	if !validPKCEMetadata(true, req.CodeChallenge, req.CodeChallengeMethod) {
		return nil, sessionError(sessionErrorInvalidRequest)
	}
	if req.MaxAgeSeconds != nil && (*req.MaxAgeSeconds < 0 || *req.MaxAgeSeconds > int64((7*24*time.Hour)/time.Second)) {
		return nil, sessionError(sessionErrorInvalidRequest)
	}
	if len(req.Prompt) > 1 && slices.Contains(req.Prompt, "none") {
		return nil, sessionError(sessionErrorInvalidRequest)
	}
	seen := map[string]bool{}
	for _, prompt := range req.Prompt {
		if seen[prompt] {
			return nil, sessionError(sessionErrorInvalidRequest)
		}
		seen[prompt] = true
		switch prompt {
		case "login", "none":
		case "consent":
			return nil, sessionError("consent_required")
		case "select_account":
			return nil, sessionError("account_selection_required")
		default:
			return nil, sessionError(sessionErrorInvalidRequest)
		}
	}
	return scopes, nil
}

func strictHTTPSURL(raw string, query bool) bool {
	u, err := url.Parse(raw)
	return err == nil && raw != "" && strings.TrimSpace(raw) == raw && u.Scheme == "https" && u.Hostname() != "" &&
		!strings.Contains(u.Host, "*") && u.User == nil && u.Fragment == "" && (query || (u.RawQuery == "" && !u.ForceQuery))
}

func strictRedirectAllowed(client oidc.Client, raw string) bool {
	return strictHTTPSURL(raw, true) && slices.Contains(client.RedirectURIs, raw)
}

func validSessionScopes(scopes []string) bool {
	if !oidc.HasScope(scopes, oidc.ScopeOpenID) {
		return false
	}
	for _, scope := range scopes {
		if scope != oidc.ScopeOpenID && scope != oidc.ScopeProfile && scope != oidc.ScopeEmail {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	return len(value) >= 32 && len(value) <= 128 && boundedASCII(value, 128)
}

func boundedASCII(value string, limit int) bool {
	if len(value) == 0 || len(value) > limit {
		return false
	}
	for i := range len(value) {
		if value[i] < 33 || value[i] > 126 {
			return false
		}
	}
	return true
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validBinding(b oidc.SessionBinding, now time.Time) bool {
	return canonicalUUID(b.SubjectID) &&
		canonicalUUID(b.SessionID) &&
		b.SecurityVersion > 0 &&
		boundedASCII(b.ClientID,
			256) &&
		boundedASCII(b.PolicyStamp,
			192) &&

		!b.AuthenticatedAt.IsZero() && !b.AuthenticatedAt.After(now) && now.Before(b.AbsoluteExpiresAt) &&
		!b.AbsoluteExpiresAt.After(b.AuthenticatedAt.Add(7*24*time.Hour))
}

func sameBinding(a, b oidc.SessionBinding) bool {
	return a.SubjectID == b.SubjectID &&
		a.SecurityVersion == b.SecurityVersion &&
		a.ClientID == b.ClientID &&
		a.SessionID == b.SessionID &&

		a.PolicyStamp == b.PolicyStamp && a.AuthenticatedAt.Equal(b.AuthenticatedAt) && a.AbsoluteExpiresAt.Equal(b.AbsoluteExpiresAt)
}

func validAdmission(current oidc.SessionAdmissionResult, expected *oidc.SessionBinding, now time.Time) bool {
	b := current.Binding
	if !current.Allowed || !current.Client.Trusted || current.ClientRevision <= 0 || current.Client.ID != b.ClientID ||
		current.Client.TokenEndpointAuthMethod != oidc.TokenEndpointAuthMethodClientSecretBasic || !validBinding(b, now) ||
		current.Account.Subject.Status != goauth.SubjectStatusActive || current.Account.Subject.ID.String() != b.SubjectID ||
		current.Account.Subject.SecurityVersion != b.SecurityVersion || !validProjection(current.Projection) {
		return false
	}
	if expected == nil {
		return true
	}
	// A later real reauthentication may advance the live sid timestamp only.
	b.AuthenticatedAt = expected.AuthenticatedAt
	return sameBinding(b, *expected) && validBinding(*expected, now)
}

func freshAuthentication(auth time.Time, age *int64, now time.Time) bool {
	if auth.IsZero() || auth.After(now) {
		return false
	}
	return age == nil || *age == 0 || now.Sub(auth) <= time.Duration(*age)*time.Second
}

func requestCompletionMatches(record oidc.SessionRequest,
	browser *oidc.BrowserSession,
	browserBinding string,
	now time.Time,
) bool {
	mark := record.LoginCompletion
	return browser != nil && mark != nil && record.ConsumedAt == nil && now.Before(record.ExpiresAt) &&
		validDigest(browserBinding) && subtleStringCompare(record.BrowserBinding, browserBinding) &&
		mark.SessionID == browser.SessionID &&
		validDigest(browser.CookieDigest) &&
		subtleStringCompare(mark.CookieDigest,
			browser.CookieDigest) &&

		!mark.AuthenticatedAt.IsZero() && !mark.AuthenticatedAt.Before(record.RequestedAt) && !mark.AuthenticatedAt.After(now)
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func isStateMissing(err error) bool {
	return errors.Is(err, oidc.ErrAuthorizationRequestNotFound) || errors.Is(err, oidc.ErrAuthorizationCodeNotFound) ||
		errors.Is(err, oidc.ErrRefreshTokenNotFound) || errors.Is(err, oidc.ErrSessionStateConflict)
}

func stateReadError(err error, code string) error {
	if isStateMissing(err) {
		return sessionError(code)
	}
	return sessionUnavailable(err)
}

func validCodeSnapshot(code oidc.SessionCode) bool {
	b := code.Binding
	return code.SubjectID == b.SubjectID && code.ClientID == b.ClientID && code.SecurityVersion == b.SecurityVersion &&
		code.AuthenticatedAt.Equal(b.AuthenticatedAt) && validSessionScopes(code.Scopes) && !code.CreatedAt.IsZero() &&
		code.ExpiresAt.After(code.CreatedAt) &&
		!code.ExpiresAt.After(code.CreatedAt.Add(time.Minute)) &&
		!code.ExpiresAt.After(b.AbsoluteExpiresAt)
}

func validRefreshSnapshot(token oidc.SessionRefresh) bool {
	b := token.Binding
	return token.SubjectID == b.SubjectID && token.ClientID == b.ClientID && token.SecurityVersion == b.SecurityVersion &&
		token.AuthenticatedAt.Equal(b.AuthenticatedAt) && validSessionScopes(token.Scopes) && canonicalUUID(token.FamilyID) &&
		!token.CreatedAt.IsZero() && token.ExpiresAt.After(token.CreatedAt) && !token.ExpiresAt.After(b.AbsoluteExpiresAt)
}
