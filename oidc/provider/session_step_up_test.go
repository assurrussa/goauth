//nolint:testpackage // Exercise exact provider binding and one-time state.
package provider

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

const (
	stepUpPromptNone     = "none"
	stepUpBindingChanged = "binding_changed"
)

const stepUpStillRequired = "still_required"

func startStepUp(t *testing.T, h *sessionFixture) (string, oidc.SessionRequest) {
	t.Helper()
	h.admission.StepUpRequired = true
	h.admission.Binding.AuthenticatedAt = h.now.Add(-25 * time.Hour)
	h.admission.Binding.AbsoluteExpiresAt = h.now.Add(3 * 24 * time.Hour)
	result, err := h.service.Authorize(t.Context(), h.authorizeRequest(), h.browser())
	require.NoError(t, err)
	u, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	challenge := u.Query().Get("oidc_challenge")
	require.NotEmpty(t, challenge)
	r := h.requests[challenge]
	require.Equal(t, sessionInteractionStepUp, r.Interaction)
	require.Equal(t, h.browser(), r.StepUpSession)
	require.Equal(t, h.admission.Binding, *r.StepUpBinding)
	require.Nil(t, r.LoginCompletion)
	require.Equal(t, 3*time.Minute, r.ExpiresAt.Sub(r.RequestedAt))
	return challenge, r
}

func TestSessionStepUpPreservesPasswordBinding(t *testing.T) {
	h := newSessionFixture(t)
	challenge, r := startStepUp(t, h)
	h.now = h.now.Add(time.Second)
	h.cookie = strings.Repeat("n", 64)
	err := h.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
		return h.MarkStepUpComplete(ctx, challenge, r.BrowserBinding, oidc.RequestStepUpCompletion{
			SessionID: h.browser().SessionID, CookieDigest: h.cookie, VerifiedAt: h.now,
		})
	})
	require.NoError(t, err)
	h.admission.StepUpRequired = false
	result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), r.BrowserBinding)
	require.NoError(t, err)
	u, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	code := h.codes[u.Query().Get("code")]
	require.Equal(t, *r.StepUpBinding, code.Binding)
	require.Equal(t, r.StepUpBinding.AuthenticatedAt, code.AuthenticatedAt)
	_, err = h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), r.BrowserBinding)
	require.Error(t, err)
	// Freshness is admission policy for new authorization only.
	h.admission.StepUpRequired = true
	token, err := h.service.ExchangeToken(t.Context(), h.codeRequest(code.Code))
	require.NoError(t, err)
	_, err = h.service.UserInfo(t.Context(), token.AccessToken)
	require.NoError(t, err)
	_, err = h.service.ExchangeToken(t.Context(), h.refreshRequest(token.RefreshToken))
	require.NoError(t, err)
}

func TestSessionStepUpRejectsWrongEvidence(t *testing.T) {
	for _, test := range []string{
		"login_marker", "same_cookie", "wrong_sid", "before_request", "at_request",
		"future_step_up", "expired_step_up", stepUpStillRequired, stepUpBindingChanged,
	} {
		t.Run(test, func(t *testing.T) {
			h := newSessionFixture(t)
			challenge, r := startStepUp(t, h)
			h.now = h.now.Add(time.Second)
			h.cookie = strings.Repeat("n", 64)
			mark := oidc.RequestStepUpCompletion{SessionID: h.browser().SessionID, CookieDigest: h.cookie, VerifiedAt: h.now}
			r.StepUpCompletion = &mark
			h.admission.StepUpRequired = false
			switch test {
			case "login_marker":
				r.StepUpCompletion = nil
				r.LoginCompletion = &oidc.RequestLoginCompletion{
					SessionID: mark.SessionID, CookieDigest: mark.CookieDigest, AuthenticatedAt: h.now,
				}
			case "same_cookie":
				h.cookie = r.StepUpSession.CookieDigest
				mark.CookieDigest = h.cookie
			case "wrong_sid":
				mark.SessionID = "wrong"
			case "before_request":
				mark.VerifiedAt = r.RequestedAt.Add(-time.Second)
			case "at_request":
				mark.VerifiedAt = r.RequestedAt
			case "future_step_up":
				mark.VerifiedAt = h.now.Add(time.Second)
			case "expired_step_up":
				h.now = r.ExpiresAt
			case stepUpStillRequired:
				h.admission.StepUpRequired = true
			case stepUpBindingChanged:
				h.admission.Binding.PolicyStamp = "changed"
			}
			h.requests[challenge] = r
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), r.BrowserBinding)
			if test == stepUpStillRequired || test == stepUpBindingChanged {
				require.NoError(t, err)
				require.Contains(t, result.RedirectURI, "access_denied")
			} else {
				require.Error(t, err)
			}
			require.Empty(t, h.codes)
		})
	}
}

func TestSessionStepUpPromptAndMaxAge(t *testing.T) {
	for _, mode := range []string{stepUpPromptNone, "login", "max_age"} {
		t.Run(mode, func(t *testing.T) {
			h := newSessionFixture(t)
			h.admission.StepUpRequired = true
			req := h.authorizeRequest()
			if mode == "max_age" {
				var zero int64
				req.MaxAgeSeconds = &zero
			} else {
				req.Prompt = []string{mode}
			}
			result, err := h.service.Authorize(t.Context(), req, h.browser())
			require.NoError(t, err)
			if mode == stepUpPromptNone {
				require.Contains(t, result.RedirectURI, "login_required")
				require.Empty(t, h.requests)
				return
			}
			require.Len(t, h.requests, 1)
			for _, r := range h.requests {
				require.NotEqual(t, sessionInteractionStepUp, r.Interaction)
				require.Nil(t, r.StepUpSession)
			}
		})
	}
}

type passwordOnlyState struct{ oidc.SessionStateStore }

func TestSessionStepUpFailsClosedWithoutStoreCapability(t *testing.T) {
	h := newSessionFixture(t)
	h.service.state = passwordOnlyState{h}
	h.admission.StepUpRequired = true
	_, err := h.service.Authorize(t.Context(), h.authorizeRequest(), h.browser())
	require.Error(t, err)
	require.Empty(t, h.requests)
	require.Empty(t, h.codes)
}

func TestSessionStepUpPositiveMaxAgeSelectsInteraction(t *testing.T) {
	for _, test := range []struct {
		name        string
		passwordAge time.Duration
		stepUp      bool
	}{
		{name: "password already stale", passwordAge: 61 * time.Second},
		{name: "password still fresh", passwordAge: 30 * time.Second, stepUp: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := newSessionFixture(t)
			h.admission.StepUpRequired = true
			h.admission.Binding.AuthenticatedAt = h.now.Add(-test.passwordAge)
			h.admission.Binding.AbsoluteExpiresAt = h.admission.Binding.AuthenticatedAt.Add(7 * 24 * time.Hour)
			original := h.admission.Binding
			req := h.authorizeRequest()
			maxAge := int64(60)
			req.MaxAgeSeconds = &maxAge
			challenge, pending := authorizeMaxAgeInteraction(t, h, req)
			require.Empty(t, h.codes)
			require.Equal(t, req.MaxAgeSeconds, pending.MaxAgeSeconds)
			require.Nil(t, pending.LoginCompletion)
			require.Nil(t, pending.StepUpCompletion)
			if !test.stepUp {
				require.Contains(t, []string{"", testSessionLogin}, pending.Interaction)
				require.Nil(t, pending.StepUpSession)
				require.Nil(t, pending.StepUpBinding)
				h.now = h.now.Add(time.Second)
				err := h.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
					return h.MarkStepUpComplete(ctx, challenge, pending.BrowserBinding, oidc.RequestStepUpCompletion{
						SessionID: h.browser().SessionID, CookieDigest: strings.Repeat("n", 64), VerifiedAt: h.now,
					})
				})
				require.ErrorIs(t, err, oidc.ErrSessionStateConflict)
				result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), pending.BrowserBinding)
				require.Error(t, err)
				require.Nil(t, result)
				require.Empty(t, h.codes)
				return
			}
			require.Equal(t, sessionInteractionStepUp, pending.Interaction)
			require.Equal(t, h.browser(), pending.StepUpSession)
			require.Equal(t, original, *pending.StepUpBinding)
			h.now = h.now.Add(time.Second)
			h.cookie = strings.Repeat("n", 64)
			require.NoError(t, h.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
				return h.MarkStepUpComplete(ctx, challenge, pending.BrowserBinding, oidc.RequestStepUpCompletion{
					SessionID: h.browser().SessionID, CookieDigest: h.cookie, VerifiedAt: h.now,
				})
			}))
			h.admission.StepUpRequired = false
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), pending.BrowserBinding)
			require.NoError(t, err)
			target, err := url.Parse(result.RedirectURI)
			require.NoError(t, err)
			code := h.codes[target.Query().Get(responseTypeCode)]
			require.NotEmpty(t, code.Code)
			require.Equal(t, original, code.Binding)
			require.Equal(t, original.AuthenticatedAt, code.AuthenticatedAt)
			require.Nil(t, h.requests[challenge].LoginCompletion, "MFA must not manufacture password proof")
		})
	}
}

func TestSessionStepUpPositiveMaxAgeExpiresBeforeContinuation(t *testing.T) {
	h := newSessionFixture(t)
	h.admission.StepUpRequired = true
	h.admission.Binding.AuthenticatedAt = h.now.Add(-59 * time.Second)
	h.admission.Binding.AbsoluteExpiresAt = h.admission.Binding.AuthenticatedAt.Add(7 * 24 * time.Hour)
	original := h.admission.Binding
	req := h.authorizeRequest()
	maxAge := int64(60)
	req.MaxAgeSeconds = &maxAge
	challenge, pending := authorizeMaxAgeInteraction(t, h, req)
	require.Equal(t, sessionInteractionStepUp, pending.Interaction)
	require.Equal(t, original, *pending.StepUpBinding)
	h.now = h.now.Add(500 * time.Millisecond)
	h.cookie = strings.Repeat("n", 64)
	require.NoError(t, h.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
		return h.MarkStepUpComplete(ctx, challenge, pending.BrowserBinding, oidc.RequestStepUpCompletion{
			SessionID: h.browser().SessionID, CookieDigest: h.cookie, VerifiedAt: h.now,
		})
	}))
	h.admission.StepUpRequired = false
	// The MFA proof and request remain live; only password freshness expires.
	h.now = h.now.Add(1500 * time.Millisecond)
	require.True(t, h.now.Before(pending.ExpiresAt))
	require.Equal(t, original, h.admission.Binding)
	result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), pending.BrowserBinding)
	require.Error(t, err)
	require.Nil(t, result)
	require.Empty(t, h.codes)
	// A new authorization must enter the password branch even though MFA is fresh.
	loginChallenge, login := authorizeMaxAgeInteraction(t, h, req)
	require.Contains(t, []string{"", testSessionLogin}, login.Interaction)
	require.Nil(t, login.StepUpSession)
	require.Nil(t, login.StepUpBinding)
	require.Nil(t, login.LoginCompletion)
	h.now = h.now.Add(time.Second)
	h.cookie = strings.Repeat("p", 64)
	h.admission.Binding.AuthenticatedAt = h.now
	require.NoError(t, h.InOwnedAuthTransaction(t.Context(), func(ctx context.Context) error {
		return h.MarkLoginComplete(ctx, loginChallenge, login.BrowserBinding, oidc.RequestLoginCompletion{
			SessionID: h.browser().SessionID, CookieDigest: h.cookie, AuthenticatedAt: h.now,
		})
	}))
	result, err = h.service.ContinueAuthorization(t.Context(), loginChallenge, h.browser(), login.BrowserBinding)
	require.NoError(t, err)
	target, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	code := h.codes[target.Query().Get(responseTypeCode)]
	require.NotEmpty(t, code.Code)
	require.Equal(t, h.now, code.Binding.AuthenticatedAt)
	require.NotEqual(t, original.AuthenticatedAt, code.Binding.AuthenticatedAt)
}

func authorizeMaxAgeInteraction(t *testing.T, h *sessionFixture,
	req oidc.SessionAuthorizeRequest,
) (string, oidc.SessionRequest) {
	t.Helper()
	result, err := h.service.Authorize(t.Context(), req, h.browser())
	require.NoError(t, err)
	target, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	require.Empty(t, target.Query().Get(responseTypeCode))
	challenge := target.Query().Get("oidc_challenge")
	require.NotEmpty(t, challenge)
	pending, exists := h.requests[challenge]
	require.True(t, exists)
	return challenge, pending
}
