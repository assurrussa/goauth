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
