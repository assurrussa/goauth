//nolint:testpackage // Exercises the owned continuation boundary and fault-injected state.
package provider

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
)

const (
	testDenialState         = "state"
	testDenialCallback      = "callback"
	testDenialAdmission     = "admission"
	testDenialUnknownCommit = "unknown commit"
	testDenialMissing       = "missing"
	testDenialClient        = "client"
	testDenialConsumed      = "consumed"
	testDenialChallenge     = "challenge"
	testDenialRevision      = "revision"
	testDenialConsume       = "consume"
	testDenialBeforeCommit  = "before commit"
	testDenialAfterCommit   = "after commit"
)

func completedSessionRequest(t *testing.T, h *sessionFixture,
	changes ...func(*oidc.SessionAuthorizeRequest),
) (oidc.SessionAuthorizeRequest, string) {
	t.Helper()
	req := h.authorizeRequest()
	req.Prompt = []string{testSessionLogin}
	req.State = "stored state + / ? & = % # ü"
	for _, change := range changes {
		change(&req)
	}
	result, err := h.service.Authorize(t.Context(), req, h.browser())
	require.NoError(t, err)
	u, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	challenge := u.Query().Get("oidc_challenge")
	require.NotEmpty(t, challenge)
	require.NoError(t, h.InOwnedAuthTransaction(t.Context(), func(tx context.Context) error {
		return h.MarkLoginComplete(tx, challenge, req.BrowserBinding, oidc.RequestLoginCompletion{
			SessionID: h.browser().SessionID, CookieDigest: h.cookie, AuthenticatedAt: h.now,
		})
	}))
	return req, challenge
}

func assertSessionDenialRedirect(t *testing.T, result *oidc.AuthorizeResult, req oidc.SessionAuthorizeRequest) {
	t.Helper()
	assertSessionErrorRedirect(t, result, req, "access_denied")
}

func assertSessionErrorRedirect(t *testing.T, result *oidc.AuthorizeResult, req oidc.SessionAuthorizeRequest, code string) {
	t.Helper()
	require.NotNil(t, result)
	u, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	query := u.Query()
	require.Equal(t, []string{code}, query["error"])
	if req.State == "" {
		require.NotContains(t, query, testDenialState)
	} else {
		require.Equal(t, []string{req.State}, query[testDenialState])
	}
	require.NotContains(t, query, responseTypeCode)
	registered, err := url.Parse(req.RedirectURI)
	require.NoError(t, err)
	for key, values := range registered.Query() {
		if key != testDenialState && key != responseTypeCode {
			require.Equal(t, values, query[key])
		}
	}
	u.RawQuery = ""
	registered.RawQuery = ""
	require.Equal(t, registered.String(), u.String())
}

func TestSessionContinuationDenialPreservesOpaqueState(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"", " ", "\t", " & + % ü "} {
		t.Run(state, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			h.admission.Client.RedirectURIs[0] += "?existing=one&existing=two&state=registration&code=old&c%6fde=older"
			req, challenge := completedSessionRequest(t, h, func(req *oidc.SessionAuthorizeRequest) { req.State = state })
			h.admission.Allowed = false
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), req.BrowserBinding)
			require.NoError(t, err)
			assertSessionDenialRedirect(t, result, req)
			require.NotNil(t, h.requests[challenge].ConsumedAt)
			assertNoSessionGrant(t, h)
		})
	}
}

func TestSessionAuthorizeErrorsPreserveOpaqueState(t *testing.T) {
	t.Parallel()
	const invalidScope = "invalid_scope"
	for _, code := range []string{invalidScope, "login_required"} {
		for _, state := range []string{"", " ", "\t", " & + % ü "} {
			t.Run(code+"/"+state, func(t *testing.T) {
				t.Parallel()
				h := newSessionFixture(t)
				h.admission.Client.RedirectURIs[0] += "?existing=one&existing=two&state=registration&code=old&c%6fde=older"
				req := h.authorizeRequest()
				req.State = state
				if code == invalidScope {
					req.Scope = testSessionOfflineScope
				} else {
					req.Prompt = []string{oidc.TokenEndpointAuthMethodNone}
				}
				result, err := h.service.Authorize(t.Context(), req, nil)
				require.NoError(t, err)
				assertSessionErrorRedirect(t, result, req, code)
				require.Empty(t, h.requests)
				require.Empty(t, h.codes)
				require.Empty(t, h.families)
				require.Empty(t, h.tokens)
				require.Zero(t, h.generation)
			})
		}
	}
}

func assertNoSessionGrant(t *testing.T, h *sessionFixture) {
	t.Helper()
	require.Empty(t, h.codes)
	require.Empty(t, h.families)
	require.Empty(t, h.tokens)
	require.Equal(t, 1, h.generation, "only the original login challenge was generated")
}

func TestSessionContinuationDenialIsTerminalCallback(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(*sessionFixture)
	}{
		{"membership revoked", func(h *sessionFixture) { h.admission.Allowed = false }},
		{"client revision changed", func(h *sessionFixture) { h.admission.ClientRevision++ }},
		{"subject suspended", func(h *sessionFixture) { h.admission.Account.Subject.Status = goauth.SubjectStatusSuspended }},
		{"live session absent", func(h *sessionFixture) { h.admission.Binding.SessionID = "" }},
		{"live session expired", func(h *sessionFixture) { h.admission.Binding.AbsoluteExpiresAt = h.now }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			req, challenge := completedSessionRequest(t, h)
			browser := h.browser()
			tc.change(h)
			before := h.commits
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, browser, req.BrowserBinding)
			require.NoError(t, err)
			assertSessionDenialRedirect(t, result, req)
			require.Equal(t, before+1, h.commits)
			require.NotNil(t, h.requests[challenge].ConsumedAt)
			assertNoSessionGrant(t, h)
			result, err = h.service.ContinueAuthorization(t.Context(), challenge, browser, req.BrowserBinding)
			require.Nil(t, result)
			requireOAuthError(t, err, sessionErrorInvalidRequest)
			require.Equal(t, before+1, h.commits, "replay must not enter another owned transaction")
		})
	}
}

func TestSessionContinuationDenialParallelSingleConsumer(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	req, challenge := completedSessionRequest(t, h)
	h.admission.Allowed = false
	type outcome struct {
		result *oidc.AuthorizeResult
		err    error
	}
	results := make(chan outcome, 2)
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), req.BrowserBinding)
			results <- outcome{result, err}
		}()
	}
	wg.Wait()
	close(results)
	redirects := 0
	for outcome := range results {
		if outcome.err == nil {
			assertSessionDenialRedirect(t, outcome.result, req)
			redirects++
		} else {
			require.Nil(t, outcome.result)
			requireOAuthError(t, outcome.err, sessionErrorInvalidRequest)
		}
	}
	require.Equal(t, 1, redirects)
	assertNoSessionGrant(t, h)
}

func TestSessionContinuationUnsafeCallbackStaysLocal(t *testing.T) {
	t.Parallel()
	for _, change := range []string{"removed", "untrusted", "wrong client"} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			req, challenge := completedSessionRequest(t, h)
			h.admission.Allowed = false
			switch change {
			case "removed":
				h.admission.Client.RedirectURIs = []string{"https://other.example/callback"}
			case "untrusted":
				h.admission.Client.Trusted = false
			case "wrong client":
				h.admission.Client.ID = testSessionOther
			}
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), req.BrowserBinding)
			require.Nil(t, result)
			requireOAuthError(t, err, "access_denied")
			require.Nil(t, h.requests[challenge].ConsumedAt)
			assertNoSessionGrant(t, h)
		})
	}
}

func TestSessionContinuationDenialRevalidatesCompletion(t *testing.T) {
	t.Parallel()
	for _, locked := range []bool{false, true} {
		for _, change := range []string{
			"binding", "sid", "cookie", "missing marker", "future marker", "old marker",
			testDenialConsumed, testDenialChallenge, testDenialClient, testDenialRevision, testDenialCallback,
		} {
			if !locked && (change == testDenialChallenge || change == testDenialClient ||
				change == testDenialRevision || change == testDenialCallback) {
				continue // These are comparisons of the locked record against the read-only hint.
			}
			t.Run(change+map[bool]string{false: "/hint", true: "/locked"}[locked], func(t *testing.T) {
				t.Parallel()
				h := newSessionFixture(t)
				req, challenge := completedSessionRequest(t, h)
				h.admission.Allowed = false
				mutate := func() {
					r := h.requests[challenge]
					mark := *r.LoginCompletion
					r.LoginCompletion = &mark
					switch change {
					case "binding":
						r.BrowserBinding = strings.Repeat("x", 64)
					case "sid":
						mark.SessionID = uuid.NewString()
					case "cookie":
						mark.CookieDigest = strings.Repeat("x", 64)
					case "missing marker":
						r.LoginCompletion = nil
					case "future marker":
						mark.AuthenticatedAt = h.now.Add(time.Second)
					case "old marker":
						mark.AuthenticatedAt = r.RequestedAt.Add(-time.Second)
					case testDenialConsumed:
						r.ConsumedAt = &h.now
					case testDenialChallenge:
						r.Challenge = "other-challenge"
					case testDenialClient:
						r.ClientID = testSessionOther
					case testDenialRevision:
						r.ClientRevision++
					case testDenialCallback:
						r.RedirectURI = "https://other.example/callback"
					}
					h.requests[challenge] = r
				}
				if locked {
					h.afterAdmission = mutate
				} else {
					mutate()
				}
				before := h.commits
				result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), req.BrowserBinding)
				require.Nil(t, result)
				requireOAuthError(t, err, sessionErrorInvalidRequest)
				require.Equal(t, before, h.commits)
				if locked || change != testDenialConsumed {
					require.Nil(t, h.requests[challenge].ConsumedAt)
				}
				assertNoSessionGrant(t, h)
			})
		}
	}
}

func TestSessionContinuationDenialExpirySuppressesOutput(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{
		"before", testDenialAdmission, testDenialConsume, testDenialBeforeCommit, testDenialAfterCommit,
	} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			req, challenge := completedSessionRequest(t, h)
			h.admission.Allowed = false
			expiry := h.requests[challenge].ExpiresAt
			expire := func() { h.now = expiry }
			switch stage {
			case "before":
				expire()
			case testDenialAdmission:
				h.afterAdmission = expire
			case testDenialConsume:
				h.afterWrite = func(string) { expire() }
			case testDenialBeforeCommit:
				h.afterWrite = func(string) {
					calls := 0
					h.service.base.now = func() time.Time {
						calls++
						if calls >= 3 {
							return expiry
						}
						return h.now
					}
				}
			case testDenialAfterCommit:
				h.afterCommit = expire
			}
			before := h.commits
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), req.BrowserBinding)
			require.Nil(t, result)
			if stage == testDenialBeforeCommit || stage == testDenialAfterCommit {
				require.ErrorIs(t, err, errSessionExpired)
			} else {
				requireOAuthError(t, err, sessionErrorInvalidRequest)
			}
			if stage == testDenialAfterCommit {
				require.Equal(t, before+1, h.commits)
				require.NotNil(t, h.requests[challenge].ConsumedAt)
			} else {
				require.Equal(t, before, h.commits)
				require.Nil(t, h.requests[challenge].ConsumedAt)
			}
			assertNoSessionGrant(t, h)
		})
	}
}

type unavailableSessionAdmission struct{ failure error }

func (a unavailableSessionAdmission) Lock(context.Context, oidc.SessionAdmissionRequest) (oidc.SessionAdmissionResult, error) {
	return oidc.SessionAdmissionResult{}, a.failure
}

func TestSessionContinuationDenialFailureWithholdsOutput(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{testDenialAdmission, testDenialConsume, testDenialUnknownCommit} {
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			req, challenge := completedSessionRequest(t, h)
			h.admission.Allowed = false
			switch stage {
			case testDenialAdmission:
				h.service.admission = unavailableSessionAdmission{errors.New("admission database unavailable")}
			case testDenialConsume:
				h.failWrite = "consume_request"
			case testDenialUnknownCommit:
				h.commitErr = goauth.ErrOperationOutcomeUnknown
			}
			result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), req.BrowserBinding)
			require.Nil(t, result)
			require.Error(t, err)
			var protocol *oidc.OAuthError
			require.NotErrorAs(t, err, &protocol)
			if stage == testDenialUnknownCommit {
				require.ErrorIs(t, err, goauth.ErrOperationOutcomeUnknown)
				require.NotNil(t, h.requests[challenge].ConsumedAt)
			} else {
				require.Nil(t, h.requests[challenge].ConsumedAt)
			}
			assertNoSessionGrant(t, h)
		})
	}
}

func TestSessionContinuationInvalidChallengeAndBrowserStayLocal(t *testing.T) {
	t.Parallel()
	for _, change := range []string{
		testDenialMissing, "malformed", "nil browser", "wrong session", "wrong cookie", "wrong binding",
	} {
		t.Run(change, func(t *testing.T) {
			t.Parallel()
			h := newSessionFixture(t)
			req, challenge := completedSessionRequest(t, h)
			h.admission.Allowed = false
			browser, binding, supplied := h.browser(), req.BrowserBinding, challenge
			switch change {
			case testDenialMissing:
				supplied += testDenialMissing
			case "malformed":
				supplied = " \x00\n"
			case "nil browser":
				browser = nil
			case "wrong session":
				browser.SessionID = uuid.NewString()
			case "wrong cookie":
				browser.CookieDigest = strings.Repeat("x", 64)
			case "wrong binding":
				binding = strings.Repeat("x", 64)
			}
			before := h.commits
			result, err := h.service.ContinueAuthorization(t.Context(), supplied, browser, binding)
			require.Nil(t, result)
			requireOAuthError(t, err, sessionErrorInvalidRequest)
			require.Equal(t, before, h.commits)
			require.Nil(t, h.requests[challenge].ConsumedAt)
			assertNoSessionGrant(t, h)
		})
	}
}
