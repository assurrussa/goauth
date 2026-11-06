//go:build integration

package postgres_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/oidc"
)

func TestSessionStepUpDurableTransitions(t *testing.T) {
	runtime, state, refresh := sessionOIDCFixture(t)
	now := refresh.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	r := sessionOIDCRequest(now)
	r.Interaction = "step_up"
	r.ExpiresAt = now.Add(3 * time.Minute)
	r.StepUpSession = &oidc.BrowserSession{SessionID: refresh.Binding.SessionID, CookieDigest: strings.Repeat("o", 64)}
	binding := refresh.Binding
	r.StepUpBinding = &binding
	require.NoError(t, runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error { return state.SaveRequest(tx, r) }))
	saved, err := state.ReadRequest(ctx, r.Challenge)
	require.NoError(t, err)
	require.Equal(t, r.StepUpSession, saved.StepUpSession)
	require.Equal(t, r.StepUpBinding, saved.StepUpBinding)
	require.Equal(t, "step_up", saved.Interaction)
	now = now.Add(time.Second)
	good := oidc.RequestStepUpCompletion{SessionID: binding.SessionID, CookieDigest: strings.Repeat("n", 64), VerifiedAt: now}
	for _, test := range []string{"password_marker", "uncompleted_consume", "same_cookie", "wrong_sid", "at_request", "future", "wrong_browser"} {
		t.Run(test, func(t *testing.T) {
			err := runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
				mark := good
				browser := r.BrowserBinding
				switch test {
				case "password_marker":
					return state.MarkLoginComplete(tx, r.Challenge, browser, oidc.RequestLoginCompletion{SessionID: mark.SessionID, CookieDigest: mark.CookieDigest, AuthenticatedAt: mark.VerifiedAt})
				case "uncompleted_consume":
					_, err := state.ConsumeRequest(tx, r.Challenge)
					return err
				case "same_cookie":
					mark.CookieDigest = r.StepUpSession.CookieDigest
				case "wrong_sid":
					mark.SessionID = "wrong"
				case "at_request":
					mark.VerifiedAt = r.RequestedAt
				case "future":
					mark.VerifiedAt = now.Add(time.Second)
				case "wrong_browser":
					browser = "wrong"
				}
				return state.MarkStepUpComplete(tx, r.Challenge, browser, mark)
			})
			require.ErrorIs(t, err, oidc.ErrSessionStateConflict)
		})
	}
	require.NoError(t, runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
		return state.MarkStepUpComplete(tx, r.Challenge, r.BrowserBinding, good)
	}))
	saved, err = state.ReadRequest(ctx, r.Challenge)
	require.NoError(t, err)
	require.Equal(t, &good, saved.StepUpCompletion)
	require.Nil(t, saved.LoginCompletion)
	require.ErrorIs(t, runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
		return state.MarkStepUpComplete(tx, r.Challenge, r.BrowserBinding, good)
	}), oidc.ErrSessionStateConflict)
	require.NoError(t, runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
		consumed, err := state.ConsumeRequest(tx, r.Challenge)
		if err != nil {
			return err
		}
		require.Equal(t, &good, consumed.StepUpCompletion)
		return nil
	}))
	require.ErrorIs(t, runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error { _, err := state.ConsumeRequest(tx, r.Challenge); return err }), oidc.ErrSessionStateConflict)
}

func TestSessionStepUpSQLGuardRejectsMarkerSubstitution(t *testing.T) {
	runtime, state, refresh := sessionOIDCFixture(t)
	now := refresh.CreatedAt
	ctx := authclock.With(t.Context(), func() time.Time { return now })
	r := sessionOIDCRequest(now)
	r.Interaction = "step_up"
	r.ExpiresAt = now.Add(3 * time.Minute)
	r.StepUpSession = &oidc.BrowserSession{SessionID: refresh.Binding.SessionID, CookieDigest: strings.Repeat("o", 64)}
	binding := refresh.Binding
	r.StepUpBinding = &binding
	require.NoError(t, runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error { return state.SaveRequest(tx, r) }))
	for _, sql := range []string{
		`UPDATE auth_oidc_authorization_requests SET interaction='login'`,
		`UPDATE auth_oidc_authorization_requests SET login_session_id='wrong',login_cookie_digest='wrong',login_authenticated_at=requested_at`,
		`UPDATE auth_oidc_authorization_requests SET consumed_at=requested_at`,
		`UPDATE auth_oidc_authorization_requests SET step_up_session_id=step_up_session->>'SessionID',step_up_cookie_digest=step_up_session->>'CookieDigest',step_up_verified_at=requested_at+interval '1 second'`,
		`UPDATE auth_oidc_authorization_requests SET step_up_binding=jsonb_set(step_up_binding,'{PolicyStamp}','"changed"')`,
	} {
		require.Error(t, runtime.InOwnedAuthTransaction(ctx, func(tx context.Context) error {
			q, err := runtime.SQLExecutor(tx)
			if err != nil {
				return err
			}
			_, err = q.ExecContext(tx, sql)
			return err
		}))
	}
}
