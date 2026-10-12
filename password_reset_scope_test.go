package goauth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/testkit"
)

func resetScopeContext(t *testing.T, scope string) context.Context {
	t.Helper()
	ctx, err := goauth.WithPasswordResetScope(t.Context(), scope)
	require.NoError(t, err)
	return ctx
}

func TestPasswordResetScopeBindsBothIssuancePaths(t *testing.T) {
	for _, hostPolicy := range []bool{false, true} {
		name := "primary"
		if hostPolicy {
			name = "recipient"
		}
		t.Run(name, func(t *testing.T) {
			var fixture *testkit.Fixture
			var account goauth.Account
			address := "scoped-reset@example.test"
			if hostPolicy {
				var policy *resetRecipientPolicy
				fixture, policy, account = resetRecipientFixture(t)
				address = policy.address
			} else {
				fixture = newFixture(t)
				account = registerAccount(t, fixture, address).Account
			}
			ctx := resetScopeContext(t, "operator-v1")
			bound := false
			require.NoError(t, fixture.Runtime.RequestPasswordResetWithReceipt(ctx, address,
				func(receiptCtx context.Context, receipt goauth.PasswordResetReceipt) error {
					require.Equal(t, "operator-v1", goauth.PasswordResetScope(receiptCtx))
					require.Equal(t, account.Subject.ID, receipt.SubjectID)
					bound = true
					return nil
				}))
			require.True(t, bound)
			token := recipientResetToken(t, fixture)
			events := fixture.Events.Events()
			notification, err := fixture.Runtime.DecryptNotificationEvent(events[len(events)-1])
			require.NoError(t, err)
			restored, err := goauth.PasswordResetNotificationContext(t.Context(), notification)
			require.NoError(t, err)
			require.Equal(t, "operator-v1", goauth.PasswordResetScope(restored))
			before, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
			require.NoError(t, err)
			for _, wrong := range []string{"", "sso-v1"} {
				require.ErrorIs(t, fixture.Runtime.ResetPassword(resetScopeContext(t, wrong), token,
					"Scoped-Replacement-Password-2026!"), goauth.ErrInvalidToken)
				after, err := fixture.Store.GetLocalAccount(t.Context(), account.Subject.ID)
				require.NoError(t, err)
				require.Equal(t, before, after)
				require.Len(t, fixture.Events.Events(), 1)
			}
			require.NoError(t, fixture.Runtime.ResetPassword(ctx, token, "Scoped-Replacement-Password-2026!"))
			require.ErrorIs(t, fixture.Runtime.ResetPassword(ctx, token, "Another-Replacement-Password-2026!"),
				goauth.ErrResetAlreadyUsed)
			events = fixture.Events.Events()
			success, err := fixture.Runtime.DecryptNotificationEvent(events[len(events)-1])
			require.NoError(t, err)
			require.Equal(t, "password_reset_success", success.Template)
			restored, err = goauth.PasswordResetNotificationContext(t.Context(), success)
			require.NoError(t, err)
			require.Equal(t, "operator-v1", goauth.PasswordResetScope(restored))
		})
	}
}

func TestPasswordResetScopeReplacementRemainsPerSubject(t *testing.T) {
	fixture, policy, _ := resetRecipientFixture(t)
	operator, central := resetScopeContext(t, "operator-v1"), resetScopeContext(t, "sso-v1")
	require.NoError(t, fixture.Runtime.RequestPasswordReset(operator, policy.address))
	old := recipientResetToken(t, fixture)
	require.NoError(t, fixture.Runtime.RequestPasswordReset(central, policy.address))
	current := recipientResetToken(t, fixture)
	require.ErrorIs(t, fixture.Runtime.ResetPassword(operator, old, "Scoped-Replacement-Password-2026!"),
		goauth.ErrResetAlreadyUsed)
	require.NoError(t, fixture.Runtime.ResetPassword(central, current, "Scoped-Replacement-Password-2026!"))
}

func TestPasswordResetScopeRestorationDoesNotInheritWorkerAuthority(t *testing.T) {
	ambient := resetScopeContext(t, "operator-v1")
	for _, notification := range []goauth.Notification{{}, {Data: map[string]string{"password_reset_scope": ""}}} {
		ctx, err := goauth.PasswordResetNotificationContext(ambient, notification)
		require.NoError(t, err)
		require.Empty(t, goauth.PasswordResetScope(ctx))
	}
	for _, invalid := range []string{"SSO", "../sso", "sso\x00operator", "sso v1", strings.Repeat("x", 65)} {
		_, err := goauth.WithPasswordResetScope(t.Context(), invalid)
		require.Error(t, err)
		_, err = goauth.PasswordResetNotificationContext(ambient,
			goauth.Notification{Data: map[string]string{"password_reset_scope": invalid}})
		require.Error(t, err)
	}
}
