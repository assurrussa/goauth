//nolint:testpackage // Verifies final delivery time and committed one-time state together.
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestSessionTokenDeliveryUsesOneTimeAndPositiveLifetime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		remaining time.Duration
		seconds   int64
	}{
		{name: "fractional positive", remaining: 1500 * time.Millisecond, seconds: 1},
		{name: "one second", remaining: time.Second, seconds: 1},
		{name: "subsecond", remaining: time.Second - time.Nanosecond},
		{name: "last nanosecond", remaining: time.Nanosecond},
		{name: "equality"},
		{name: "past deadline", remaining: -time.Nanosecond},
	}
	for _, grant := range []string{grantTypeAuthorizationCode, grantTypeRefreshToken} {
		for _, tc := range cases {
			t.Run(grant+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				h := newSessionFixture(t)
				var request oidc.TokenRequest
				if grant == grantTypeAuthorizationCode {
					request = h.codeRequest(h.authorizeCode(t))
				} else {
					request = h.refreshRequest(h.issue(t).RefreshToken)
				}
				beforeCommits, beforeTokens := h.commits, len(h.tokens)
				deadline := h.now.Add(5 * time.Minute).Truncate(time.Second)
				deliveryTime := deadline.Add(-tc.remaining)
				clockCalls := 0
				h.afterCommit = func() {
					h.service.base.now = func() time.Time {
						// A second sample would cross the deadline in every positive case.
						value := deliveryTime.Add(time.Duration(clockCalls) * 2 * time.Second)
						clockCalls++
						return value
					}
				}
				response, err := h.service.ExchangeToken(context.Background(), request)
				require.Equal(t, 1, clockCalls, "validity and lifetime must use one final delivery time")
				if tc.seconds > 0 {
					require.NoError(t, err)
					require.NotNil(t, response)
					require.Equal(t, tc.seconds, response.ExpiresIn)
				} else {
					require.ErrorIs(t, err, errSessionExpired)
					require.Nil(t, response)
				}
				require.Equal(t, beforeCommits+1, h.commits, "delivery suppression cannot undo a confirmed commit")
				require.Len(t, h.tokens, beforeTokens+1, "the committed successor remains stored after safe loss")
				require.Len(t, h.families, 1)
				var familyID string
				if grant == grantTypeAuthorizationCode {
					require.NotNil(t, h.codes[request.Code].ConsumedAt)
					familyID = h.codes[request.Code].FamilyID
				} else {
					require.NotNil(t, h.tokens[request.RefreshToken].ConsumedAt)
					familyID = h.tokens[request.RefreshToken].FamilyID
				}
				require.Contains(t, h.families, familyID)
				require.Equal(t, h.admission.Binding, h.families[familyID].Binding)
				require.Nil(t, h.families[familyID].RevokedAt)
				require.Zero(t, h.replays)
			})
		}
	}
}
