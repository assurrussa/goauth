//nolint:testpackage // Verifies strict issuance and the in-memory transactional state together.
package provider

import (
	"context"
	"maps"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth/oidc"
)

func TestSessionSigningKeyProfileFailureDoesNotConsumeState(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, id string }{
		{name: "embedded space", id: "signing key 1"},
		{name: "oversized", id: strings.Repeat("k", 257)},
		{name: "non ASCII", id: "signing-key-\u2603"},
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
				beforeCodes := maps.Clone(h.codes)
				beforeTokens := maps.Clone(h.tokens)
				beforeFamilies := maps.Clone(h.families)
				beforeCommits := h.commits
				key, err := h.keys.Active(context.Background())
				require.NoError(t, err)
				key.ID = tc.id
				h.keys.keys[tc.id] = key
				h.keys.activeID = tc.id
				response, err := h.service.ExchangeToken(context.Background(), request)
				require.ErrorContains(t, err, "invalid session signing key id")
				require.Nil(t, response)
				require.Equal(t, beforeCodes, h.codes, "code consumption must roll back")
				require.Equal(t, beforeTokens, h.tokens, "no refresh consumption or unusable successor")
				require.Equal(t, beforeFamilies, h.families, "no family issuance, revocation or binding mutation")
				require.Equal(t, beforeCommits, h.commits)
				require.Zero(t, h.replays)
			})
		}
	}
}
