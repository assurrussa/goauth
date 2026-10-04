//nolint:testpackage // Verifies strict registered callback validation before state mutation.
package provider

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func malformedSessionCallbackQueries() []string {
	return []string{
		"?tenant=a;b",
		"?ordinary=good&tenant=a;b&ordinary=other",
		"?tenant=%",
		"?tenant=%GG",
		"?ordinary=good&tenant=%2&ordinary=other",
	}
}

func TestSessionAuthorizeRejectsMalformedCallbackQuery(t *testing.T) {
	t.Parallel()
	for _, query := range malformedSessionCallbackQueries() {
		for _, protocolError := range []bool{false, true} {
			name := query + map[bool]string{false: "/ready", true: "/protocol error"}[protocolError]
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				h := newSessionFixture(t)
				h.admission.Client.RedirectURIs[0] += query
				req := h.authorizeRequest()
				if protocolError {
					req.Scope = testSessionOfflineScope
				}
				result, err := h.service.Authorize(t.Context(), req, h.browser())
				require.Nil(t, result)
				requireOAuthError(t, err, sessionErrorInvalidRequest)
				require.Empty(t, h.requests)
				require.Empty(t, h.codes)
				require.Empty(t, h.families)
				require.Empty(t, h.tokens)
				require.Zero(t, h.generation)
			})
		}
	}
}

func TestSessionContinuationRejectsMalformedCallbackQueryWithoutConsumption(t *testing.T) {
	t.Parallel()
	for _, query := range malformedSessionCallbackQueries() {
		for _, allowed := range []bool{false, true} {
			name := query + map[bool]string{false: "/denied", true: "/ready"}[allowed]
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				h := newSessionFixture(t)
				req, challenge := completedSessionRequest(t, h)
				// Model a request persisted before this stricter callback validation.
				// The malformed URI still exactly matches the current registration.
				h.admission.Client.RedirectURIs[0] += query
				record := h.requests[challenge]
				record.RedirectURI = h.admission.Client.RedirectURIs[0]
				h.requests[challenge] = record
				h.admission.Allowed = allowed
				result, err := h.service.ContinueAuthorization(t.Context(), challenge, h.browser(), req.BrowserBinding)
				require.Nil(t, result)
				requireOAuthError(t, err, "access_denied")
				require.Nil(t, h.requests[challenge].ConsumedAt)
				assertNoSessionGrant(t, h)
			})
		}
	}
}

func TestSessionAuthorizePreservesEncodedCallbackQuery(t *testing.T) {
	t.Parallel()
	h := newSessionFixture(t)
	h.admission.Client.RedirectURIs[0] += "?tenant=a%3Bb&tenant=c%3Bd&ordinary=one&ordinary=two"
	result, err := h.service.Authorize(t.Context(), h.authorizeRequest(), h.browser())
	require.NoError(t, err)
	require.NotNil(t, result)
	callback, err := url.Parse(result.RedirectURI)
	require.NoError(t, err)
	query, err := url.ParseQuery(callback.RawQuery)
	require.NoError(t, err)
	require.Equal(t, []string{"a;b", "c;d"}, query["tenant"])
	require.Equal(t, []string{"one", "two"}, query["ordinary"])
	require.Len(t, query[responseTypeCode], 1)
	require.NotEmpty(t, query.Get(responseTypeCode))
	require.Len(t, h.codes, 1)
	require.Empty(t, h.families)
	require.Empty(t, h.tokens)
}
