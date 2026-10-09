package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/assurrussa/goauth"
)

func TestNormalizeLogin(t *testing.T) {
	input := goauth.IdentifierInput{Scheme: loginScheme, Value: "Operator_42-A"}
	got, err := normalizeLogin(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, input, got)
	for _, value := range []string{"", " operator", "operator@example.test", "оператор", "a\x00b", strings.Repeat("a", 65)} {
		_, err := normalizeLogin(context.Background(), goauth.IdentifierInput{Scheme: loginScheme, Value: value})
		require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
	}
	_, err = normalizeLogin(context.Background(), goauth.IdentifierInput{Scheme: goauth.IdentifierSchemeEmail, Value: "Operator"})
	require.ErrorIs(t, err, goauth.ErrInvalidIdentifier)
}

func TestMalformedHostTokens(t *testing.T) {
	// Malformed/oversized input must fail before any Runtime or database access.
	host := sessionHost{}
	for _, token := range []string{"", "short", strings.Repeat("!", 43), strings.Repeat("A", 1<<20)} {
		account, err := host.authenticate(t.Context(), token, "demo-project")
		require.ErrorIs(t, err, errDenied)
		require.Zero(t, account)
	}
}
