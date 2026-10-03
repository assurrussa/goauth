package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/assurrussa/goauth"
)

type identifierPolicyResolver struct{}

func (identifierPolicyResolver) NormalizeIdentifier(
	_ context.Context,
	input goauth.IdentifierInput,
) (goauth.IdentifierInput, error) {
	return input, nil
}

func TestRuntimeRejectsUnsupportedIdentifierBeforeDatabaseAccess(t *testing.T) {
	t.Parallel()
	runtime, err := NewRuntime(Config{Runtime: goauth.Config{
		IdentifierResolvers: map[goauth.IdentifierScheme]goauth.IdentifierResolver{"INVALID": identifierPolicyResolver{}},
	}})
	if runtime != nil || !errors.Is(err, goauth.ErrInvalidIdentifierScheme) {
		t.Fatalf("expected identifier preflight before missing-DB validation, got runtime=%v err=%v", runtime, err)
	}
}

func TestRuntimeIdentifierPolicyPreservesEmailAndIgnoredNilResolvers(t *testing.T) {
	t.Parallel()
	for _, resolvers := range []map[goauth.IdentifierScheme]goauth.IdentifierResolver{
		nil,
		{},
		{goauth.IdentifierSchemeEmail: identifierPolicyResolver{}},
		{"username": nil},
		{"username": identifierPolicyResolver{}},
	} {
		if err := validateRuntimeIdentifierSchemes(resolvers); err != nil {
			t.Fatal(err)
		}
	}
}
