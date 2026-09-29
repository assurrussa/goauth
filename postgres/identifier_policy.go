package postgres

import (
	"fmt"

	"github.com/assurrussa/goauth"
)

// The canonical PostgreSQL account lookup currently selects the primary email.
// Do not accept a resolver whose output the store cannot look up. Custom schemes
// remain available to direct root Runtime assemblies with a matching store.
func validateRuntimeIdentifierSchemes(resolvers map[goauth.IdentifierScheme]goauth.IdentifierResolver) error {
	for scheme, resolver := range resolvers {
		if scheme != goauth.IdentifierSchemeEmail && resolver != nil {
			return fmt.Errorf("%w: PostgreSQL Runtime supports only the email scheme", goauth.ErrInvalidIdentifierScheme)
		}
	}
	return nil
}
