package postgres

import "github.com/assurrussa/goauth"

func validateRuntimeIdentifierSchemes(resolvers map[goauth.IdentifierScheme]goauth.IdentifierResolver) error {
	for scheme, resolver := range resolvers {
		if resolver != nil {
			if err := scheme.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}
