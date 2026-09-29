package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/oidc"
)

func (s *Service) checkAuthorizationSubject(ctx context.Context, expected goauth.Account) error {
	current, err := s.claims.Resolve(ctx, expected.Subject.ID.String())
	if err != nil {
		return fmt.Errorf("resolve authorization subject: %w", err)
	}
	if !authorizationCodeMatches(oidc.AuthorizationCode{
		SubjectID: expected.Subject.ID.String(), SecurityVersion: expected.Subject.SecurityVersion,
	}, current) || expected.Subject.Status != goauth.SubjectStatusActive {
		return s.oauthError("invalid_grant", "authentication state is no longer current", http.StatusBadRequest)
	}
	return nil
}

func authorizationCodeMatches(code oidc.AuthorizationCode, current goauth.Account) bool {
	return !current.IsZero() && current.Subject.Status == goauth.SubjectStatusActive &&
		code.SubjectID == current.Subject.ID.String() && code.SecurityVersion > 0 &&
		code.SecurityVersion == current.Subject.SecurityVersion
}
