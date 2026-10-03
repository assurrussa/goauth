package testkit

import (
	"context"
	"errors"

	"github.com/assurrussa/goauth"
)

func (s *Store) SetTrustedLocalPassword(
	ctx context.Context, request goauth.TrustedLocalPasswordStoreRequest,
) (goauth.Account, error) {
	if request.SubjectID.IsZero() || request.ExpectedPasswordPHC == "" || request.NewPasswordPHC == "" ||
		request.ExpectedSecurityVersion < 1 || request.Now.IsZero() {
		return goauth.Account{}, errors.New("invalid trusted local password request")
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := request.SubjectID.String()
	account, found := s.accounts[key]
	if !found {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	current, found := s.passwords[key]
	if !found {
		return goauth.Account{}, goauth.ErrAccountNotFound
	}
	if account.Subject.SecurityVersion != request.ExpectedSecurityVersion {
		return goauth.Account{}, goauth.ErrSecurityVersionMismatch
	}
	if current != request.ExpectedPasswordPHC || s.passwordPolicies[key] != request.ExpectedPasswordInputPolicy {
		return goauth.Account{}, goauth.ErrPasswordChangeConflict
	}
	s.passwords[key] = request.NewPasswordPHC
	s.passwordPolicies[key] = goauth.PasswordInputPolicyUnicode
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = request.Now
	s.accounts[key] = account
	s.revokeSubjectSecurityLocked(request.SubjectID, request.Now)
	s.invalidatePasswordResetsLocked(request.SubjectID, request.Now)
	return cloneAccount(account), nil
}

var _ goauth.TrustedLocalPasswordStore = (*Store)(nil)
