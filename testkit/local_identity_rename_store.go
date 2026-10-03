package testkit

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
	"github.com/assurrussa/goauth/internal/identifierbounds"
)

func localIdentifierKey(id goauth.SubjectID, scheme goauth.IdentifierScheme) string {
	return id.String() + ":" + string(scheme)
}

func cloneLocalIdentifier(identifier goauth.Identifier) goauth.Identifier {
	if identifier.VerifiedAt != nil {
		value := *identifier.VerifiedAt
		identifier.VerifiedAt = &value
	}
	return identifier
}

func (s *Store) GetLocalIdentifier(
	ctx context.Context, subjectID goauth.SubjectID, scheme goauth.IdentifierScheme,
) (goauth.Identifier, error) {
	if subjectID.IsZero() {
		return goauth.Identifier{}, goauth.ErrAccountNotFound
	}
	if err := validateLocalIdentifierScheme(scheme); err != nil {
		return goauth.Identifier{}, err
	}
	if err := s.validateTransactionScope(ctx); err != nil {
		return goauth.Identifier{}, err
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	identifier, found := s.localIdentifiers[localIdentifierKey(subjectID, scheme)]
	if !found {
		return goauth.Identifier{}, goauth.ErrLocalIdentifierConflict
	}
	return cloneLocalIdentifier(identifier), nil
}

func validateLocalIdentifierScheme(scheme goauth.IdentifierScheme) error {
	if scheme == goauth.IdentifierSchemeEmail {
		return goauth.ErrInvalidIdentifierScheme
	}
	return scheme.Validate()
}

func (s *Store) RenameLocalIdentity(
	ctx context.Context, request goauth.RenameLocalIdentityStoreRequest,
) (goauth.LocalIdentityView, error) {
	if request.SubjectID.IsZero() {
		return goauth.LocalIdentityView{}, goauth.ErrAccountNotFound
	}
	if err := validateLocalIdentifierScheme(request.Scheme); err != nil {
		return goauth.LocalIdentityView{}, err
	}
	if request.ExpectedSecurityVersion < 1 {
		return goauth.LocalIdentityView{}, goauth.ErrSecurityVersionMismatch
	}
	if !identifierbounds.Valid(request.ExpectedNormalizedValue) || !identifierbounds.Valid(request.NewDisplayValue) ||
		!identifierbounds.Valid(request.NewNormalizedValue) {
		return goauth.LocalIdentityView{}, goauth.ErrInvalidIdentifier
	}
	if request.Now.IsZero() {
		return goauth.LocalIdentityView{}, errors.New("rename local identity requires a timestamp")
	}
	started := time.Now()
	if err := s.validateTransactionScope(ctx); err != nil {
		return goauth.LocalIdentityView{}, err
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := request.SubjectID.String()
	account, found := s.accounts[key]
	if !found {
		return goauth.LocalIdentityView{}, goauth.ErrAccountNotFound
	}
	if account.Subject.SecurityVersion != request.ExpectedSecurityVersion {
		return goauth.LocalIdentityView{}, goauth.ErrSecurityVersionMismatch
	}
	localKey := localIdentifierKey(request.SubjectID, request.Scheme)
	identifier, found := s.localIdentifiers[localKey]
	if !found {
		return goauth.LocalIdentityView{}, goauth.ErrLocalIdentifierConflict
	}
	if _, found := s.passwords[key]; !found {
		return goauth.LocalIdentityView{}, goauth.ErrAccountNotFound
	}
	if identifier.NormalizedValue != request.ExpectedNormalizedValue {
		return goauth.LocalIdentityView{}, goauth.ErrLocalIdentifierConflict
	}
	if identifier.NormalizedValue == request.NewNormalizedValue && identifier.DisplayValue == request.NewDisplayValue {
		return goauth.LocalIdentityView{}, goauth.ErrIdentifierUnchanged
	}
	nextKey := identifierKey(request.Scheme, request.NewNormalizedValue)
	oldKey := identifierKey(identifier.Scheme, identifier.NormalizedValue)
	if _, found := s.identifiers[nextKey]; found && nextKey != oldKey {
		return goauth.LocalIdentityView{}, goauth.ErrIdentifierAlreadyExists
	}
	if account.Subject.SecurityVersion == math.MaxInt64 {
		return goauth.LocalIdentityView{}, errors.New("local identity security version overflow")
	}
	now := authclock.Now(ctx, request.Now, started)
	delete(s.identifiers, oldKey)
	s.identifiers[nextKey] = key
	identifier.DisplayValue = request.NewDisplayValue
	identifier.NormalizedValue = request.NewNormalizedValue
	identifier.UpdatedAt = now
	s.localIdentifiers[localKey] = identifier
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = now
	s.accounts[key] = account
	s.revokeSubjectSecurityLocked(request.SubjectID, now)
	s.invalidatePasswordResetsLocked(request.SubjectID, now)
	return goauth.LocalIdentityView{Account: cloneAccount(account), Identifier: cloneLocalIdentifier(identifier)}, nil
}

var (
	_ goauth.LocalIdentifierReader    = (*Store)(nil)
	_ goauth.LocalIdentityRenameStore = (*Store)(nil)
)
