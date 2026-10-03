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

func (s *Store) subjectLifecycleLocked(id goauth.SubjectID) (goauth.SubjectLifecycleView, error) {
	account, found := s.accounts[id.String()]
	if !found {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	view := goauth.SubjectLifecycleView{Account: cloneAccount(account)}
	if retired, found := s.retired[id.String()]; found {
		view.RetiredAt = &retired
	}
	return view, nil
}

func (s *Store) GetSubjectLifecycle(ctx context.Context, id goauth.SubjectID) (goauth.SubjectLifecycleView, error) {
	if id.IsZero() {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	if err := s.validateTransactionScope(ctx); err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.subjectLifecycleLocked(id)
}

func (s *Store) RetireLocalIdentity(
	ctx context.Context, request goauth.RetireLocalIdentityStoreRequest,
) (goauth.SubjectLifecycleView, error) {
	if request.SubjectID.IsZero() {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	if err := validateLocalIdentifierScheme(request.Scheme); err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	if request.ExpectedSecurityVersion < 1 {
		return goauth.SubjectLifecycleView{}, goauth.ErrSecurityVersionMismatch
	}
	if !identifierbounds.Valid(request.ExpectedNormalizedValue) {
		return goauth.SubjectLifecycleView{}, goauth.ErrInvalidIdentifier
	}
	if request.Now.IsZero() {
		return goauth.SubjectLifecycleView{}, errors.New("retire local identity requires a timestamp")
	}
	started := time.Now()
	if err := s.validateTransactionScope(ctx); err != nil {
		return goauth.SubjectLifecycleView{}, err
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := request.SubjectID.String()
	account, found := s.accounts[key]
	if !found {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	if _, retired := s.retired[key]; retired {
		return goauth.SubjectLifecycleView{}, goauth.ErrSubjectRetired
	}
	if account.Subject.SecurityVersion != request.ExpectedSecurityVersion {
		return goauth.SubjectLifecycleView{}, goauth.ErrSecurityVersionMismatch
	}
	localKey := localIdentifierKey(request.SubjectID, request.Scheme)
	identifier, found := s.localIdentifiers[localKey]
	if !found || identifier.NormalizedValue != request.ExpectedNormalizedValue {
		return goauth.SubjectLifecycleView{}, goauth.ErrLocalIdentifierConflict
	}
	if _, found := s.passwords[key]; !found {
		return goauth.SubjectLifecycleView{}, goauth.ErrAccountNotFound
	}
	if account.Subject.SecurityVersion == math.MaxInt64 {
		return goauth.SubjectLifecycleView{}, errors.New("subject retirement security version overflow")
	}
	now := authclock.Now(ctx, request.Now, started)
	account.Subject.Status = goauth.SubjectStatusDisabled
	account.Subject.SecurityVersion++
	account.Subject.UpdatedAt = now
	s.accounts[key] = account
	s.retired[key] = now
	delete(s.identifiers, identifierKey(identifier.Scheme, identifier.NormalizedValue))
	delete(s.localIdentifiers, localKey)
	delete(s.passwords, key)
	delete(s.passwordPolicies, key)
	s.revokeSubjectSecurityLocked(request.SubjectID, now)
	s.invalidatePasswordResetsLocked(request.SubjectID, now)
	return s.subjectLifecycleLocked(request.SubjectID)
}

var (
	_ goauth.SubjectLifecycleReader       = (*Store)(nil)
	_ goauth.LocalIdentityRetirementStore = (*Store)(nil)
)
