package testkit

import (
	"context"
	"errors"
	"time"

	"github.com/assurrussa/goauth"
	"github.com/assurrussa/goauth/internal/authclock"
)

func (s *Store) CreatePasswordResetForSubject(ctx context.Context, record goauth.PasswordResetRecord) error {
	if record.SubjectID.IsZero() || record.Selector == "" || len(record.Digest.Digest) != 32 ||
		record.Digest.KeyID == "" || record.ExpectedNormalizedEmail != "" || record.ExpectedSecurityVersion < 1 ||
		record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) {
		return errors.New("invalid subject-bound password reset record")
	}
	if err := s.validateTransactionScope(ctx); err != nil {
		return err
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	key := record.SubjectID.String()
	account, found := s.accounts[key]
	_, retired := s.retired[key]
	if !found || retired || account.Subject.Status != goauth.SubjectStatusActive ||
		account.Subject.SecurityVersion != record.ExpectedSecurityVersion || s.passwords[key] == "" {
		return goauth.ErrAccountNotFound
	}
	if _, exists := s.resets[record.Selector]; exists {
		return errors.New("duplicate password reset selector")
	}
	s.invalidatePasswordResetsLocked(record.SubjectID, record.CreatedAt)
	s.resets[record.Selector] = &passwordReset{
		SubjectID: record.SubjectID, Digest: cloneDigest(record.Digest), ExpiresAt: record.ExpiresAt,
	}
	return nil
}

// InvalidatePasswordResets mirrors the managed PostgreSQL helper for fixture
// hosts. Call it with the same transaction context as the alias mutation.
func (s *Store) InvalidatePasswordResets(ctx context.Context, subjectID goauth.SubjectID, now time.Time) error {
	if subjectID.IsZero() || now.IsZero() {
		return goauth.ErrAccountNotFound
	}
	if err := s.validateTransactionScope(ctx); err != nil {
		return err
	}
	s = s.scoped(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, found := s.accounts[subjectID.String()]; !found {
		return goauth.ErrAccountNotFound
	}
	s.invalidatePasswordResetsLocked(subjectID, now)
	return nil
}

var _ goauth.PasswordResetSubjectStore = (*Store)(nil)

// ConsumePasswordResetWithPreparation serializes the entire authenticated
// preparation and mutation while allowing resolver reads through the same scope.
func (s *Store) ConsumePasswordResetWithPreparation(
	ctx context.Context, request goauth.PasswordResetConsumeRequest,
	prepare func(context.Context, goauth.Account) (string, error),
) (goauth.PasswordResetConsumeResult, error) {
	if prepare == nil {
		return goauth.PasswordResetConsumeResult{}, errors.New("password reset preparation is required")
	}
	started := time.Now()
	clockCtx := authclock.With(ctx, func() time.Time { return authclock.Now(ctx, request.Now, started) })
	var result goauth.PasswordResetConsumeResult
	err := s.InAuthTransaction(clockCtx, func(txCtx context.Context) error {
		var err error
		result, err = s.consumePasswordReset(txCtx, request, prepare)
		return err
	})
	return result, err
}
